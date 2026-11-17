"""conn.log -> özellikler -> kural skoru -> (isteğe bağlı) backend'e gönder (Kademe 3).

Kullanım:
    python detect.py sample/conn.log                   # sadece tespitleri göster (hiçbir şey göndermez)
    python detect.py sample/conn.log --send            # backend'e de gönder
    python detect.py sample/conn.log --send --delay 1  # olaylar arası 1 sn bekle (panelde canlı izlemek için)
    python detect.py lab/data/conn.log --follow --send # dosyayı CANLI takip et (Ctrl+C ile dur)

Backend adresi ve token: --url / --token ya da SENSOR_API_TOKEN ortam değişkeni.
"""

import argparse
import os
import sys
import time
import urllib.error
from datetime import datetime

from client import DEFAULT_URL, build_event, send_event
from features import WINDOW_SECONDS, extract
from follow import LiveMonitor, tail_records
from rules import detect
from zeek_reader import read_log


def describe(det):
    start = datetime.fromtimestamp(det.window_start).strftime("%H:%M:%S")
    return (f"{start}  {det.src_ip:15} {det.attack_type:12} risk={det.risk_score:.2f} "
            f"{det.level:6}  {'; '.join(det.reasons)}")


def describe_row(row):
    """Kural tetiklenmese de pencerede ne olduğunu gösterir (--verbose)."""
    start = datetime.fromtimestamp(row["window_start"]).strftime("%H:%M:%S")
    return (f"{start}  {row['src_ip']:15} pencere: {row['n_conns']} bağlantı, {row['n_dst_ports']} port, "
            f"%{row['fail_ratio'] * 100:.0f} başarısız, en çok port {row['top_port']}")


def follow(args, sleep=time.sleep, clock=time.monotonic, stop=lambda: False, out=sys.stdout, err=sys.stderr):
    """conn.log'u canlı takip eder; kapanan her pencereyi değerlendirir, tespitleri gönderir.

    Çıkış kodu: 0 normal durma, 1 token reddedildi. Backend'e ulaşılamazsa durmaz: o olay atlanır,
    sayılır ve izleme sürer (sensör backend yüzünden körleşmesin).
    """
    monitor = LiveMonitor(args.window, args.grace, clock)
    stats = {"sent": 0, "failed": 0}

    def warn(exc):
        monitor.bad_lines += 1
        print(f"uyarı: {exc}", file=err)

    print(f"{args.path} izleniyor (pencere {args.window} sn, kapanış beklemesi {args.grace:g} sn). "
          f"Durdurmak için Ctrl+C.", file=out, flush=True)
    code = 0
    try:
        for record in tail_records(args.path, args.poll, args.from_start, sleep, stop, on_error=warn):
            if record is not None:
                monitor.add(record)
                continue
            for row, det in monitor.close_ready():
                if det is None:
                    if args.verbose:
                        print(describe_row(row), file=out, flush=True)
                    continue
                line = describe(det)
                if args.send:
                    try:
                        status, body = send_event(args.url, args.token, build_event(det))
                    except urllib.error.URLError as exc:
                        stats["failed"] += 1
                        line += f"\n          -> gönderilemedi: {exc.reason}"
                    else:
                        line += f"\n          -> HTTP {status} {body.get('status') or body.get('error')}"
                        if status == 401:
                            print(line, file=out, flush=True)
                            print("\nToken reddedildi: SENSOR_API_TOKEN backend'dekiyle aynı olmalı.", file=err)
                            return 1
                        stats["sent"] += 1
                print(line, file=out, flush=True)
    except KeyboardInterrupt:
        print(file=out)
    print(f"{monitor.rows} pencere incelendi, {monitor.detections} tespit"
          + (f", {stats['sent']} gönderildi, {stats['failed']} gönderilemedi" if args.send else "")
          + f"; {monitor.late} kayıt geç geldiği için atlandı, {len(monitor.pending)} pencere beklemede "
          f"(gönderilmedi).", file=out)
    return code


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("path", help="Zeek conn.log dosyası")
    parser.add_argument("-w", "--window", type=int, default=WINDOW_SECONDS, help="pencere uzunluğu (sn)")
    parser.add_argument("--send", action="store_true", help="tespitleri backend'e gönder")
    parser.add_argument("--url", default=DEFAULT_URL, help=f"backend olay adresi (varsayılan {DEFAULT_URL})")
    parser.add_argument("--token", default=os.environ.get("SENSOR_API_TOKEN", ""),
                        help="Bearer token (varsayılan: SENSOR_API_TOKEN ortam değişkeni)")
    parser.add_argument("--delay", type=float, default=0.0, help="gönderimler arası bekleme (sn)")
    parser.add_argument("--follow", action="store_true",
                        help="dosyayı canlı takip et (tail -f gibi); pencereler kapandıkça değerlendirilir")
    parser.add_argument("--from-start", action="store_true",
                        help="--follow ile: dosyada zaten olan kayıtları da işle (varsayılan: yalnızca yenileri)")
    parser.add_argument("--grace", type=float, default=8.0,
                        help="--follow ile: pencere bittikten sonra geç kayıtlar için beklenecek süre (sn)")
    parser.add_argument("--poll", type=float, default=0.5, help="--follow ile: dosyaya bakma aralığı (sn)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="--follow ile: kural tetiklenmeyen pencereleri de yaz")
    args = parser.parse_args(argv)
    if args.window < 1:
        parser.error("pencere en az 1 sn olmalı")
    if not args.follow:
        for flag, used in (("--from-start", args.from_start), ("--verbose", args.verbose)):
            if used:
                parser.error(f"{flag} yalnızca --follow ile kullanılır")
    else:
        if args.delay:
            parser.error("--delay --follow ile kullanılmaz (canlı modda olaylar zaten gerçek zamanlı gider)")
        if args.grace < 0 or args.poll <= 0:
            parser.error("--grace 0 ya da büyük, --poll sıfırdan büyük olmalı")
    if args.send and not args.token:
        parser.error("--send için token gerekli (--token ya da SENSOR_API_TOKEN)")

    if args.follow:
        return follow(args)

    rows = extract(read_log(args.path), window=args.window)
    found = detect(rows, window=args.window)
    print(f"{len(rows)} pencere incelendi, {len(found)} tespit\n")

    for i, det in enumerate(found):
        line = describe(det)
        if args.send:
            if i and args.delay:
                time.sleep(args.delay)
            try:
                status, body = send_event(args.url, args.token, build_event(det))
            except urllib.error.URLError as exc:
                print(line)
                print(f"\nBackend'e ulaşılamadı ({args.url}): {exc.reason}", file=sys.stderr)
                return 1
            line += f"\n          -> HTTP {status} {body.get('status') or body.get('error')}"
            if status == 401:
                print(line)
                print("\nToken reddedildi: SENSOR_API_TOKEN backend'dekiyle aynı olmalı.", file=sys.stderr)
                return 1
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
