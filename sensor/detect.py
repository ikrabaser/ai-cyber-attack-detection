"""conn.log -> özellikler -> kural skoru -> (isteğe bağlı) backend'e gönder (Kademe 3).

Kullanım:
    python detect.py sample/conn.log                   # sadece tespitleri göster (hiçbir şey göndermez)
    python detect.py sample/conn.log --send            # backend'e de gönder
    python detect.py sample/conn.log --send --delay 1  # olaylar arası 1 sn bekle (panelde canlı izlemek için)
    python detect.py lab/data/conn.log --follow --send # dosyayı CANLI takip et (Ctrl+C ile dur)
    python detect.py sample/conn.log --model models/xgb.json   # kurallara ek olarak XGBoost modelini de kullan

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
from follow import LiveMonitor, LogTail
from rules import MODEL_MIN_PROB, detect
from tree_model import TreeModel
from zeek_reader import read_log


def describe(det):
    start = datetime.fromtimestamp(det.window_start).strftime("%H:%M:%S")
    return (f"{start}  {det.src_ip:15} {det.attack_type:12} risk={det.risk_score:.2f} "
            f"{det.level:6}  {'; '.join(det.reasons)}")


def describe_row(row):
    """Kural tetiklenmese de pencerede ne olduğunu gösterir (--verbose)."""
    start = datetime.fromtimestamp(row["window_start"]).strftime("%H:%M:%S")
    line = (f"{start}  {row['src_ip']:15} pencere: {row['n_conns']} bağlantı, {row['n_dst_ports']} port, "
            f"%{row['fail_ratio'] * 100:.0f} başarısız, en çok port {row['top_port']}")
    if row.get("ssh_failed_auth"):
        line += f", {row['ssh_failed_auth']} başarısız SSH parolası"
    return line


def ssh_log_path(args):
    """Kullanılacak ssh.log yolu: --no-ssh ise None, --ssh-log verildiyse o, yoksa conn.log'un yanındaki ssh.log."""
    if args.no_ssh:
        return None
    return args.ssh_log or os.path.join(os.path.dirname(args.path), "ssh.log")


def follow(args, sleep=time.sleep, clock=time.monotonic, stop=lambda: False, out=sys.stdout, err=sys.stderr,
           model=None):
    """conn.log'u canlı takip eder; kapanan her pencereyi değerlendirir, tespitleri gönderir.

    Çıkış kodu: 0 normal durma, 1 token reddedildi. Backend'e ulaşılamazsa durmaz: o olay atlanır,
    sayılır ve izleme sürer (sensör backend yüzünden körleşmesin).
    """
    monitor = LiveMonitor(args.window, args.grace, clock, model, getattr(args, "model_threshold", None))
    stats = {"sent": 0, "failed": 0}

    def warn(exc):
        monitor.bad_lines += 1
        print(f"uyarı: {exc}", file=err)

    ssh_path = ssh_log_path(args)
    conn_tail = LogTail(args.path, args.from_start, warn)
    ssh_tail = LogTail(ssh_path, args.from_start, warn) if ssh_path else None
    print(f"{args.path} izleniyor (pencere {args.window} sn, kapanış beklemesi {args.grace:g} sn)"
          + (f"; SSH denemeleri için {ssh_path}" if ssh_path else "")
          + ". Durdurmak için Ctrl+C.", file=out, flush=True)
    try:
        while not stop():
            for record in conn_tail.read_new():
                monitor.add(record)
            if ssh_tail:
                for record in ssh_tail.read_new():
                    monitor.add_ssh(record)
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
            sleep(args.poll)
    except KeyboardInterrupt:
        print(file=out)
    finally:
        conn_tail.close()
        if ssh_tail:
            ssh_tail.close()
    print(f"{monitor.rows} pencere incelendi, {monitor.detections} tespit"
          + (f", {stats['sent']} gönderildi, {stats['failed']} gönderilemedi" if args.send else "")
          + f"; {monitor.late} kayıt geç geldiği için atlandı, {len(monitor.pending)} pencere beklemede "
          f"(gönderilmedi).", file=out)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("path", help="Zeek conn.log dosyası")
    parser.add_argument("-w", "--window", type=int, default=WINDOW_SECONDS, help="pencere uzunluğu (sn)")
    parser.add_argument("--send", action="store_true", help="tespitleri backend'e gönder")
    parser.add_argument("--url", default=DEFAULT_URL, help=f"backend olay adresi (varsayılan {DEFAULT_URL})")
    parser.add_argument("--token", default=os.environ.get("SENSOR_API_TOKEN", ""),
                        help="Bearer token (varsayılan: SENSOR_API_TOKEN ortam değişkeni)")
    parser.add_argument("--delay", type=float, default=0.0, help="gönderimler arası bekleme (sn)")
    parser.add_argument("--ssh-log", help="Zeek ssh.log yolu (varsayılan: conn.log'un yanındaki ssh.log, varsa)")
    parser.add_argument("--no-ssh", action="store_true", help="ssh.log'u kullanma (yalnızca conn.log'a bak)")
    parser.add_argument("--model", help="XGBoost modeli (ml/export_model.py çıktısı); kurallara ek ikinci sinyal olur")
    parser.add_argument("--model-threshold", type=float, default=MODEL_MIN_PROB,
                        help=f"modelin saldırı saymak için gereken olasılığı (varsayılan {MODEL_MIN_PROB})")
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
    if not 0.0 < args.model_threshold < 1.0:
        parser.error("--model-threshold 0 ile 1 arasında olmalı")
    if args.model_threshold != MODEL_MIN_PROB and not args.model:
        parser.error("--model-threshold yalnızca --model ile kullanılır")

    model = None
    if args.model:
        try:
            model = TreeModel.load(args.model)
        except (OSError, ValueError, KeyError) as exc:  # JSONDecodeError de ValueError'dır
            print(f"model yüklenemedi ({args.model}): {exc}", file=sys.stderr)
            return 1
        print(f"model yüklendi: {args.model} ({len(model.trees)} ağaç, eşik {args.model_threshold})")

    if args.follow:
        return follow(args, model=model)

    ssh_records = []
    ssh_path = ssh_log_path(args)
    if ssh_path and (args.ssh_log or os.path.exists(ssh_path)):
        try:
            ssh_records = list(read_log(ssh_path))
        except (OSError, ValueError) as exc:
            print(f"ssh.log okunamadı: {exc}", file=sys.stderr)
            return 1
        print(f"{ssh_path}: {len(ssh_records)} SSH kaydı kullanıldı")

    rows = extract(read_log(args.path), window=args.window, ssh_records=ssh_records)
    found = detect(rows, window=args.window, model=model, model_threshold=args.model_threshold)
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
