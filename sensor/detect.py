"""conn.log -> özellikler -> kural skoru -> (isteğe bağlı) backend'e gönder (Kademe 3).

Kullanım:
    python detect.py sample/conn.log                   # sadece tespitleri göster (hiçbir şey göndermez)
    python detect.py sample/conn.log --send            # backend'e de gönder
    python detect.py sample/conn.log --send --delay 1  # olaylar arası 1 sn bekle (panelde canlı izlemek için)

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
from rules import detect
from zeek_reader import read_log


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("path", help="Zeek conn.log dosyası")
    parser.add_argument("-w", "--window", type=int, default=WINDOW_SECONDS, help="pencere uzunluğu (sn)")
    parser.add_argument("--send", action="store_true", help="tespitleri backend'e gönder")
    parser.add_argument("--url", default=DEFAULT_URL, help=f"backend olay adresi (varsayılan {DEFAULT_URL})")
    parser.add_argument("--token", default=os.environ.get("SENSOR_API_TOKEN", ""),
                        help="Bearer token (varsayılan: SENSOR_API_TOKEN ortam değişkeni)")
    parser.add_argument("--delay", type=float, default=0.0, help="gönderimler arası bekleme (sn)")
    args = parser.parse_args(argv)
    if args.window < 1:
        parser.error("pencere en az 1 sn olmalı")
    if args.send and not args.token:
        parser.error("--send için token gerekli (--token ya da SENSOR_API_TOKEN)")

    rows = extract(read_log(args.path), window=args.window)
    found = detect(rows, window=args.window)
    print(f"{len(rows)} pencere incelendi, {len(found)} tespit\n")

    for i, det in enumerate(found):
        start = datetime.fromtimestamp(det.window_start).strftime("%H:%M:%S")
        line = (f"{start}  {det.src_ip:15} {det.attack_type:12} risk={det.risk_score:.2f} "
                f"{det.level:6}  {'; '.join(det.reasons)}")
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
