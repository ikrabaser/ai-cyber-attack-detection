"""Bir Zeek conn.log dosyasını okuyup özetler (Kademe 1).

Kullanım:
    python read_conn_log.py sample/conn.log
    python read_conn_log.py sample/conn.log -n 40      # ilk 40 kaydı göster

Amaç henüz tespit değil: bir bağlantı kaydının neye benzediğini ve ham veriden
neler "görülebildiğini" anlamak. Tespit kademe 2 ve 3'te gelecek.
"""

import argparse
from collections import Counter, defaultdict
from datetime import datetime

from zeek_reader import CONN_STATE_ACIKLAMA, read_log


def fmt_time(ts):
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S") if ts is not None else "-"


def fmt_num(value, suffix=""):
    return "-" if value is None else f"{value}{suffix}"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("path", help="Zeek conn.log dosyası (TSV veya JSON)")
    parser.add_argument("-n", type=int, default=15, help="tabloda gösterilecek kayıt sayısı")
    args = parser.parse_args()

    records = list(read_log(args.path))
    if not records:
        print("Dosyada kayıt yok.")
        return

    times = [r["ts"] for r in records if r.get("ts") is not None]
    print(f"Dosya: {args.path}")
    print(f"{len(records)} bağlantı kaydı, {fmt_time(min(times))} - {fmt_time(max(times))} "
          f"({max(times) - min(times):.0f} sn)\n")

    # 1) İlk kayıtlar: bir bağlantı = 1 satır
    print(f"İlk {min(args.n, len(records))} kayıt")
    header = f"{'zaman':8}  {'kaynak':15} {'->':2} {'hedef:port':21} {'proto':5} {'servis':6} {'durum':6} {'süre':7} {'gönd/alın bayt'}"
    print(header)
    print("-" * len(header))
    for r in records[: args.n]:
        dst = f"{r['id.resp_h']}:{r['id.resp_p']}"
        sent_recv = f"{fmt_num(r.get('orig_bytes'))}/{fmt_num(r.get('resp_bytes'))}"
        print(f"{fmt_time(r['ts']):8}  {r['id.orig_h']:15} -> {dst:21} {r['proto']:5} "
              f"{(r.get('service') or '-'):6} {r['conn_state']:6} {fmt_num(r.get('duration')):7} {sent_recv}")

    # 2) conn_state dağılımı: bağlantılar nasıl sonlanmış?
    print("\nBağlantı durumu (conn_state) dağılımı")
    for state, count in Counter(r["conn_state"] for r in records).most_common():
        print(f"  {state:6} {count:4}  {CONN_STATE_ACIKLAMA.get(state, '')}")

    # 3) Kaynak başına özet: kim kaç bağlantı kurmuş, kaç farklı porta dokunmuş?
    per_src = defaultdict(lambda: {"conns": 0, "ports": set(), "hosts": set()})
    for r in records:
        s = per_src[r["id.orig_h"]]
        s["conns"] += 1
        s["ports"].add(r["id.resp_p"])
        s["hosts"].add(r["id.resp_h"])
    print("\nKaynak IP başına özet")
    print(f"  {'kaynak':15} {'bağlantı':>9} {'farklı port':>12} {'farklı hedef':>13}")
    for ip, s in sorted(per_src.items(), key=lambda kv: -kv[1]["conns"]):
        print(f"  {ip:15} {s['conns']:9} {len(s['ports']):12} {len(s['hosts']):13}")
    print("\nİpucu: bir kaynağın bağlantı sayısı ve dokunduğu port sayısı, ham kayıtlara tek tek "
          "bakmadan da neyin olağandışı olduğunu gösteriyor. Kademe 2'de bunu sistematik hâle getireceğiz.")


if __name__ == "__main__":
    main()
