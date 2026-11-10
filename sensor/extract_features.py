"""conn.log'tan pencere başına özellik tablosu üretir (Kademe 2).

Kullanım:
    python extract_features.py sample/conn.log
    python extract_features.py sample/conn.log -w 5            # 5 sn'lik pencereler
    python extract_features.py sample/conn.log --csv out.csv   # tabloyu CSV'ye de yaz

Tablodaki her satır, bir kaynağın bir penceredeki davranışının özetidir. Henüz "saldırı mı?"
demiyoruz; sadece sayıları çıkarıyoruz. Karar verme (önce kurallar, sonra modeller) sonraki kademeler.
"""

import argparse
import csv
from datetime import datetime

from features import FEATURES, WINDOW_SECONDS, extract
from zeek_reader import read_log


def write_csv(rows, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        # Meta alanlar (top_port, top_dst_host) modele girmez; CSV'ye yalnızca kimlik + özellikler yazılır.
        writer = csv.DictWriter(f, fieldnames=["src_ip", "window_start", *FEATURES], extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({k: (round(v, 4) if isinstance(v, float) else v) for k, v in row.items()})


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("path", help="Zeek conn.log dosyası")
    parser.add_argument("-w", "--window", type=int, default=WINDOW_SECONDS, help="pencere uzunluğu (sn)")
    parser.add_argument("--csv", metavar="DOSYA", help="tabloyu CSV olarak da kaydet")
    args = parser.parse_args()
    if args.window < 1:
        parser.error("pencere en az 1 sn olmalı")

    rows = extract(read_log(args.path), window=args.window)
    print(f"{len(rows)} (kaynak, {args.window} sn pencere) örneği\n")

    header = (f"{'pencere':8}  {'kaynak':15} {'bağl.':>5} {'port':>5} {'hedef':>5} "
              f"{'başarısız':>9} {'süre(sn)':>8} {'bayt':>8} {'port payı':>9}")
    print(header)
    print("-" * len(header))
    for r in rows:
        start = datetime.fromtimestamp(r["window_start"]).strftime("%H:%M:%S")
        print(f"{start:8}  {r['src_ip']:15} {r['n_conns']:5} {r['n_dst_ports']:5} {r['n_dst_hosts']:5} "
              f"{r['fail_ratio']:9.0%} {r['mean_duration']:8.2f} {r['mean_bytes']:8.0f} {r['top_port_share']:9.0%}")

    if args.csv:
        write_csv(rows, args.csv)
        print(f"\nCSV yazıldı: {args.csv}")


if __name__ == "__main__":
    main()
