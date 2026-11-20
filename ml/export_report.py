"""Model değerlendirmesini panelin göstereceği küçük bir JSON dosyasına yazar.

Panel bu dosyayı olduğu gibi okur (hesap yapmaz): sayılar burada, eğitimle aynı kodla
üretilir. Veri veya model değişince bu betik yeniden çalıştırılır:

    python export_report.py data/windows_lycos.csv --out ../backend/core/ml_report.json
"""

import argparse
import json
from datetime import date

from baseline import evaluate_rules
from dataset import CLASSES, TRAIN_FRACTION, GAP_SECONDS, assign_split, load_windows
from train_xgb import PARAMS, evaluate_model, importances, train

# Alt sınır dahil, üst sınır hariç; PortScan pencerelerinin hedef port sayısı aralıkları.
PORT_BINS = [(1, 3, "1-2"), (3, 6, "3-5"), (6, 10, "6-9"), (10, 50, "10-49"), (50, 500, "50-499"), (500, None, "500+")]


def port_histogram(rows):
    counts = [0] * len(PORT_BINS)
    for r in rows:
        for i, (lo, hi, _) in enumerate(PORT_BINS):
            if r["n_dst_ports"] >= lo and (hi is None or r["n_dst_ports"] < hi):
                counts[i] += 1
                break
    return counts


def split_counts(rows):
    out = {}
    for name in ("train", "gap", "test"):
        out[name] = {c: sum(1 for r in rows if r["split"] == name and r["cls"] == c) for c in CLASSES}
    return out


def build_report(rows):
    train_rows = [r for r in rows if r["split"] == "train"]
    test_rows = [r for r in rows if r["split"] == "test"]
    model = train(train_rows)
    ports = lambda part: port_histogram([r for r in part if r["cls"] == "port_scan"])
    return {
        "generated": date.today().isoformat(),
        "dataset": "LycoS-IDS2017 (CIC-IDS2017)",
        "window": "(kaynak IP, 10 sn)",
        "split": {"train_fraction": TRAIN_FRACTION, "gap_seconds": GAP_SECONDS, "counts": split_counts(rows)},
        "classes": CLASSES,
        "xgb_params": PARAMS,
        "xgb": evaluate_model(model, test_rows),
        "rules": evaluate_rules(rows, ("test",)),
        "importance": [[n, g] for n, g in importances(model)],
        "port_scan_ports": {
            "bins": [b[2] for b in PORT_BINS],
            "train": ports(train_rows),
            "test": ports(test_rows),
        },
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("csv")
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    report = build_report(assign_split(load_windows(args.csv)))
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=1, sort_keys=True)
        fh.write("\n")
    print("yazıldı:", args.out)


if __name__ == "__main__":
    main()
