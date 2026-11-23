"""Model değerlendirmesini panelin göstereceği küçük bir JSON dosyasına yazar.

Panel bu dosyayı olduğu gibi okur (hesap yapmaz): sayılar burada, eğitimle aynı kodla
üretilir. Veri veya model değişince bu betik yeniden çalıştırılır:

    python export_report.py data/windows_lycos.csv --out ../backend/core/ml_report.json \\
        --lab ../lab/data/conn.log ../lab/data/runs.jsonl

Autoencoder (5 tohum) yaklaşık 1 dk sürer; `--no-ae` ile atlanır. `--lab` verilmezse lab bölümü eklenmez.

H1 (eşit yanlış alarm) ve etiket gürültüsü bölümleri her çalıştırmada eklenir. Mevcut raporun geri kalanına
dokunmadan yalnızca bu iki bölümü (ve xgboost sürümünü) yenilemek için:

    python export_report.py data/windows_lycos.csv --out ../backend/core/ml_report.json --extras-only
"""

import argparse
import json
from datetime import date
from pathlib import Path

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


def build_extras(rows):
    """H1 ve etiket gürültüsü bölümleri; sayılar xgboost sürümüne göre değişebilir, bu yüzden sürüm de yazılır."""
    import equal_fpr
    import label_noise
    import xgboost
    from train_xgb import predict, predict_proba

    train_rows = [r for r in rows if r["split"] == "train"]
    model = train(train_rows)
    scores = equal_fpr.collect_scores(rows, lambda rs: predict_proba(model, rs))
    noise = label_noise.panel_summary(label_noise.profile(rows), label_noise.compare(rows, train, predict))
    return {"equal_fpr": equal_fpr.panel_summary(scores), "label_noise": noise, "xgboost_version": xgboost.__version__}


def build_report(rows, lab=None, with_ae=True):
    train_rows = [r for r in rows if r["split"] == "train"]
    test_rows = [r for r in rows if r["split"] == "test"]
    model = train(train_rows)
    ports = lambda part: port_histogram([r for r in part if r["cls"] == "port_scan"])
    report = {
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
    if with_ae:
        import autoencoder

        report["autoencoder"] = autoencoder.panel_summary(autoencoder.run(rows))
    if lab:
        import lab_eval

        conn_log, runs_path = lab
        result = lab_eval.run_lab(conn_log, runs_path, train_rows)
        report["lab"] = lab_eval.panel_summary(result)
    report.update(build_extras(rows))
    return report


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("csv")
    ap.add_argument("--out", required=True)
    ap.add_argument("--lab", nargs=2, metavar=("CONN_LOG", "RUNS"), help="lab doğrulamasını da ekle")
    ap.add_argument("--no-ae", action="store_true", help="autoencoder'ı çalıştırma (yaklaşık 1 dk sürer)")
    ap.add_argument("--extras-only", action="store_true",
                    help="mevcut --out dosyasındaki diğer bölümlere dokunma; yalnızca H1 ve etiket gürültüsünü yenile")
    args = ap.parse_args(argv)
    rows = assign_split(load_windows(args.csv))
    if args.extras_only:
        try:
            report = json.loads(Path(args.out).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise SystemExit(f"--extras-only için okunabilir bir rapor gerekir ({args.out}): {exc}")
        report.update(build_extras(rows))
    else:
        report = build_report(rows, lab=args.lab, with_ae=not args.no_ae)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=1, sort_keys=True)
        fh.write("\n")
    print("yazıldı:", args.out)


if __name__ == "__main__":
    main()
