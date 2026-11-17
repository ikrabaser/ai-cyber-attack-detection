"""Zeek conn.log pencerelerini koşu günlüğüyle etiketler ve koşu başına ölçüm özeti verir.

    python label_windows.py data/conn.log data/runs.jsonl                    # özet
    python label_windows.py data/conn.log data/runs.jsonl --out data/windows.csv

Etiket kuralı: bir pencere, kaynak IP'si bir koşunun kaynağıyla aynıysa ve pencere koşu aralığıyla
örtüşüyorsa o koşunun etiketini (port_scan, brute_force, normal) alır. Hiçbir koşuyla eşleşmeyen pencere
`unknown` olur (ölçümden ve eğitimden hariç tutulmalı). Koşunun başında ya da sonunda yarım kalan pencere
ile iki koşunun örtüştüğü pencere `boundary=1` işaretlenir: o pencerede koşunun trafiği seyreltilmiştir.

Conn.log'un yanında ssh.log varsa (Zeek SSH çözümleyicisi) otomatik kullanılır: kural, bağlantı sayısına
ek olarak başarısız parola denemelerini de sayar (`ssh_failed_auth` sütunu). `--no-ssh` ile kapatılır.

"İlk tespit" süresi, koşu başlangıcından ilk tespit edilen pencerenin BİTİŞİne kadardır: sensör
pencere bitmeden hüküm veremez (canlı modda buna `--grace` de eklenir).

Özetteki "pencere" sayısı sensörün gerçekte gördüğü pencere sayısıdır; ısrar eşiğini (ardışık pencere)
ayarlamak için bu sayıya bakılır. Etiketin tek kaynağı koşu günlüğüdür; kuralların kararı yalnızca
karşılaştırma için `detected` sütununa yazılır.
"""

import argparse
import csv
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "common"))
sys.path.insert(0, str(HERE.parent / "sensor"))

from features import FEATURES, WINDOW_SECONDS, extract  # noqa: E402
from rules import detect  # noqa: E402
from runlog import read_runs  # noqa: E402
from zeek_reader import read_log  # noqa: E402

UNKNOWN = "unknown"
COLUMNS = ["run_id", "label", "boundary", "src_ip", "window_start", *FEATURES, "ssh_failed_auth",
           "detected", "risk"]


def _overlap(start, end, run):
    return min(end, run["end"]) - max(start, run["start"])


def label_row(row, runs, window):
    """Pencereyi (run_id, label, boundary) üçlüsüne çevirir. Eşleşme yoksa (None, 'unknown', True)."""
    start = row["window_start"]
    end = start + window
    hits = [(r, _overlap(start, end, r)) for r in runs if r["src_ip"] == row["src_ip"]]
    hits = [(r, ov) for r, ov in hits if ov > 0]
    if not hits:
        return None, UNKNOWN, True
    run, _ = max(hits, key=lambda h: h[1])
    inside = run["start"] <= start and end <= run["end"]
    boundary = (not inside) or len(hits) > 1
    return run["run_id"], run["label"], boundary


def label_windows(records, runs, window=WINDOW_SECONDS, ssh_records=()):
    """conn.log (+ ssh.log) kayıtları ve koşular -> etiketli pencere satırları (kural kararı dahil)."""
    rows = extract(records, window=window, ssh_records=ssh_records)
    found = {(d.src_ip, d.window_start): d for d in detect(rows, window=window)}
    out = []
    for row in rows:
        run_id, label, boundary = label_row(row, runs, window)
        det = found.get((row["src_ip"], row["window_start"]))
        out.append({
            "run_id": run_id or "",
            "label": label,
            "boundary": int(boundary),
            "src_ip": row["src_ip"],
            "window_start": row["window_start"],
            **{f: row[f] for f in FEATURES},
            "ssh_failed_auth": row["ssh_failed_auth"],
            "detected": det.attack_type if det else "",
            "risk": round(det.risk_score, 3) if det else "",
        })
    return out


def summarize(labeled, runs, window=WINDOW_SECONDS):
    """Koşu başına: pencere sayısı, yarım pencere sayısı, kural tetiklenen pencere, ilk tespite kadar süre.

    İlk tespit süresi = ilk tespit edilen pencerenin bitişi - koşu başlangıcı (hep pozitif)."""
    per_run = {}
    for r in labeled:
        per_run.setdefault(r["run_id"], []).append(r)
    summary = []
    for run in sorted(runs, key=lambda x: x["start"]):
        rows = sorted(per_run.get(run["run_id"], []), key=lambda r: r["window_start"])
        hits = [r for r in rows if r["detected"] == run["label"]]
        summary.append({
            "run_id": run["run_id"],
            "label": run["label"],
            "scenario": run["scenario"],
            "duration": round(run["end"] - run["start"], 1),
            "windows": len(rows),
            "boundary_windows": sum(r["boundary"] for r in rows),
            "detected_windows": len(hits),
            "wrong_rule_windows": sum(1 for r in rows if r["detected"] and r["detected"] != run["label"]),
            "first_detection_s": round(hits[0]["window_start"] + window - run["start"], 1) if hits else None,
        })
    unknown = [r for r in labeled if r["label"] == UNKNOWN]
    return summary, {
        "unknown_windows": len(unknown),
        "unknown_detected": sum(1 for r in unknown if r["detected"]),
    }


def format_summary(summary, extra):
    lines = [f"{'koşu':22} {'etiket':12} {'süre':>6} {'pencere':>8} {'yarım':>6} {'tetik':>6} {'yanlış kural':>13} {'ilk tespit':>11}"]
    for s in summary:
        first = "-" if s["first_detection_s"] is None else f"{s['first_detection_s']} sn"
        lines.append(f"{s['run_id']:22} {s['label']:12} {s['duration']:>6} {s['windows']:>8} {s['boundary_windows']:>6} "
                     f"{s['detected_windows']:>6} {s['wrong_rule_windows']:>13} {first:>11}")
    lines.append(f"\nEşleşmeyen (unknown) pencere: {extra['unknown_windows']}, bunlardan kural tetiklenen: {extra['unknown_detected']}")
    return "\n".join(lines)


def write_csv(path, labeled):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(labeled)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("conn_log", help="Zeek conn.log")
    parser.add_argument("runs", help="koşu günlüğü (JSONL)")
    parser.add_argument("-w", "--window", type=int, default=WINDOW_SECONDS, help="pencere uzunluğu (sn)")
    parser.add_argument("--out", help="etiketli pencereleri bu CSV dosyasına yaz")
    parser.add_argument("--ssh-log", help="Zeek ssh.log (varsayılan: conn.log'un yanındaki ssh.log, varsa)")
    parser.add_argument("--no-ssh", action="store_true", help="ssh.log'u kullanma")
    args = parser.parse_args(argv)
    if args.window < 1:
        parser.error("pencere en az 1 sn olmalı")
    try:
        runs = read_runs(args.runs)
    except (OSError, ValueError) as exc:
        print(f"Koşu günlüğü okunamadı: {exc}", file=sys.stderr)
        return 1
    ssh_path = None if args.no_ssh else (args.ssh_log or str(Path(args.conn_log).with_name("ssh.log")))
    ssh_records = []
    if ssh_path and (args.ssh_log or Path(ssh_path).exists()):
        try:
            ssh_records = list(read_log(ssh_path))
        except (OSError, ValueError) as exc:
            print(f"ssh.log okunamadı: {exc}", file=sys.stderr)
            return 1
    labeled = label_windows(read_log(args.conn_log), runs, window=args.window, ssh_records=ssh_records)
    summary, extra = summarize(labeled, runs, window=args.window)
    print(f"{len(labeled)} pencere, {len(runs)} koşu" + (f", {len(ssh_records)} SSH kaydı" if ssh_records else "") + "\n")
    print(format_summary(summary, extra))
    if args.out:
        write_csv(args.out, labeled)
        print(f"\nEtiketli pencereler yazıldı: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
