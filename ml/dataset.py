"""Pencere CSV'sini okur, sınıflara eşler ve ZAMANA göre eğitim/test olarak böler (ML-2).

    python dataset.py data/windows_lycos.csv        # bölme özetini yazdırır

Neden zamana göre bölüyoruz? Aynı saldırının ardışık pencereleri birbirine neredeyse eşittir. Rastgele
bölersek (karıştırıp %60/%40) bir pencere eğitimde, hemen yanındaki kardeşi testte olur; model ezberlediğini
"tahmin" eder ve skor şişer (veri sızıntısı). Zamana göre bölünce test, modelin hiç görmediği ANLARDAN gelir.

Kural (her grup için ayrı):
    grup = her saldırı etiketi ayrı (ftp_patator, ssh_patator, portscan); normal trafik gün gün ayrı.
    Gruptaki pencereler zamana göre dizilir; ilk %60'ı train. Kesim noktasından sonraki GAP_SECONDS
    saniye "gap" (ne train ne test): kesimin iki yanındaki pencereler birbirine çok benzer.
    Gap'ten sonrası test.

Dışarıda kalanlar (`split = "excluded"`): bu deneyin sınıfı olmayan etiketler (DoS, web saldırıları, bot...)
ve karışık pencereler (`label_share < 1`: pencerede başka etiketli akış da var, etiket güvenilmez).
"""

import csv
import sys
from collections import Counter

import _sensor  # noqa: F401
from features import FEATURES

# LycoS etiketi -> bu deneyin sınıfı. Sensörün kural adlarıyla aynı (port_scan, brute_force).
CLASS_MAP = {
    "benign": "normal",
    "portscan": "port_scan",
    "ssh_patator": "brute_force",
    "ftp_patator": "brute_force",
}
CLASSES = ["normal", "port_scan", "brute_force"]

TRAIN_FRACTION = 0.6
GAP_SECONDS = 60

_INT = ["window_start", "n_flows", "top_port", "n_conns", "n_dst_ports", "n_dst_hosts"]
_FLOAT = ["fail_ratio", "mean_duration", "mean_bytes", "top_port_share", "label_share"]


def load_windows(path):
    """CSV -> satır sözlükleri (sayısal alanlar sayıya çevrilmiş)."""
    rows = []
    with open(path, newline="", encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            for k in _INT:
                r[k] = int(float(r[k]))
            for k in _FLOAT:
                r[k] = float(r[k])
            rows.append(r)
    return rows


def _group_key(row):
    # Normal trafik gün gün; saldırılar kendi etiketiyle (her saldırının kendi zaman çizgisi var).
    return (row["label"], row["day"]) if row["label"] == "benign" else (row["label"],)


def assign_split(rows, train_fraction=TRAIN_FRACTION, gap_seconds=GAP_SECONDS):
    """Her satıra `cls` ve `split` (train / gap / test / excluded) ekler; yeni liste döndürür."""
    out = [dict(r, cls=None, split="excluded") for r in rows]
    groups = {}
    for r in out:
        if r["label"] in CLASS_MAP and r["label_share"] >= 1.0:
            r["cls"] = CLASS_MAP[r["label"]]
            groups.setdefault(_group_key(r), []).append(r)
    for members in groups.values():
        times = sorted(r["window_start"] for r in members)
        k = int(len(times) * train_fraction)
        cutoff = times[k] if k < len(times) else times[-1] + 1
        for r in members:
            ws = r["window_start"]
            r["split"] = "train" if ws < cutoff else "gap" if ws < cutoff + gap_seconds else "test"
    return out


def feature_matrix(rows):
    """Satırlar -> (X, y): X her satır için FEATURES sırasıyla sayı listesi, y sınıf adları."""
    return [[r[f] for f in FEATURES] for r in rows], [r["cls"] for r in rows]


def summary(rows):
    """(split, sınıf) -> pencere sayısı."""
    return Counter((r["split"], r["cls"]) for r in rows)


def format_summary(rows):
    counts = summary(rows)
    lines = [f"{'':12}" + "".join(f"{s:>9}" for s in ("train", "gap", "test"))]
    for cls in CLASSES:
        lines.append(f"{cls:12}" + "".join(f"{counts.get((s, cls), 0):>9}" for s in ("train", "gap", "test")))
    lines.append(f"dışarıda kalan pencere: {sum(v for (s, _), v in counts.items() if s == 'excluded')}")
    return "\n".join(lines)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("kullanım: python dataset.py data/windows_lycos.csv")
    print(format_summary(assign_split(load_windows(sys.argv[1]))))
