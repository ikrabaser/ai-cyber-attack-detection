"""Pencereleri kaynak IP'ye göre gruplayıp zaman sırasına dizi (sequence) halinde birleştirir (ML-6, ilk adım).

LSTM tek pencereye değil, ardışık pencerelerin DİZİSİNE bakar. Burada yalnızca veri hazırlığı var:
eğitim yok, model yok. Diziler ML-2'nin (dataset.py) aynı train/gap/test bölmesini kullanır; bir dizi
iki farklı bölmenin penceresini ASLA karıştırmaz (gap zaten araya girer, ayrıca bkz. aşağıdaki boşluk kuralı).

Dürüst sınır: pencereler arasında trafiksiz bir boşluk varsa (bir sonraki pencere tam WINDOW_SECONDS
sonra başlamıyorsa) dizi orada kesilir ve yeni bir dizi başlar. Yoksa saatler arayla olan iki pencere
"ardışık" sayılıp modele yanlış bir süreklilik öğretilmiş olurdu.

    python lstm_sequences.py data/windows_lycos.csv [--seq-len 5]
"""

import sys
from collections import Counter, defaultdict

import _sensor  # noqa: F401
from dataset import assign_split, load_windows
from features import FEATURES, WINDOW_SECONDS

SEQ_LEN = 5


def _contiguous_runs(members, step=WINDOW_SECONDS):
    """window_start'a göre sıralı pencereleri, tam `step` aralıklı ardışık çalışmalara böler."""
    runs, current, prev = [], [], None
    for r in members:
        if prev is not None and r["window_start"] != prev + step:
            runs.append(current)
            current = []
        current.append(r)
        prev = r["window_start"]
    if current:
        runs.append(current)
    return runs


def build_sequences(rows, seq_len=SEQ_LEN):
    """assign_split çıktısından (X, y, split) döner.

    X[i]: seq_len pencerenin FEATURES sırasıyla sayı dizisi (liste-liste, uzunluk seq_len).
    y[i]: dizinin SON penceresinin sınıfı (cls).
    split[i]: dizinin bölmesi ("train" ya da "test").
    Dışarıda kalan (excluded) ve gap pencereleri, kaynak IP+bölme+sınıf sınırını aşan ve
    aralarında zaman boşluğu olan birleşmeler kullanılmaz.
    """
    groups = defaultdict(list)
    for r in rows:
        if r["split"] in ("train", "test"):
            groups[(r["src_ip"], r["split"], r["cls"])].append(r)

    X, y, split = [], [], []
    for members in groups.values():
        members = sorted(members, key=lambda r: r["window_start"])
        for run in _contiguous_runs(members):
            for i in range(len(run) - seq_len + 1):
                chunk = run[i:i + seq_len]
                X.append([[w[f] for f in FEATURES] for w in chunk])
                y.append(chunk[-1]["cls"])
                split.append(chunk[-1]["split"])
    return X, y, split


def format_summary(X, y, split, seq_len=SEQ_LEN):
    counts = Counter(zip(split, y))
    classes = sorted({c for _, c in counts})
    lines = [f"dizi uzunluğu: {seq_len}", f"{'':12}" + "".join(f"{s:>9}" for s in ("train", "test"))]
    for cls in classes:
        lines.append(f"{cls:12}" + "".join(f"{counts.get((s, cls), 0):>9}" for s in ("train", "test")))
    lines.append(f"toplam dizi: {len(X)}")
    return "\n".join(lines)


if __name__ == "__main__":
    args = sys.argv[1:]
    seq_len = SEQ_LEN
    if "--seq-len" in args:
        i = args.index("--seq-len")
        seq_len = int(args[i + 1])
        del args[i:i + 2]
    if len(args) != 1:
        raise SystemExit("kullanım: python lstm_sequences.py data/windows_lycos.csv [--seq-len N]")
    split_rows = assign_split(load_windows(args[0]))
    seqs_X, seqs_y, seqs_split = build_sequences(split_rows, seq_len=seq_len)
    print(format_summary(seqs_X, seqs_y, seqs_split, seq_len=seq_len))
