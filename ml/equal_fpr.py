"""H1: kurallar ve XGBoost AYNI yanlış alarm oranında karşılaştırılınca hangisi daha çok saldırı yakalıyor?

    python equal_fpr.py data/windows_lycos.csv

Neden? Şu ana kadarki kıyas "her yöntemin kendi eşiğinde" yapıldı: kuralların yanlış alarmı %0,02, modelinki
%0,1. Daha çok alarm veren yöntem doğal olarak daha çok saldırı yakalar; bu adil bir kıyas değil. Adil kıyas:
yanlış alarm oranını sabitle, o orandaki yakalama oranına (recall) bak.

Her sınıf için (port_scan, brute_force) her pencereye bir "skor" veriyoruz:
  - model: o sınıfın olasılığı
  - kurallar: o sınıfta tetiklenen kuralın risk skoru (tetiklenmediyse 0); ısrar bonusu dahil
Eşik taranır; "normal pencerelerin en çok %X'i alarm versin" şartıyla yakalanan saldırı oranı hesaplanır.
Kuralların skoru birkaç değer alır, yani kural eğrisi seyrek noktalardan oluşur: hedef orana ulaşılamıyorsa
kural o orandaki en iyi noktasını verir (hiçbiri yoksa 0).
"""

import math
import sys

import _sensor  # noqa: F401
from dataset import assign_split, load_windows
from label_noise import is_suspect
from rules import detect

CLASSES_UNDER_TEST = ("port_scan", "brute_force")
TARGETS = (0.0002, 0.0005, 0.001, 0.005, 0.01)  # yanlış alarm oranı hedefleri (%0,02 ... %1)


def rule_scores(rows):
    """{(src_ip, window_start): (tür, skor)}: kuralların her pencere için verdiği en yüksek skorlu tespit."""
    ordered = sorted(rows, key=lambda r: (r["window_start"], r["src_ip"]))
    fed = [dict(r, ssh_failed_auth=0) for r in ordered]  # CIC'de ssh.log yok
    return {(d.src_ip, d.window_start): (d.attack_type, d.risk_score) for d in detect(fed)}


def recall_at_fpr(pos_scores, neg_scores, target):
    """Normallerin en çok `target` oranı eşiği geçsin; en düşük (en cömert) böyle eşikte yakalanan pozitif oranı.

    Dönüş: (recall, gerçekleşen yanlış alarm oranı, eşik). Hiçbir eşik şartı sağlamıyorsa recall 0.
    Eşit skorlar birlikte geçer ya da birlikte kalır (bağlı skorları bölmeyiz).
    """
    if not pos_scores or not neg_scores:
        return 0.0, 0.0, None
    best = (0.0, 0.0, None)
    for thr in sorted({s for s in pos_scores + neg_scores if s > 0}, reverse=True):
        fpr = sum(s >= thr for s in neg_scores) / len(neg_scores)
        if fpr > target:
            break
        best = (sum(s >= thr for s in pos_scores) / len(pos_scores), fpr, thr)
    return best


def wilson(k, n, z=1.96):
    """Oran için %95 Wilson güven aralığı (küçük n'de normal yaklaşımdan güvenilir)."""
    if n == 0:
        return 0.0, 0.0
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, c - h), min(1.0, c + h)


def collect_scores(rows, proba_fn):
    """Test pencereleri için {yöntem: {sınıf: (pozitif skorlar, negatif (normal) skorlar)}}."""
    from dataset import CLASSES

    rs = rule_scores(rows)
    test = [r for r in rows if r["split"] == "test" and r["cls"]]
    proba = proba_fn(test)  # satır başına sınıf sırasıyla olasılıklar
    out = {"kurallar": {}, "model": {}}
    for c in CLASSES_UNDER_TEST:
        ci = CLASSES.index(c)
        rule_s = [rs.get((r["src_ip"], r["window_start"]), (None, 0.0)) for r in test]
        rule_s = [s if t == c else 0.0 for t, s in rule_s]
        model_s = [float(p[ci]) for p in proba]
        for name, scores in (("kurallar", rule_s), ("model", model_s)):
            pos = [s for s, r in zip(scores, test) if r["cls"] == c]
            neg = [s for s, r in zip(scores, test) if r["cls"] == "normal"]
            keep = [not is_suspect(r) for r in test if r["cls"] == "normal"]
            out[name][c] = {"pos": pos, "neg": neg, "neg_clean": [s for s, k in zip(neg, keep) if k]}
    return out


def compare(scores, key="neg", targets=TARGETS):
    """Satırlar: (sınıf, hedef) -> {yöntem: (recall, gerçekleşen fpr, n_pos, güven aralığı)}."""
    rows = {}
    for c in CLASSES_UNDER_TEST:
        for t in targets:
            cell = {}
            for method in ("kurallar", "model"):
                d = scores[method][c]
                recall, fpr, _ = recall_at_fpr(d["pos"], d[key], t)
                k = round(recall * len(d["pos"]))
                cell[method] = (recall, fpr, len(d["pos"]), wilson(k, len(d["pos"])))
            rows[(c, t)] = cell
    return rows


def format_comparison(rows):
    lines = [f"{'sınıf':13}{'hedef FPR':>10}  {'kurallar recall (gerç. FPR)':>30}  {'model recall (gerç. FPR)':>28}  {'pozitif':>8}"]
    for (c, t), cell in rows.items():
        def f(m):
            r, fpr, n, (lo, hi) = cell[m]
            return f"{r:5.2f} [{lo:.2f}-{hi:.2f}] ({fpr * 100:.3f}%)"
        lines.append(f"{c:13}{t * 100:9.3f}%  {f('kurallar'):>30}  {f('model'):>28}  {cell['model'][2]:8}")
    return "\n".join(lines)


def panel_summary(scores, targets=TARGETS):
    """Panelin gösterdiği özet: sınıf ve hedef yanlış alarm oranı başına iki yöntemin yakalama oranı (güven aralığıyla).

    İki varyant: "all" (normallerin hepsi) ve "clean" (172.16.0.1'den gelen şüpheli normaller hariç).
    """
    out = {"targets": list(targets), "classes": list(CLASSES_UNDER_TEST), "variants": {}}
    for variant, key in (("all", "neg"), ("clean", "neg_clean")):
        rows = []
        for (c, t), cell in compare(scores, key, targets).items():
            entry = {"cls": c, "target": t, "n_pos": cell["model"][2]}
            for method, name in (("kurallar", "rules"), ("model", "model")):
                recall, fpr, _, (lo, hi) = cell[method]
                entry[name] = {"recall": recall, "fpr": fpr, "lo": lo, "hi": hi}
            rows.append(entry)
        out["variants"][variant] = rows
    return out


def main(path):
    from train_xgb import predict_proba, train

    rows = assign_split(load_windows(path))
    model = train([r for r in rows if r["split"] == "train"])
    scores = collect_scores(rows, lambda rs: predict_proba(model, rs))
    print("=== TÜM TEST (normal pencereler: hepsi) ===")
    print(format_comparison(compare(scores, "neg")))
    print("\n=== 172.16.0.1'den gelen 'benign' pencereler hariç ===")
    print(format_comparison(compare(scores, "neg_clean")))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("kullanım: python equal_fpr.py data/windows_lycos.csv")
    main(sys.argv[1])
