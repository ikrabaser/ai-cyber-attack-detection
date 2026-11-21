"""Autoencoder (ML-5): yalnızca NORMAL trafiği öğrenir, öğrenmediği her şeyi "tuhaf" diye işaretler.

    python autoencoder.py data/windows_lycos.csv
    python autoencoder.py data/windows_lycos.csv --json data/ae_report.json

Fikir: 7 sayıyı 3 sayıya sıkıştırıp (kodlayıcı) tekrar 7 sayıya açan (çözücü) küçük bir sinir ağı. Yalnızca
normal pencerelerle eğitilince normal trafiği iyi "yeniden kurar". Saldırı penceresini kuramaz, çünkü
bunun gibi bir şey görmedi: yeniden kurma hatası büyür. Hata büyükse alarm. XGBoost'tan farkı: saldırı
ÖRNEĞİ görmez, bu yüzden hiç tanımadığı saldırı türlerini de yakalama şansı vardır.

Karar eşiği: eğitim kısmındaki normal pencerelerin SON %20'sinde (zamanca testten önce) ölçülen hatanın
yüzdelik dilimi. Örneğin %99: "normalin %1'ine yanlış alarm vermeyi göze al". Eşik test setine bakılarak
seçilmez. Mimari ve hiperparametreler sabit ve önceden belirlendi; sinir ağı rastgele başlatmaya duyarlı
olduğundan 5 tohumla çalıştırılır ve ortalama ile en kötü/en iyi değer birlikte verilir.

Ölçüm: test normal pencerelerine karşı her saldırı türü için
  - recall: eşiğin üstüne çıkan saldırı penceresi oranı,
  - AUC: rastgele bir saldırı penceresinin rastgele bir normal pencereden daha yüksek hata alma olasılığı
    (0,5 = şans, 1,0 = mükemmel ayrım; eşikten bağımsız).
Görülen türler (port tarama, kaba kuvvet) yalnızca test bölmesinden; eğitimde hiç kullanılmayan türler
(DoS, web saldırıları, bot...) tüm pencerelerinden ölçülür. Kurallar ve XGBoost aynı pencerelerde
yan yana verilir ("alarm verdi" = normalden başka bir şey dedi).

Sınırlar: yalnızca bağlantı düzeyinde 7 özellik var; yük (HTTP içeriği) görünmez, bu yüzden web
saldırıları ve düşük hacimli trafik normalden ayrılamayabilir.
"""

import argparse
import json
import sys
from collections import defaultdict

import _sensor  # noqa: F401
from dataset import assign_split, load_windows
from features import FEATURES

HIDDEN = (5, 3, 5)  # 7 -> 5 -> 3 -> 5 -> 7: ortadaki 3 sayı "sıkıştırılmış hâl"
SEEDS = (0, 1, 2, 3, 4)
QUANTILES = (0.99, 0.999)
FIT_FRACTION = 0.8
LOG_FEATURES = ("n_conns", "n_dst_ports", "n_dst_hosts", "mean_duration", "mean_bytes")
MIN_RELIABLE = 30  # bundan az pencereli türün sonucu kesin değil, işaret


def _matrix(rows):
    import numpy as np

    a = np.array([[r[f] for f in FEATURES] for r in rows], dtype=float)
    for i, f in enumerate(FEATURES):
        if f in LOG_FEATURES:  # uzun kuyruklu sayılar: log1p ile sıkıştır (1 bağlantı ile 5000 bağlantı aynı ölçekte olsun)
            a[:, i] = np.log1p(a[:, i])
    return a


class Scaler:
    """Eğitim normallerinin ortalama ve standart sapmasıyla ölçekler (saldırılara bakmaz)."""

    def __init__(self, rows):
        a = _matrix(rows)
        self.mean = a.mean(axis=0)
        self.std = a.std(axis=0) + 1e-9

    def transform(self, rows):
        return (_matrix(rows) - self.mean) / self.std


def fit_validation_split(train_normals, fit_fraction=FIT_FRACTION):
    """Eğitim normallerini zamana göre böler: ilk %80 ağı eğitir, son %20 eşiği belirler."""
    ordered = sorted(train_normals, key=lambda r: (r["window_start"], r["src_ip"]))
    k = int(len(ordered) * fit_fraction)
    return ordered[:k], ordered[k:]


def train(fit_rows, seed, hidden=HIDDEN):
    """(ölçekleyici, ağ) döndürür. Ağ girdiyi kendisine benzetmeye çalışır (girdi = hedef)."""
    from sklearn.neural_network import MLPRegressor

    scaler = Scaler(fit_rows)
    z = scaler.transform(fit_rows)
    net = MLPRegressor(hidden_layer_sizes=hidden, activation="tanh", max_iter=200, random_state=seed)
    net.fit(z, z)
    return scaler, net


def errors(model, rows):
    """Pencere başına yeniden kurma hatası (ortalama kare hata, 7 özellik üzerinden)."""
    scaler, net = model
    if not rows:
        return []
    z = scaler.transform(rows)
    return ((net.predict(z) - z) ** 2).mean(axis=1)


def threshold(val_errors, q):
    import numpy as np

    return float(np.quantile(val_errors, q))


def attack_sets(rows):
    """{tür: pencereler}. Görülen türler (cls atanmış) yalnızca test bölmesinden, diğerleri tümünden.
    Karışık (label_share < 1) pencereler dışarıda."""
    sets = defaultdict(list)
    for r in rows:
        if r["label"] == "benign" or r["label_share"] < 1.0:
            continue
        if r["cls"] is not None and r["split"] != "test":
            continue
        sets[r["label"]].append(r)
    return dict(sets)


def auc(normal_errors, attack_errors):
    from sklearn.metrics import roc_auc_score

    y = [0] * len(normal_errors) + [1] * len(attack_errors)
    return float(roc_auc_score(y, list(normal_errors) + list(attack_errors)))


def evaluate_seed(model, val_rows, test_normals, sets):
    """Tek ağ için: eşik başına test normal yanlış alarm oranı ve tür başına recall + AUC."""
    val_err = errors(model, val_rows)
    en = errors(model, test_normals)
    out = {"fpr": {}, "recall": {}, "auc": {}}
    attack_err = {label: errors(model, rs) for label, rs in sets.items()}
    for q in QUANTILES:
        thr = threshold(val_err, q)
        out["fpr"][q] = float((en > thr).mean())
        out["recall"][q] = {label: float((e > thr).mean()) for label, e in attack_err.items()}
    out["auc"] = {label: auc(en, e) for label, e in attack_err.items()}
    return out


def summarize(per_seed):
    """Tohumlar arası: her değer için (ortalama, en küçük, en büyük)."""
    def stat(values):
        return {"mean": sum(values) / len(values), "min": min(values), "max": max(values)}

    labels = per_seed[0]["auc"].keys()
    return {
        "fpr": {q: stat([s["fpr"][q] for s in per_seed]) for q in QUANTILES},
        "recall": {q: {l: stat([s["recall"][q][l] for s in per_seed]) for l in labels} for q in QUANTILES},
        "auc": {l: stat([s["auc"][l] for s in per_seed]) for l in labels},
    }


def comparator_rates(rows, sets):
    """Kurallar ve XGBoost'un aynı pencerelerde alarm verme oranı (normalden başka bir şey demesi)."""
    from baseline import rule_predictions
    from train_xgb import predict, train as train_xgb

    rule = rule_predictions(rows)
    xgb = train_xgb([r for r in rows if r["split"] == "train"])
    rates = {"rules": {}, "xgb": {}}
    for label, rs in sets.items():
        rates["rules"][label] = sum(1 for r in rs if (r["src_ip"], r["window_start"]) in rule) / len(rs)
        rates["xgb"][label] = sum(1 for p in predict(xgb, rs) if p != "normal") / len(rs)
    tn = [r for r in rows if r["split"] == "test" and r["cls"] == "normal"]
    rates["fpr"] = {
        "rules": sum(1 for r in tn if (r["src_ip"], r["window_start"]) in rule) / len(tn),
        "xgb": sum(1 for p in predict(xgb, tn) if p != "normal") / len(tn),
    }
    return rates


def volume_baseline(val_rows, test_normals, sets, feature="n_conns"):
    """En basit rakip: tek özellikte (bağlantı sayısı) eşik. Eşik, autoencoder ile AYNI yoldan
    (doğrulama normallerinin yüzdelik dilimi) bulunur. Autoencoder bunun üstüne ne katıyor sorusu için."""
    import numpy as np

    out = {}
    for q in QUANTILES:
        thr = float(np.quantile([r[feature] for r in val_rows], q))
        out[q] = {"feature": feature, "threshold": thr,
                  "fpr": sum(1 for r in test_normals if r[feature] > thr) / len(test_normals),
                  "recall": {l: sum(1 for r in rs if r[feature] > thr) / len(rs) for l, rs in sets.items()}}
    return out


def run(rows, seeds=SEEDS, hidden=HIDDEN):
    train_normals = [r for r in rows if r["split"] == "train" and r["cls"] == "normal"]
    fit_rows, val_rows = fit_validation_split(train_normals)
    test_normals = [r for r in rows if r["split"] == "test" and r["cls"] == "normal"]
    sets = attack_sets(rows)
    per_seed = [evaluate_seed(train(fit_rows, s, hidden), val_rows, test_normals, sets) for s in seeds]
    return {
        "hidden": list(hidden), "seeds": list(seeds),
        "counts": {"fit": len(fit_rows), "val": len(val_rows), "test_normal": len(test_normals),
                   "attacks": {l: len(rs) for l, rs in sets.items()}},
        "ae": summarize(per_seed),
        "others": comparator_rates(rows, sets),
        "volume": volume_baseline(val_rows, test_normals, sets),
    }


def format_report(rep):
    ae, oth, vol, c = rep["ae"], rep["others"], rep["volume"], rep["counts"]
    q1, q2 = QUANTILES
    lines = [f"mimari 7-{'-'.join(map(str, rep['hidden']))}-7, {len(rep['seeds'])} tohum; eğitim {c['fit']}, "
             f"eşik (doğrulama) {c['val']}, test normal {c['test_normal']} pencere", ""]
    lines.append("yanlış alarm oranı (test normal):")
    lines.append(f"  kurallar {oth['fpr']['rules']:.4f}  xgboost {oth['fpr']['xgb']:.4f}  "
                 f"n_conns eşiği p99 {vol[q1]['fpr']:.4f} / p99.9 {vol[q2]['fpr']:.4f}  "
                 f"AE p99 {ae['fpr'][q1]['mean']:.4f} / p99.9 {ae['fpr'][q2]['mean']:.4f}")
    lines.append("alarm verilen pencere oranı (recall):")
    lines.append(f"{'tür':26}{'n':>6} {'kural':>6} {'xgb':>6} {'hacim99':>8} {'hacim99.9':>10} {'AE99':>6} {'AE99.9':>7}   AE AUC (ort; min-max)")
    for label in sorted(c["attacks"], key=lambda l: -ae["auc"][l]["mean"]):
        n = c["attacks"][label]
        mark = "*" if n < MIN_RELIABLE else " "
        a = ae["auc"][label]
        lines.append(f"{label:26}{n:>5}{mark} {oth['rules'][label]:>6.2f} {oth['xgb'][label]:>6.2f} "
                     f"{vol[q1]['recall'][label]:>8.2f} {vol[q2]['recall'][label]:>10.2f} "
                     f"{ae['recall'][q1][label]['mean']:>6.2f} {ae['recall'][q2][label]['mean']:>7.2f}   "
                     f"{a['mean']:.3f} ({a['min']:.3f}-{a['max']:.3f})")
    lines.append(f"(* = {MIN_RELIABLE}'dan az pencere: kesin sonuç değil, işaret; hacim = yalnızca bağlantı sayısı eşiği)")
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("csv")
    ap.add_argument("--json", help="sonucu bu dosyaya yaz")
    args = ap.parse_args(argv)
    rep = run(assign_split(load_windows(args.csv)))
    print(format_report(rep))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(rep, fh, ensure_ascii=False, indent=1, default=str)
        print("\nyazıldı:", args.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
