"""XGBoost sınıflandırıcı (ML-3): aynı bölmede, aynı metriklerle, kurallarla yarışır.

    python train_xgb.py data/windows_lycos.csv            # eğit, test et, kurallarla kıyasla
    python train_xgb.py data/windows_lycos.csv --save data/xgb.json

Girdi: sensörün 7 özelliği (`features.FEATURES`), başka hiçbir şey. `src_ip`, `top_port`, gün gibi
sütunlar bilerek model girdisi DEĞİL: saldırının hepsi tek bir IP'den (172.16.0.1) geldiği için model
IP'yi öğrenirse "saldırgan IP'sini tanıyan" bir şey olur, saldırı davranışını değil.

Boosting kısaca: ağaçlar PEŞ PEŞE eklenir; her yeni ağaç, şimdiye kadarki ağaçların yaptığı HATALARI
düzeltmeye çalışır. Tek bir derin ağaç yerine yüzlerce küçük (max_depth=4) ağacın toplamı. `learning_rate`
her yeni ağacın katkısını küçültür (aşırı ezberlemeyi azaltır). Rastgele orman (bagging) ise ağaçları
birbirinden bağımsız eğitip oy birliğine bakar.

Sınıf dengesizliği: eğitimde normal pencereler saldırılardan yüzlerce kat fazla. Düzeltmeden eğitirsek
model "hep normal de" diye kolay yolu seçer. Her örneğe sınıfının nadirliğiyle ters orantılı ağırlık
veriyoruz (`balanced_weights`): nadir sınıfın bir hatası daha pahalı olur.

Hiperparametreler SABİT ve ayarlanmadı: test setine bakarak ayar yaparsak test artık "görülmemiş" olmaz.
Ayarlama gerekirse yalnızca eğitim kısmında, zamana göre iç doğrulamayla yapılmalı.
"""

import argparse
from collections import Counter

import _sensor  # noqa: F401
from baseline import evaluate_rules
from dataset import CLASSES, assign_split, feature_matrix, format_summary, load_windows
from features import FEATURES
from metrics import evaluate, format_report

PARAMS = {
    "n_estimators": 200,
    "max_depth": 4,
    "learning_rate": 0.1,
    "subsample": 0.8,
    "colsample_bytree": 0.8,
    "random_state": 0,
    "n_jobs": 1,
    "tree_method": "hist",
    "eval_metric": "mlogloss",
}


def balanced_weights(y):
    """Her örnek için: toplam / (sınıf sayısı x o sınıfın örnek sayısı). Hep eşit ağırlıkta toplanır."""
    counts = Counter(y)
    n, k = len(y), len(counts)
    return [n / (k * counts[c]) for c in y]


def encode(y, classes=CLASSES):
    return [classes.index(c) for c in y]


def train(rows, params=None):
    """`split == "train"` olan satırlarla XGBoost eğitir; eğitilmiş model döndürür."""
    from xgboost import XGBClassifier

    X, y = feature_matrix(rows)
    model = XGBClassifier(objective="multi:softprob", num_class=len(CLASSES), **(params or PARAMS))
    model.fit(X, encode(y), sample_weight=balanced_weights(y))
    return model


def predict_proba(model, rows):
    """Satırlar -> her sınıf için olasılık (sütun sırası CLASSES)."""
    X, _ = feature_matrix(rows)
    return model.predict_proba(X)


def predict(model, rows):
    return [CLASSES[i] for i in predict_proba(model, rows).argmax(axis=1)]


def evaluate_model(model, rows):
    """Satırlardaki gerçek sınıflarla `metrics.evaluate` sonucu + sınıf başına PR-AUC (average precision)."""
    from sklearn.metrics import average_precision_score

    y_true = [r["cls"] for r in rows]
    result = evaluate(y_true, predict(model, rows), CLASSES)
    proba = predict_proba(model, rows)
    result["pr_auc"] = {}
    for i, c in enumerate(CLASSES):
        positives = [1 if t == c else 0 for t in y_true]
        if 0 < sum(positives) < len(positives):
            result["pr_auc"][c] = float(average_precision_score(positives, proba[:, i]))
    return result


def importances(model):
    """Özellik -> önem (toplamı 1), büyükten küçüğe. XGBoost'ta varsayılan ölçü "gain": o özelliğin
    bölmelerinin hatayı ne kadar azalttığı. Hiç kullanılmayan özelliğin önemi 0'dır."""
    return sorted(zip(FEATURES, (float(v) for v in model.feature_importances_)),
                  key=lambda kv: kv[1], reverse=True)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("csv")
    ap.add_argument("--save", help="eğitilen modeli bu dosyaya yaz (JSON)")
    args = ap.parse_args(argv)

    rows = assign_split(load_windows(args.csv))
    print(format_summary(rows))
    train_rows = [r for r in rows if r["split"] == "train"]
    test_rows = [r for r in rows if r["split"] == "test"]
    model = train(train_rows)

    print("\n=== XGBOOST - TEST ===")
    res = evaluate_model(model, test_rows)
    print(format_report(res, CLASSES))
    print("PR-AUC:", {c: round(v, 3) for c, v in res["pr_auc"].items()})

    print("\n=== KURALLAR (tetiklenen her alarm) - TEST, kıyas için ===")
    print(format_report(evaluate_rules(rows, ("test",)), CLASSES))

    print("\nözellik önemi (gain, toplam 1):")
    for name, gain in importances(model):
        print(f"  {name:16}{gain:8.3f}")
    if args.save:
        model.save_model(args.save)
        print(f"\nmodel yazıldı: {args.save}")


if __name__ == "__main__":
    main()
