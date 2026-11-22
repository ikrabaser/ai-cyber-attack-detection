"""Etiket gürültüsü deneyi: "benign" etiketli ama saldırgan adresinden gelen pencereler (ML-8).

    python label_noise.py data/windows_lycos.csv

Neden? CIC-IDS2017'de bütün saldırılar tek adresten (172.16.0.1, güvenlik duvarının NAT adresi) gelir.
Bu adresten "benign" etiketli pencereler de var. Bulgu (bkz. `profile`): bu pencerelerin çoğunda bağlantıların
hepsi başarısız, bayt yok ve aynı adresin saldırı pencerelerinin hemen yanında duruyorlar: tarama kuyruğu
gibi görünüyor, normal trafik gibi değil. Eğer öyleyse XGBoost'un bu pencerelerde verdiği "yanlış alarm"
aslında etiket hatasıdır.

KANIT SINIRI: pcap olmadan hangisinin gerçekten saldırı olduğunu bilemeyiz. Bu yüzden pencereleri yeniden
etiketlemiyoruz; "şüpheli" diye işaretleyip sonucu iki şekilde veriyoruz (hepsi dahil / şüpheliler dışarıda)
ve eğitimden çıkarmanın etkisine bakıyoruz. Gerçek ayrım için etiketi bizim bildiğimiz lab verisi gerekir.
"""

import sys

import _sensor  # noqa: F401
from baseline import rule_predictions
from dataset import CLASSES, assign_split, load_windows
from metrics import evaluate

SUSPECT_IP = "172.16.0.1"
NEAR_ATTACK_SECONDS = 300


def is_suspect(row):
    """Normal etiketli ama saldırıların geldiği adresten gelen pencere."""
    return row["cls"] == "normal" and row["src_ip"] == SUSPECT_IP


def profile(rows):
    """Şüpheli pencerelerin özeti, diğer normallerle kıyas."""
    suspects = [r for r in rows if is_suspect(r)]
    others = [r for r in rows if r["cls"] == "normal" and not is_suspect(r)]
    # Yakınlık: bu adresin herhangi bir saldırı etiketli penceresi (DoS, web saldırısı dahil, "excluded" olanlar da).
    attack_times = sorted(r["window_start"] for r in rows if r["src_ip"] == SUSPECT_IP and r["label"] != "benign")

    def all_failed(r):
        return r["fail_ratio"] >= 1.0

    def failed_empty(r):
        return r["fail_ratio"] >= 1.0 and r["mean_bytes"] == 0

    def near(r):
        return any(abs(t - r["window_start"]) <= NEAR_ATTACK_SECONDS for t in attack_times)

    def share(rs, pred):
        return sum(1 for r in rs if pred(r)) / len(rs) if rs else 0.0

    return {
        "suspects": len(suspects),
        "suspect_all_failed": share(suspects, all_failed),
        "others_all_failed": share(others, all_failed),
        "suspect_failed_empty": share(suspects, failed_empty),
        "others_failed_empty": share(others, failed_empty),
        "suspect_near_attack": share(suspects, near),
    }


def _summary(y_true, y_pred):
    res = evaluate(y_true, y_pred, CLASSES)
    normals = sum(res["matrix"]["normal"].values())
    false_alarms = round(res["fpr"] * normals)
    ps = res["per_class"]["port_scan"]
    return {"normals": normals, "false_alarms": false_alarms, "fpr": res["fpr"],
            "ps_precision": ps["precision"], "ps_recall": ps["recall"], "macro_f1": res["macro_f1"]}


def compare(rows, train_fn, predict_fn):
    """Satırlar: {(yöntem, değerlendirme): özet}. Yöntemler: kurallar, model (tüm eğitim), model (şüpheliler eğitimde yok)."""
    rule_pred = rule_predictions(rows)
    train_all = [r for r in rows if r["split"] == "train"]
    train_clean = [r for r in train_all if not is_suspect(r)]
    test_all = [r for r in rows if r["split"] == "test"]
    test_clean = [r for r in test_all if not is_suspect(r)]

    predictors = {
        "kurallar": lambda rs: [rule_pred.get((r["src_ip"], r["window_start"]), "normal") for r in rs],
        "model": (lambda m: lambda rs: predict_fn(m, rs))(train_fn(train_all)),
        "model (şüpheli eğitimde yok)": (lambda m: lambda rs: predict_fn(m, rs))(train_fn(train_clean)),
    }
    out = {}
    for name, predict in predictors.items():
        for label, test in (("tüm test", test_all), ("şüpheliler hariç", test_clean)):
            out[(name, label)] = _summary([r["cls"] for r in test], predict(test))
    return out


def format_comparison(result):
    lines = [f"{'yöntem':30}{'değerlendirme':18}{'normal':>8}{'yanlış alarm':>14}{'FPR %':>8}"
             f"{'tarama P':>10}{'tarama R':>10}{'macro-F1':>10}"]
    for (name, label), s in result.items():
        lines.append(f"{name:30}{label:18}{s['normals']:8}{s['false_alarms']:14}{s['fpr'] * 100:8.3f}"
                     f"{s['ps_precision']:10.2f}{s['ps_recall']:10.2f}{s['macro_f1']:10.3f}")
    return "\n".join(lines)


def main(path):
    from train_xgb import predict, train

    rows = assign_split(load_windows(path))
    p = profile(rows)
    print(f"{SUSPECT_IP} adresinden 'benign' etiketli pencere: {p['suspects']}")
    print(f"  bağlantıların hepsi başarısız: %{p['suspect_all_failed'] * 100:.0f} "
          f"(diğer normal pencerelerde %{p['others_all_failed'] * 100:.2f})")
    print(f"  hepsi başarısız ve hiç bayt yok: %{p['suspect_failed_empty'] * 100:.0f} "
          f"(diğer normal pencerelerde %{p['others_failed_empty'] * 100:.2f})")
    print(f"  aynı adresin herhangi bir saldırı penceresine {NEAR_ATTACK_SECONDS} sn'den yakın: %{p['suspect_near_attack'] * 100:.0f}\n")
    print(format_comparison(compare(rows, train, predict)))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("kullanım: python label_noise.py data/windows_lycos.csv")
    main(sys.argv[1])
