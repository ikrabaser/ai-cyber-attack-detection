"""Kural tabanlı kıyas noktası (ML-2): sensörün kuralları aynı pencerelerde ne kadar iyi?

    python baseline.py data/windows_lycos.csv

Modeller (XGBoost, Autoencoder...) "kurallardan daha mı iyi?" sorusuna ancak bu sayılarla cevap verebilir.

Kurallar (`sensor/rules.py`) AYNEN kullanılır, burada yeniden yazılmaz. İki not:
- Kurallar durumludur (ısrar bonusu): TÜM pencereler zamana göre kurala verilir, değerlendirme sonra
  yalnızca ilgili bölmenin pencerelerinde yapılır. Sensör de canlıda böyle görürdü.
- CIC-IDS2017'de Zeek ssh.log yok: `ssh_failed_auth` her pencerede 0 verilir, yani "başarısız parola"
  kanıtı kullanılamaz; brute force yalnızca bağlantı sayısından yakalanabilir. Bu, kuralların
  CIC üzerindeki sonucunu olduğundan kötü gösterebilir ve raporda belirtilmeli.

Kural bir pencerede tetiklenirse tahmin kuralın sınıfıdır (port_scan / brute_force), tetiklenmezse normal.
`min_score` ile "orta ve üstü alarm" (panelde görünen, skor >= 0,7) gibi daha sıkı varyantlar denenir.
"""

import sys

import _sensor  # noqa: F401
from dataset import CLASSES, assign_split, format_summary, load_windows
from metrics import evaluate, format_report
from rules import MEDIUM_AT, detect


def rule_predictions(rows, min_score=0.0):
    """{(src_ip, window_start): tahmin edilen sınıf}. Tetiklenmeyen pencere "normal" sayılır."""
    ordered = sorted(rows, key=lambda r: (r["window_start"], r["src_ip"]))
    fed = [dict(r, ssh_failed_auth=0) for r in ordered]
    preds = {}
    for d in detect(fed):
        if d.risk_score >= min_score:
            preds[(d.src_ip, d.window_start)] = d.attack_type
    return preds


def evaluate_rules(rows, splits=("test",), min_score=0.0):
    """Kuralları `rows` (assign_split çıktısı) üzerinde çalıştırır, seçili bölmeleri değerlendirir."""
    preds = rule_predictions(rows, min_score)
    chosen = [r for r in rows if r["split"] in splits]
    y_true = [r["cls"] for r in chosen]
    y_pred = [preds.get((r["src_ip"], r["window_start"]), "normal") for r in chosen]
    return evaluate(y_true, y_pred, CLASSES)


def main(path):
    rows = assign_split(load_windows(path))
    print(format_summary(rows))
    for title, splits, min_score in [
        ("KURALLAR (tetiklenen her alarm) - TEST", ("test",), 0.0),
        (f"KURALLAR (skor >= {MEDIUM_AT}) - TEST", ("test",), MEDIUM_AT),
        ("KURALLAR (tetiklenen her alarm) - TRAIN+TEST (daha çok örnek)", ("train", "test"), 0.0),
    ]:
        print(f"\n=== {title} ===")
        print(format_report(evaluate_rules(rows, splits, min_score), CLASSES))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("kullanım: python baseline.py data/windows_lycos.csv")
    main(sys.argv[1])
