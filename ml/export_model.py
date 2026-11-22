"""Eğitilmiş XGBoost modelini sensörün okuyacağı küçük JSON'a çevirir (ML-7).

Kullanım:
    python export_model.py data/xgb.json ../sensor/models/xgb.json

Girdi, `train_xgb.py --save` ile yazılan XGBoost JSON'udur. Çıktı yalnızca ağaçların iskeletini
(özellik, eşik, çocuklar, yaprak değeri) ve sınıf/özellik sırasını içerir; `sensor/tree_model.py` okur.
"""

import argparse
import json
import math
import sys

import _sensor  # noqa: F401  (sensor/ yolunu ekler)
from dataset import CLASSES
from features import FEATURES


def convert(xgb_json):
    learner = xgb_json["learner"]
    param = learner["learner_model_param"]
    if learner["objective"]["name"] != "multi:softprob":
        raise ValueError("yalnızca multi:softprob modelleri destekleniyor")
    if int(param["num_class"]) != len(CLASSES) or int(param["num_feature"]) != len(FEATURES):
        raise ValueError("model sınıf/özellik sayısı projeyle uyuşmuyor")
    model = learner["gradient_booster"]["model"]

    # XGBoost 3.x: base_score sınıf başına olasılık uzayında yazılır; softmax'tan önceki taban puan
    # (margin) için logit dönüşümü gerekmez, ama olasılıktan çevirmek gerekir (bkz. test).
    raw = param["base_score"]
    base = json.loads(raw) if raw.startswith("[") else [float(raw)] * len(CLASSES)

    trees = []
    for t in model["trees"]:
        if any(s != 0 for s in t["split_type"]):
            raise ValueError("kategorik bölmeler desteklenmiyor")
        feat = list(t["split_indices"])
        thr = list(t["split_conditions"])
        left, right = list(t["left_children"]), list(t["right_children"])
        trees.append({"f": feat, "t": thr, "l": left, "r": right, "d": [int(v) for v in t["default_left"]]})
    return {
        "classes": CLASSES,
        "features": FEATURES,
        "base_margin": base,
        "tree_class": [int(c) for c in model["tree_info"]],
        "trees": trees,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("src")
    ap.add_argument("dst")
    args = ap.parse_args(argv)
    with open(args.src, encoding="utf-8") as fh:
        out = convert(json.load(fh))
    with open(args.dst, "w", encoding="utf-8") as fh:
        json.dump(out, fh, separators=(",", ":"))
    print(f"{len(out['trees'])} ağaç yazıldı: {args.dst}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
