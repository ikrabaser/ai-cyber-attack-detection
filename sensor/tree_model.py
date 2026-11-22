"""Eğitilmiş XGBoost modelini XGBoost'suz çalıştırır (ML-7: modeli canlı sensöre bağlama).

Neden ayrı bir yorumlayıcı? Sensör yalnızca standart kütüphaneyle çalışır; xgboost + numpy +
scikit-learn kurmak onu şişirir. Oysa bir XGBoost modeli sadece bir ağaç listesidir: her ağaçta
"özellik x eşikten küçükse sola, değilse sağa" diye inilir, yaprağa varınca bir sayı alınır.
Sınıf başına yaprak sayıları toplanır, softmax ile olasılığa çevrilir. Bu dosya o kadarını yapar.

Model dosyası `ml/export_model.py` ile üretilir (biçim: aşağıdaki `load`). Sensör sadece bu dosyayı
okur; eğitim kodunu veya xgboost'u görmez.

Birebir aynı sonucu vermek için iki ayrıntı önemli:
  - XGBoost özellikleri ve eşikleri 32 bit (float32) tutar; karşılaştırmadan önce biz de 32 bite yuvarlarız.
  - Bölme kuralı "x < eşik" (küçük-eşit değil).
"""

import json
import math
import struct

from features import FEATURES


def _f32(x):
    return struct.unpack("f", struct.pack("f", x))[0]


class TreeModel:
    """`classes` sırasına göre olasılık veren, bağımlılıksız ağaç topluluğu."""

    def __init__(self, classes, features, base_margin, trees, tree_class):
        if list(features) != list(FEATURES):
            raise ValueError(
                f"model özellik sırası sensörünkiyle uyuşmuyor: {list(features)} != {list(FEATURES)}"
            )
        if len(trees) != len(tree_class):
            raise ValueError("her ağaç için bir sınıf numarası gerekir")
        if len(base_margin) != len(classes):
            raise ValueError("sınıf başına bir taban değer gerekir")
        self.classes = list(classes)
        self.features = list(features)
        self.base_margin = list(base_margin)
        # Ağaç = (özellik, eşik/yaprak değeri, sol, sağ, boşsa-sola) dizileri. Eşikler float32'ye yuvarlı.
        self.trees = [
            (t["f"], [_f32(v) for v in t["t"]], t["l"], t["r"], t["d"]) for t in trees
        ]
        self.tree_class = list(tree_class)

    @classmethod
    def load(cls, path):
        with open(path, encoding="utf-8") as fh:
            d = json.load(fh)
        return cls(d["classes"], d["features"], d["base_margin"], d["trees"], d["tree_class"])

    def _leaf(self, tree, x):
        feat, thr, left, right, dleft = tree
        node = 0
        while left[node] != -1:
            v = x[feat[node]]
            if v != v:  # NaN: eksik değer, kaydedilen varsayılan yöne
                node = left[node] if dleft[node] else right[node]
            else:
                node = left[node] if v < thr[node] else right[node]
        return thr[node]  # yaprakta "eşik" alanı yaprak değerini taşır

    def margins(self, row):
        """Ham puanlar (softmax'tan önce), sınıf sırasına göre."""
        x = [_f32(float(row[name])) for name in self.features]
        m = list(self.base_margin)
        for tree, c in zip(self.trees, self.tree_class):
            m[c] += self._leaf(tree, x)
        return m

    def predict_proba(self, row):
        """{sınıf: olasılık}. Toplamları 1."""
        m = self.margins(row)
        top = max(m)
        e = [math.exp(v - top) for v in m]
        s = sum(e)
        return {c: v / s for c, v in zip(self.classes, e)}
