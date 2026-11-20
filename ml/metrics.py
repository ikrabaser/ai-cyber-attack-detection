"""Sınıflandırma metrikleri, elle yazılmış (ML-2). Hepsi bir "karışıklık matrisi"nden türer.

Karışıklık matrisi: satır = GERÇEK sınıf, sütun = TAHMİN. Köşegen doğru bildiklerimiz.

Bir sınıf (örn. port_scan) için:
    TP  gerçekten port_scan, port_scan dedik
    FP  aslında başka şey, port_scan dedik   (yanlış alarm)
    FN  aslında port_scan, başka şey dedik   (kaçırılan saldırı)

    precision = TP / (TP + FP)   "port_scan dediklerimizin kaçı gerçekten öyle?"
    recall    = TP / (TP + FN)   "gerçek port_scan'lerin kaçını yakaladık?"
    f1        = 2·P·R / (P + R)  ikisinin dengeli ortalaması (biri sıfırsa f1 de sıfır)

Neden accuracy'e güvenmiyoruz: veride pencerelerin %98'i normal. Hiçbir şey yakalamayan bir sistem de
%98 doğruluk alır. Bu yüzden sınıf sınıf precision/recall ve macro-F1 (sınıfların f1 ortalaması, her
sınıfa eşit ağırlık) raporlarız. Saldırı tespitinde ayrıca:
    FPR = normal pencerelerin kaçına yanlışlıkla saldırı dedik (yanlış alarm oranı)
"""


def confusion_matrix(y_true, y_pred, labels):
    """{gerçek: {tahmin: sayı}}; yalnızca `labels` içindeki sınıflar."""
    if len(y_true) != len(y_pred):
        raise ValueError("y_true ve y_pred aynı uzunlukta olmalı")
    m = {t: {p: 0 for p in labels} for t in labels}
    for t, p in zip(y_true, y_pred):
        m[t][p] += 1
    return m


def _safe_div(a, b):
    return a / b if b else 0.0


def per_class(matrix, labels):
    """Sınıf -> {precision, recall, f1, support}."""
    out = {}
    for c in labels:
        tp = matrix[c][c]
        fp = sum(matrix[t][c] for t in labels if t != c)
        fn = sum(matrix[c][p] for p in labels if p != c)
        precision, recall = _safe_div(tp, tp + fp), _safe_div(tp, tp + fn)
        out[c] = {"precision": precision, "recall": recall,
                  "f1": _safe_div(2 * precision * recall, precision + recall),
                  "support": sum(matrix[c].values())}
    return out


def macro_f1(per_class_report, labels=None):
    """Sınıfların f1 ortalaması. Destek (örnek sayısı) 0 olan sınıflar ortalamaya girmez."""
    scores = [v["f1"] for k, v in per_class_report.items()
              if v["support"] > 0 and (labels is None or k in labels)]
    return sum(scores) / len(scores) if scores else 0.0


def accuracy(matrix, labels):
    total = sum(sum(matrix[t].values()) for t in labels)
    return _safe_div(sum(matrix[c][c] for c in labels), total)


def false_positive_rate(matrix, labels, normal="normal"):
    """Normal pencerelerin kaçına saldırı dedik."""
    row = matrix[normal]
    return _safe_div(sum(v for p, v in row.items() if p != normal), sum(row.values()))


def evaluate(y_true, y_pred, labels):
    """Hepsi bir arada: matris, sınıf raporu, macro-F1, accuracy, FPR."""
    m = confusion_matrix(y_true, y_pred, labels)
    pc = per_class(m, labels)
    return {"matrix": m, "per_class": pc, "macro_f1": macro_f1(pc), "accuracy": accuracy(m, labels),
            "fpr": false_positive_rate(m, labels) if "normal" in labels else None}


def format_report(result, labels):
    w = max(len(c) for c in labels) + 2
    lines = [f"{'':{w}}{'precision':>10}{'recall':>9}{'f1':>7}{'destek':>9}"]
    for c in labels:
        r = result["per_class"][c]
        lines.append(f"{c:{w}}{r['precision']:>10.3f}{r['recall']:>9.3f}{r['f1']:>7.3f}{r['support']:>9}")
    lines.append(f"macro-F1 {result['macro_f1']:.3f}   accuracy {result['accuracy']:.3f}"
                 + (f"   FPR {result['fpr']:.4f}" if result["fpr"] is not None else ""))
    lines.append("karışıklık matrisi (satır=gerçek, sütun=tahmin):")
    lines.append(f"{'':{w}}" + "".join(f"{p:>{w}}" for p in labels))
    for t in labels:
        lines.append(f"{t:{w}}" + "".join(f"{result['matrix'][t][p]:>{w}}" for p in labels))
    return "\n".join(lines)
