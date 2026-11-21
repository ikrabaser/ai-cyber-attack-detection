"""Lab doğrulaması (ML-4): CIC üzerinde eğitilen model ve kurallar, gerçek lab trafiğinde nasıl çalışıyor?

    python lab_eval.py ../lab/data/conn.log ../lab/data/runs.jsonl --train data/windows_lycos.csv

Neden önemli: ML-3'teki bütün sayılar CIC-IDS2017'den geldi (modelin eğitildiği veri ailesi). Burada model
HİÇ görmediği, kendi ağımızdan, gerçek nmap ve Hydra ile üretilmiş trafiğe bakar. Etiketin tek kaynağı
koşu günlüğüdür (lab/label_windows.py ile aynı kural); modelin ve kuralların kararı etiket sayılmaz.

Model: LycoS verisinin eğitim bölmesinde (ML-3 ile aynı sabit parametreler) eğitilir; lab verisinde
hiçbir şey ayarlanmaz. Kurallar iki biçimde ölçülür:
  - ssh.log ile (lab'da canlıda böyle çalışır: başarısız parola sayısı bilinir),
  - ssh.log OLMADAN (CIC'teki koşullarla aynı; model ile adil kıyas bu).

Dışarıda kalanlar: koşu aralığıyla örtüşmeyen (`unknown`) ve koşu başında/sonunda yarım kalan ya da iki
koşunun örtüştüğü (`boundary`) pencereler metriklere girmez; sayıları ayrıca yazılır.

Uyarı: lab örneği küçüktür (birkaç koşu). Sonuç bir işarettir, kesin bir ölçüm değil; raporda böyle yazılmalı.
"""

import argparse
import json
import sys
import time
from collections import defaultdict
from pathlib import Path

import _sensor  # noqa: F401

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "lab"))
sys.path.insert(0, str(HERE.parent / "lab" / "common"))

from dataset import CLASSES, assign_split, feature_matrix, load_windows  # noqa: E402
from features import WINDOW_SECONDS, extract  # noqa: E402
from label_windows import label_row  # noqa: E402
from metrics import evaluate, format_report  # noqa: E402
from rules import detect  # noqa: E402
from runlog import read_runs  # noqa: E402
from zeek_reader import read_log  # noqa: E402


def rule_calls(rows, use_ssh=True):
    """{(src_ip, window_start): sınıf}. Kurallar durumlu: tüm pencereler zamana göre verilir."""
    ordered = sorted(rows, key=lambda r: (r["window_start"], r["src_ip"]))
    fed = ordered if use_ssh else [dict(r, ssh_failed_auth=0) for r in ordered]
    return {(d.src_ip, d.window_start): d.attack_type for d in detect(fed)}


def label_rows(rows, runs, window=WINDOW_SECONDS):
    """Her satıra run_id, label, boundary ekler (lab/label_windows.py ile aynı kural). `cls` yalnızca üç sınıfta."""
    out = []
    for r in rows:
        run_id, label, boundary = label_row(r, runs, window)
        out.append(dict(r, run_id=run_id, label=label, boundary=int(boundary),
                        cls=label if label in CLASSES else None))
    return out


def model_calls(model, rows):
    """Modelin her pencere için tahmini: {(src_ip, window_start): sınıf}."""
    if not rows:
        return {}
    proba = model.predict_proba(feature_matrix([dict(r, cls=None) for r in rows])[0])
    return {(r["src_ip"], r["window_start"]): CLASSES[int(p.argmax())] for r, p in zip(rows, proba)}


def evaluate_lab(rows, calls):
    """`calls`: {ad: {(ip, pencere): sınıf}}. Yalnızca koşusu bilinen, yarım olmayan pencerelerde ölçer."""
    scored = [r for r in rows if r["cls"] and not r["boundary"]]
    y_true = [r["cls"] for r in scored]
    out = {}
    for name, c in calls.items():
        y_pred = [c.get((r["src_ip"], r["window_start"]), "normal") for r in scored]
        res = evaluate(y_true, y_pred, CLASSES)
        # Lab'da bir sınıf hiç ölçülmemiş olabilir (destek 0); onun 0'ı ortalamayı sahte düşürür.
        present = [c for c in CLASSES if res["per_class"][c]["support"] > 0]
        res["macro_f1"] = sum(res["per_class"][c]["f1"] for c in present) / len(present) if present else 0.0
        out[name] = res
    return out


def per_run(rows, calls):
    """Koşu başına: etiket, pencere sayısı, yarım pencere sayısı ve her yöntemin doğru sınıfı bulduğu pencere sayısı."""
    groups = defaultdict(list)
    for r in rows:
        if r["run_id"]:
            groups[r["run_id"]].append(r)
    table = []
    for run_id, members in sorted(groups.items(), key=lambda kv: min(m["window_start"] for m in kv[1])):
        whole = [m for m in members if not m["boundary"]]
        entry = {"run_id": run_id, "label": members[0]["label"], "windows": len(whole),
                 "boundary": len(members) - len(whole), "hit": {}}
        for name, c in calls.items():
            entry["hit"][name] = sum(1 for m in whole
                                     if c.get((m["src_ip"], m["window_start"]), "normal") == m["label"])
        table.append(entry)
    return table


def outside_runs(rows, calls):
    """Hiçbir koşuyla eşleşmeyen (`unknown`) pencereler ve yöntemlerin bunlara verdiği alarmlar."""
    unknown = [r for r in rows if r["label"] == "unknown"]
    return {"windows": len(unknown),
            "alarms": {name: sum(1 for r in unknown if c.get((r["src_ip"], r["window_start"]), "normal") != "normal")
                       for name, c in calls.items()}}


NAMES = {"xgb": "XGBoost", "rules_ssh": "Kurallar (ssh.log ile)", "rules_nossh": "Kurallar (ssh.log yok)"}


def format_lab(rows, results, runs_table, outside):
    scored = [r for r in rows if r["cls"] and not r["boundary"]]
    lines = [f"toplam pencere {len(rows)}; ölçülen {len(scored)}; yarım (boundary) {sum(1 for r in rows if r['boundary'] and r['cls'])}; "
             f"koşu dışı (unknown) {outside['windows']}",
             "makro-F1 yalnızca lab'da örneği olan sınıflar üzerinden hesaplanır.", ""]
    for key, res in results.items():
        lines += [f"=== {NAMES[key]} ===", format_report(res, CLASSES), ""]
    lines.append("koşu başına (doğru sınıfı bulunan pencere / ölçülen pencere):")
    for t in runs_table:
        cells = "  ".join(f"{NAMES[k]}: {t['hit'][k]}/{t['windows']}" for k in results)
        lines.append(f"  {t['run_id']}  {t['label']:12} {cells}  (yarım {t['boundary']})")
    lines.append("")
    lines.append("koşu dışı pencerelerde verilen alarm: " + ", ".join(f"{NAMES[k]} {v}" for k, v in outside["alarms"].items()))
    return "\n".join(lines)


def run_lab(conn_log, runs_path, train_rows, ssh_log=None):
    """Lab günlüklerini etiketler, model ve kuralları çalıştırır. Dönen sözlük yazdırmaya ve panele yeter."""
    from train_xgb import train  # xgboost gerekir

    ssh_path = Path(ssh_log) if ssh_log else Path(conn_log).with_name("ssh.log")
    ssh_records = list(read_log(ssh_path)) if ssh_path.exists() else []
    runs = read_runs(runs_path)
    rows = label_rows(extract(read_log(conn_log), ssh_records=ssh_records), runs)
    model = train(train_rows)
    calls = {"xgb": model_calls(model, rows), "rules_ssh": rule_calls(rows, True), "rules_nossh": rule_calls(rows, False)}
    if not ssh_records:
        calls.pop("rules_ssh")  # ssh.log yoksa iki kural varyantı aynıdır
    return {"rows": rows, "runs": runs, "ssh_records": len(ssh_records), "results": evaluate_lab(rows, calls),
            "per_run": per_run(rows, calls), "outside": outside_runs(rows, calls)}


def panel_summary(lab):
    """Panelin gösterdiği küçük özet: yöntem başına, sınıf başına (doğru, ölçülen) pencere sayısı."""
    methods = []
    for key, res in lab["results"].items():
        methods.append({"name": NAMES[key], "hits": {c: [res["matrix"][c][c], res["per_class"][c]["support"]]
                                                      for c in CLASSES}})
    support = {c: next(iter(lab["results"].values()))["per_class"][c]["support"] for c in CLASSES}
    start = min(r["start"] for r in lab["runs"])
    return {"date": time.strftime("%Y-%m-%d", time.localtime(start)),
            "runs": len(lab["runs"]), "windows": sum(support.values()), "support": support,
            "unmeasured_boundary": sum(1 for r in lab["rows"] if r["cls"] and r["boundary"]),
            "ssh_log": lab["ssh_records"] > 0, "methods": methods}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("conn_log")
    ap.add_argument("runs")
    ap.add_argument("--train", required=True, help="LycoS pencere CSV'si (ml/data/windows_lycos.csv)")
    ap.add_argument("--ssh-log", help="Zeek ssh.log (varsayılan: conn.log'un yanındaki, varsa)")
    ap.add_argument("--json", help="sonucu bu JSON dosyasına yaz")
    args = ap.parse_args(argv)

    train_rows = [r for r in assign_split(load_windows(args.train)) if r["split"] == "train"]
    lab = run_lab(args.conn_log, args.runs, train_rows, args.ssh_log)
    print(f"ssh.log: {'var, ' + str(lab['ssh_records']) + ' kayıt' if lab['ssh_records'] else 'yok'}\n")
    print(format_lab(lab["rows"], lab["results"], lab["per_run"], lab["outside"]))
    if args.json:
        Path(args.json).write_text(json.dumps({"results": lab["results"], "runs": lab["per_run"],
                                               "outside": lab["outside"]}, ensure_ascii=False, indent=1),
                                   encoding="utf-8")
        print("\nyazıldı:", args.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
