"""Koşu günlüğü: her saldırı ya da normal trafik koşusunu tek satırlık JSON (JSONL) olarak kaydeder.

Etiketin TEK kaynağı bu günlüktür. Sensörün kendi kararı etiket sayılmaz; aksi halde ölçüm kendi
çıktısını doğrulamaya döner. Konteynerler ana makinenin saatini paylaştığı için buradaki zamanlar
Zeek'in `ts` alanıyla aynı saati kullanır.

Satır alanları: run_id, label (port_scan | brute_force | normal), scenario, src_ip, dst_ip,
params, start, end (Unix zamanı), exit_code.
"""

import json
import os
import time
import uuid
from contextlib import contextmanager

REQUIRED = ("run_id", "label", "scenario", "src_ip", "dst_ip", "start", "end")


def new_run_id(now=None):
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime(time.time() if now is None else now))
    return f"{stamp}-{uuid.uuid4().hex[:6]}"


def append_record(path, record):
    """Tek `write` ile satır ekler; aynı dosyaya iki koşu yazsa bile satırlar birbirine karışmaz."""
    line = json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n"
    folder = os.path.dirname(path)
    if folder:
        os.makedirs(folder, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
    try:
        os.write(fd, line.encode("utf-8"))
    finally:
        os.close(fd)


@contextmanager
def logged_run(path, label, scenario, src_ip, dst_ip, params=None, clock=time.time):
    """Koşuyu kaydeder. Gövde `run["exit_code"]` değerini atar; hata ya da kesintide -1 yazılır.

    Kayıt koşu BİTİNCE (hata olsa da) yazılır; yarım kalan koşu da günlükte görünür.
    """
    run = {
        "run_id": new_run_id(),
        "label": label,
        "scenario": scenario,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "params": params or {},
        "start": clock(),
        "end": None,
        "exit_code": None,
    }
    try:
        yield run
    except BaseException:
        if run["exit_code"] is None:
            run["exit_code"] = -1
        raise
    finally:
        run["end"] = clock()
        append_record(path, run)


def read_runs(path):
    """Günlüğü okur; bozuk ya da eksik alanlı satırda satır numarasıyla ValueError verir."""
    runs = []
    with open(path, encoding="utf-8") as fh:
        for no, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{no}: geçersiz JSON ({exc.msg})") from exc
            if not isinstance(rec, dict):
                raise ValueError(f"{path}:{no}: satır bir JSON nesnesi olmalı")
            missing = [k for k in REQUIRED if k not in rec or rec[k] is None]
            if missing:
                raise ValueError(f"{path}:{no}: eksik alan: {', '.join(missing)}")
            if not isinstance(rec["start"], (int, float)) or not isinstance(rec["end"], (int, float)):
                raise ValueError(f"{path}:{no}: start ve end sayı olmalı")
            if rec["end"] < rec["start"]:
                raise ValueError(f"{path}:{no}: end, start'tan önce")
            runs.append(rec)
    return runs
