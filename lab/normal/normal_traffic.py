"""Normal trafik üreticisi: web istekleri ve ara sıra gerçek bir SSH girişi.

    python3 /lab/normal_traffic.py --seconds 120
    python3 /lab/normal_traffic.py --seconds 300 --mean-interval 1.5 --seed 7

Amaç yanlış alarm oranını ölçebilmektir: kurallar bu trafiğe tetiklenmemelidir.
"""

import argparse
import os
import random
import subprocess
import sys
import time
import urllib.request

from netguard import require_private
from runlog import logged_run

SSH_USER = "labuser"
SSH_PASSWORD = "lab123"  # test hedefinin bilinen parolası; yalnızca izole lab ağında


def choose_action(rng, ssh_share=0.2):
    return "ssh" if rng.random() < ssh_share else "http"


def ssh_command(target):
    return ["sshpass", "-p", SSH_PASSWORD, "ssh",
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=5", f"{SSH_USER}@{target}", "true"]


def do_http(target):
    with urllib.request.urlopen(f"http://{target}/", timeout=5) as resp:
        resp.read()


def do_ssh(target):
    done = subprocess.run(ssh_command(target), capture_output=True, timeout=15)
    if done.returncode != 0:
        raise RuntimeError("ssh başarısız")


def run_traffic(target, seconds, mean_interval, rng, sleep=time.sleep, clock=time.monotonic,
                actions=None):
    """Süre dolana kadar rastgele aralıklarla istek yapar; her türün başarı ve hata sayısını döndürür."""
    actions = actions or {"http": do_http, "ssh": do_ssh}
    counts = {"http_ok": 0, "http_fail": 0, "ssh_ok": 0, "ssh_fail": 0}
    deadline = clock() + seconds
    while clock() < deadline:
        kind = choose_action(rng)
        try:
            actions[kind](target)
            counts[f"{kind}_ok"] += 1
        except Exception:
            counts[f"{kind}_fail"] += 1
        sleep(min(rng.expovariate(1.0 / mean_interval), 3 * mean_interval))
    return counts


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default=os.environ.get("LAB_TARGET_IP", ""), help="hedef IP (LAB_TARGET_IP)")
    parser.add_argument("--src", default=os.environ.get("LAB_SRC_IP", ""), help="bu konteynerin IP'si (LAB_SRC_IP)")
    parser.add_argument("--runlog", default=os.environ.get("LAB_RUNLOG", "/runs/runs.jsonl"))
    parser.add_argument("--seconds", type=float, default=120.0, help="koşu süresi")
    parser.add_argument("--mean-interval", type=float, default=2.0, help="istekler arası ortalama bekleme (sn)")
    parser.add_argument("--seed", type=int, default=None, help="tekrarlanabilirlik için rastgelelik tohumu")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        target = require_private(args.target)
        src = require_private(args.src)
    except ValueError as exc:
        parser.error(str(exc))
    if args.seconds <= 0 or args.mean_interval <= 0:
        parser.error("seconds ve mean-interval sıfırdan büyük olmalı")
    rng = random.Random(args.seed)
    params = {"seconds": args.seconds, "mean_interval": args.mean_interval, "seed": args.seed}
    with logged_run(args.runlog, "normal", "normal_web_ssh", src, target, params) as run:
        counts = run_traffic(target, args.seconds, args.mean_interval, rng)
        run["params"].update(counts)
        run["exit_code"] = 0
    print(f"koşu kaydedildi: {run['run_id']} {counts}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
