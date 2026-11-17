"""Saldırgan konteynerde çalışır: nmap ya da Hydra ile bir koşu yapar ve koşu günlüğüne yazar.

    python3 /lab/attack.py scan                 # nmap SYN taraması
    python3 /lab/attack.py scan --timing 2      # daha yavaş tarama
    python3 /lab/attack.py brute                # Hydra ile SSH parola denemesi
    python3 /lab/attack.py brute --threads 1

Hedef, kaynak adres ve günlük yolu ortam değişkenlerinden gelir (LAB_TARGET_IP, LAB_SRC_IP, LAB_RUNLOG).
"""

import argparse
import os
import re
import subprocess
import sys

from netguard import require_private
from runlog import logged_run

PORTS_RE = re.compile(r"^[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*$")
WORDLIST = "/lab/wordlist.txt"
SSH_USER = "labuser"


def scan_command(target, ports="1-1024", timing=4):
    if not PORTS_RE.match(ports):
        raise ValueError(f"geçersiz port listesi: {ports!r}")
    if not 0 <= timing <= 5:
        raise ValueError("timing 0 ile 5 arasında olmalı")
    return ["nmap", "-sS", "-Pn", "-n", "-p", ports, f"-T{timing}", target]


def brute_command(target, threads=4, user=SSH_USER, wordlist=WORDLIST):
    if not 1 <= threads <= 16:
        raise ValueError("threads 1 ile 16 arasında olmalı")
    # -I: önceki oturumu sürdürme sorusunu atla. -f verilmez: parola bulunsa da liste bitene kadar denenir,
    # böylece koşu süresi sabit kalır ve kaç pencere ürettiği karşılaştırılabilir.
    return ["hydra", "-l", user, "-P", wordlist, "-t", str(threads), "-I", f"ssh://{target}"]


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default=os.environ.get("LAB_TARGET_IP", ""), help="hedef IP (LAB_TARGET_IP)")
    parser.add_argument("--src", default=os.environ.get("LAB_SRC_IP", ""), help="bu konteynerin IP'si (LAB_SRC_IP)")
    parser.add_argument("--runlog", default=os.environ.get("LAB_RUNLOG", "/runs/runs.jsonl"), help="koşu günlüğü yolu")
    sub = parser.add_subparsers(dest="kind", required=True)
    scan = sub.add_parser("scan", help="nmap SYN taraması")
    scan.add_argument("--ports", default="1-1024")
    scan.add_argument("--timing", type=int, default=4, help="nmap -T değeri (0 en yavaş, 5 en hızlı)")
    brute = sub.add_parser("brute", help="Hydra ile SSH parola denemesi")
    brute.add_argument("--threads", type=int, default=4)
    return parser


def main(argv=None, runner=subprocess.run):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        target = require_private(args.target)
        src = require_private(args.src)
        if args.kind == "scan":
            cmd = scan_command(target, args.ports, args.timing)
            label, scenario = "port_scan", "nmap_syn"
            params = {"ports": args.ports, "timing": args.timing}
        else:
            cmd = brute_command(target, args.threads)
            label, scenario = "brute_force", "hydra_ssh"
            params = {"threads": args.threads, "service": "ssh"}
    except ValueError as exc:
        parser.error(str(exc))
    print("+", " ".join(cmd), flush=True)
    with logged_run(args.runlog, label, scenario, src, target, params) as run:
        run["exit_code"] = runner(cmd).returncode
    print(f"koşu kaydedildi: {run['run_id']} ({run['end'] - run['start']:.1f} sn, çıkış {run['exit_code']})")
    return 0 if run["exit_code"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
