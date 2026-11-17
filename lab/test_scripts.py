import os
import random
import tempfile
import unittest
from types import SimpleNamespace

import _paths  # noqa: F401
import attack
import normal_traffic
from netguard import require_private
from runlog import read_runs


class NetguardTests(unittest.TestCase):
    def test_private_addresses_pass(self):
        for ok in ("10.77.0.10", "192.168.1.5", "172.16.4.4"):
            self.assertEqual(require_private(ok), ok)

    def test_public_loopback_and_garbage_are_refused(self):
        for bad in ("8.8.8.8", "1.1.1.1", "127.0.0.1", "::1", "10.77.0.0/24", "example.com", "", "10.0.0"):
            with self.assertRaises(ValueError, msg=bad):
                require_private(bad)


class CommandTests(unittest.TestCase):
    def test_scan_command(self):
        self.assertEqual(attack.scan_command("10.77.0.10", "1-1024", 4),
                         ["nmap", "-sS", "-Pn", "-n", "-p", "1-1024", "-T4", "10.77.0.10"])

    def test_scan_rejects_bad_ports_and_timing(self):
        for ports in ("1-1024; rm -rf /", "$(id)", "", "a-b", "80,"):
            with self.assertRaises(ValueError, msg=ports):
                attack.scan_command("10.77.0.10", ports, 4)
        for timing in (-1, 6):
            with self.assertRaises(ValueError):
                attack.scan_command("10.77.0.10", "1-10", timing)

    def test_brute_command_has_no_stop_on_first_flag(self):
        cmd = attack.brute_command("10.77.0.10", threads=2)
        self.assertEqual(cmd[:7], ["hydra", "-l", "labuser", "-P", "/lab/wordlist.txt", "-t", "2"])
        self.assertNotIn("-f", cmd)
        self.assertEqual(cmd[-1], "ssh://10.77.0.10")

    def test_brute_rejects_bad_threads(self):
        for threads in (0, 17):
            with self.assertRaises(ValueError):
                attack.brute_command("10.77.0.10", threads)

    def test_ssh_command_targets_lab_user(self):
        cmd = normal_traffic.ssh_command("10.77.0.10")
        self.assertIn("labuser@10.77.0.10", cmd)
        self.assertEqual(cmd[0], "sshpass")


class AttackMainTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.log = os.path.join(self.dir.name, "runs.jsonl")
        self.base = ["--target", "10.77.0.10", "--src", "10.77.0.20", "--runlog", self.log]

    def tearDown(self):
        self.dir.cleanup()

    def run_main(self, extra, code=0):
        seen = []

        def runner(cmd):
            seen.append(cmd)
            return SimpleNamespace(returncode=code)

        rc = attack.main(self.base + extra, runner=runner)
        return rc, seen

    def test_scan_logs_a_port_scan_run(self):
        rc, seen = self.run_main(["scan", "--timing", "2"])
        self.assertEqual(rc, 0)
        self.assertEqual(seen[0][0], "nmap")
        (rec,) = read_runs(self.log)
        self.assertEqual((rec["label"], rec["scenario"], rec["exit_code"]), ("port_scan", "nmap_syn", 0))
        self.assertEqual(rec["params"]["timing"], 2)

    def test_brute_logs_a_brute_force_run_and_failure_exit(self):
        rc, _ = self.run_main(["brute"], code=3)
        self.assertEqual(rc, 1)
        (rec,) = read_runs(self.log)
        self.assertEqual((rec["label"], rec["exit_code"]), ("brute_force", 3))

    def test_public_target_is_refused_and_nothing_runs(self):
        with self.assertRaises(SystemExit):
            attack.main(["--target", "8.8.8.8", "--src", "10.77.0.20", "--runlog", self.log, "scan"],
                        runner=lambda cmd: self.fail("çalışmamalı"))
        self.assertFalse(os.path.exists(self.log))


class NormalTrafficTests(unittest.TestCase):
    def test_choose_action_share(self):
        rng = random.Random(1)
        picks = [normal_traffic.choose_action(rng) for _ in range(2000)]
        share = picks.count("ssh") / len(picks)
        self.assertTrue(0.15 < share < 0.25, share)

    def test_run_traffic_counts_and_survives_errors(self):
        now = [0.0]

        def clock():
            return now[0]

        def sleep(sec):
            now[0] += 1.0  # her istekten sonra bir saniye geçti say

        def bad_ssh(target):
            raise RuntimeError("ssh başarısız")

        counts = normal_traffic.run_traffic("10.77.0.10", 50, 1.0, random.Random(3), sleep=sleep, clock=clock,
                                            actions={"http": lambda t: None, "ssh": bad_ssh})
        self.assertEqual(counts["http_ok"] + counts["ssh_fail"], 50)
        self.assertEqual((counts["http_fail"], counts["ssh_ok"]), (0, 0))
        self.assertGreater(counts["ssh_fail"], 0)

    def test_main_rejects_public_target(self):
        with self.assertRaises(SystemExit):
            normal_traffic.main(["--target", "93.184.216.34", "--src", "10.77.0.30", "--seconds", "1"])


if __name__ == "__main__":
    unittest.main()
