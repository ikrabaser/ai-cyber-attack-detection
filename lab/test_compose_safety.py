"""Lab güvenlik değişmezleri: compose dosyası bozulursa test düşer (yalnızca standart kütüphane)."""

import re
import unittest
from pathlib import Path

COMPOSE = (Path(__file__).resolve().parent / "docker-compose.lab.yml").read_text(encoding="utf-8")
CODE = "\n".join(line for line in COMPOSE.splitlines() if not line.lstrip().startswith("#"))


class ComposeSafetyTests(unittest.TestCase):
    def test_lab_network_is_internal(self):
        self.assertRegex(CODE, r"labnet:\n\s+internal: true")

    def test_no_service_publishes_ports(self):
        self.assertNotRegex(CODE, r"(?m)^\s*ports:")

    def test_no_host_or_default_network_modes(self):
        modes = re.findall(r"network_mode:\s*\"?([^\"\n]+)\"?", CODE)
        self.assertEqual(modes, ["service:target"])  # yalnızca Zeek, hedefin ağını paylaşır
        self.assertNotIn("privileged", CODE)
        self.assertNotIn("/var/run/docker.sock", CODE)

    def test_every_lab_service_address_is_in_the_lab_subnet(self):
        ips = re.findall(r"ipv4_address:\s*(\S+)", CODE)
        self.assertEqual(len(ips), 3)
        self.assertTrue(all(ip.startswith("10.77.0.") for ip in ips), ips)

    def test_only_zeek_gets_extra_capabilities(self):
        zeek = CODE.split("  zeek:")[1].split("\n  attacker:")[0]
        self.assertIn("NET_RAW", zeek)
        rest = CODE.replace(zeek, "")
        self.assertNotIn("cap_add", rest)


if __name__ == "__main__":
    unittest.main()
