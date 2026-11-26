from django.test import TestCase, override_settings

from .threat_intel import is_known_bad_ip


class ThreatIntelTests(TestCase):
    @override_settings(THREAT_INTEL_BAD_IPS=["203.0.113.7", "198.51.100.0/24"])
    def test_exact_match(self):
        self.assertTrue(is_known_bad_ip("203.0.113.7"))

    @override_settings(THREAT_INTEL_BAD_IPS=["203.0.113.7", "198.51.100.0/24"])
    def test_network_match(self):
        self.assertTrue(is_known_bad_ip("198.51.100.9"))

    @override_settings(THREAT_INTEL_BAD_IPS=["203.0.113.7"])
    def test_no_match(self):
        self.assertFalse(is_known_bad_ip("10.0.0.5"))

    @override_settings(THREAT_INTEL_BAD_IPS=[])
    def test_empty_list_never_matches(self):
        self.assertFalse(is_known_bad_ip("203.0.113.7"))

    @override_settings(THREAT_INTEL_BAD_IPS=["203.0.113.7"])
    def test_unparseable_ip_is_not_bad_fail_open(self):
        # protection.is_protected_ip tersine: bu liste bilgilendiricidir, güvenlik kararı
        # etkilemediği için ayrıştırılamayan girdi "kötü değil" sayılır (fail-open).
        self.assertFalse(is_known_bad_ip("not-an-ip"))
        self.assertFalse(is_known_bad_ip(""))

    @override_settings(THREAT_INTEL_BAD_IPS=["not-a-valid-entry", "203.0.113.7"])
    def test_bad_config_entry_is_skipped_not_fatal(self):
        # Yapılandırmada hatalı bir satır olsa bile geçerli olanlar çalışmaya devam eder.
        self.assertTrue(is_known_bad_ip("203.0.113.7"))
        self.assertFalse(is_known_bad_ip("10.0.0.1"))
