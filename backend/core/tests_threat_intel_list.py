from io import StringIO
from unittest import mock

from django.core.management import call_command
from django.test import TestCase

from .threat_intel_list import normalize_list, split_tokens


class SplitTokensTests(TestCase):
    def test_splits_on_commas_newlines_and_spaces(self):
        text = "203.0.113.7, 203.0.113.8\n198.51.100.0/24   10.0.0.1"
        self.assertEqual(
            split_tokens(text),
            ["203.0.113.7", "203.0.113.8", "198.51.100.0/24", "10.0.0.1"],
        )

    def test_empty_text_gives_no_tokens(self):
        self.assertEqual(split_tokens("   \n\n  "), [])


class NormalizeListTests(TestCase):
    def test_valid_ip_and_cidr_pass_through(self):
        valid, invalid = normalize_list(["203.0.113.7", "198.51.100.0/24"])
        self.assertEqual(valid, ["203.0.113.7", "198.51.100.0/24"])
        self.assertEqual(invalid, [])

    def test_cidr_with_host_bits_set_is_normalized_to_network_address(self):
        valid, invalid = normalize_list(["198.51.100.5/24"])
        self.assertEqual(valid, ["198.51.100.0/24"])
        self.assertEqual(invalid, [])

    def test_invalid_entries_are_reported_separately(self):
        valid, invalid = normalize_list(["not-an-ip", "203.0.113.7"])
        self.assertEqual(valid, ["203.0.113.7"])
        self.assertEqual(invalid, ["not-an-ip"])

    def test_blank_and_comment_lines_are_silently_skipped(self):
        valid, invalid = normalize_list(["", "   ", "# yorum satırı", "203.0.113.7"])
        self.assertEqual(valid, ["203.0.113.7"])
        self.assertEqual(invalid, [])

    def test_duplicates_are_removed_keeping_first_seen_order(self):
        valid, invalid = normalize_list(["203.0.113.7", "203.0.113.8", "203.0.113.7"])
        self.assertEqual(valid, ["203.0.113.7", "203.0.113.8"])
        self.assertEqual(invalid, [])

    def test_order_is_preserved_not_sorted(self):
        valid, invalid = normalize_list(["203.0.113.8", "203.0.113.7"])
        self.assertEqual(valid, ["203.0.113.8", "203.0.113.7"])

    def test_ipv6_address_is_accepted_and_normalized(self):
        valid, invalid = normalize_list(["2001:0db8:0000:0000:0000:0000:0000:0001"])
        self.assertEqual(valid, ["2001:db8::1"])


class NormalizeThreatIntelIpsCommandTests(TestCase):
    def test_positional_entries_produce_env_line(self):
        out = StringIO()
        call_command(
            "normalize_threat_intel_ips",
            "203.0.113.7,198.51.100.0/24",
            stdout=out,
        )
        self.assertEqual(out.getvalue().strip(), "THREAT_INTEL_BAD_IPS=203.0.113.7,198.51.100.0/24")

    def test_invalid_entries_reported_as_warnings_and_excluded(self):
        out, err = StringIO(), StringIO()
        call_command(
            "normalize_threat_intel_ips",
            "203.0.113.7,not-an-ip",
            stdout=out,
            stderr=err,
        )
        self.assertEqual(out.getvalue().strip(), "THREAT_INTEL_BAD_IPS=203.0.113.7")
        self.assertIn("not-an-ip", err.getvalue())

    def test_no_valid_entries_prints_warning_and_no_env_line(self):
        out = StringIO()
        call_command("normalize_threat_intel_ips", "not-an-ip", stdout=out)
        self.assertNotIn("THREAT_INTEL_BAD_IPS", out.getvalue())

    def test_reads_from_stdin_when_no_entries_given(self):
        out = StringIO()
        with mock.patch("sys.stdin", StringIO("203.0.113.7\n203.0.113.8\n")):
            call_command("normalize_threat_intel_ips", stdout=out)
        self.assertEqual(out.getvalue().strip(), "THREAT_INTEL_BAD_IPS=203.0.113.7,203.0.113.8")
