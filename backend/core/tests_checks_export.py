import csv
import io
import json
import os
import tempfile
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone

from . import checks, incidents
from .models import Event, Incident

User = get_user_model()
STRONG = "x7Qm2vL9pR4tZ8wK1nB6cD3fG5hJ0sAa"


class SecretChecksTests(SimpleTestCase):
    def issues(self, **overrides):
        base = dict(SENSOR_API_TOKEN=STRONG, RT_PROXY_SECRET=STRONG, RT_API_KEY=STRONG, SECRET_KEY=STRONG)
        base.update(overrides)
        with override_settings(**base):
            return checks.check_secrets(None)

    @override_settings(SECRETS_STRICT=False)
    def test_strong_secrets_are_clean(self):
        self.assertEqual(self.issues(), [])

    @override_settings(SECRETS_STRICT=False)
    def test_empty_secret_is_not_flagged(self):
        self.assertEqual(self.issues(SENSOR_API_TOKEN=""), [])

    @override_settings(SECRETS_STRICT=False)
    def test_placeholder_warns_when_not_strict(self):
        out = self.issues(SENSOR_API_TOKEN="degistir-beni-sensor-tokeni")
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].level, 30)  # WARNING
        self.assertEqual(out[0].id, "core.W001")
        self.assertIn("SENSOR_API_TOKEN", out[0].msg)

    @override_settings(SECRETS_STRICT=True)
    def test_placeholder_is_error_when_strict(self):
        out = self.issues(RT_PROXY_SECRET="Degistir-Beni-proxy-sirri-xx")
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].level, 40)  # ERROR
        self.assertEqual(out[0].id, "core.E001")

    @override_settings(SECRETS_STRICT=False)
    def test_short_secret_is_flagged(self):
        out = self.issues(RT_API_KEY="abc123")
        self.assertEqual(len(out), 1)
        self.assertIn("kısa", out[0].msg)

    @override_settings(SECRETS_STRICT=False)
    def test_django_secret_key_uses_env_name_in_message(self):
        out = self.issues(SECRET_KEY="degistir-beni-uzun-rastgele-bir-deger")
        self.assertIn("DJANGO_SECRET_KEY", out[0].msg)

    @override_settings(SECRETS_STRICT=False)
    def test_message_never_contains_the_secret(self):
        secret = "degistir-beni-gizli-ama-ornek"
        out = self.issues(SENSOR_API_TOKEN=secret)
        text = out[0].msg + out[0].hint
        self.assertNotIn(secret, text)

    @override_settings(SECRETS_STRICT=False)
    def test_several_problems_give_several_issues(self):
        out = self.issues(SENSOR_API_TOKEN="degistir-beni-x", RT_API_KEY="kisa")
        self.assertEqual(len(out), 2)


def make_incident(ip, events=(("port_scan", {"n_conns": 40, "fail_ratio": 0.9}), ("ssh_bruteforce", {}))):
    now = timezone.now()
    inc = Incident.objects.create(source_ip=ip, status=Incident.Status.NEW, risk_level="high", max_risk=0.9,
                                  attack_type="x", event_count=len(events), first_seen=now, last_seen=now)
    for attack, feats in events:
        Event.objects.create(source_ip=ip, attack_type=attack, risk_score=0.9, risk_level="high", incident=inc,
                             features=feats)
    return inc


class ExportDecisionsTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("ops", password="x", is_staff=True)

    def export(self, *args):
        out = io.StringIO()
        call_command("export_decisions", *args, stdout=out)
        return out.getvalue()

    def rows(self, *args):
        return [json.loads(line) for line in self.export(*args).splitlines()]

    def test_confirm_and_false_positive_are_labeled(self):
        a = make_incident("203.0.113.1")
        b = make_incident("203.0.113.2")
        incidents.decide(a.pk, self.user, "confirm")
        incidents.decide(b.pk, self.user, "false_positive")
        rows = {r["incident_id"]: r for r in self.rows()}
        self.assertEqual(rows[a.pk]["label"], "attack")
        self.assertEqual(rows[b.pk]["label"], "false_positive")
        self.assertIn("recon_to_credential", rows[a.pk]["evidence"])
        self.assertEqual(rows[a.pk]["status_before"], "new")

    def test_resolve_alone_is_not_a_label_unless_asked(self):
        inc = make_incident("203.0.113.3")
        incidents.decide(inc.pk, self.user, "resolve")
        self.assertEqual(self.rows(), [])
        rows = self.rows("--include-unlabeled")
        self.assertEqual([r["label"] for r in rows], ["unlabeled"])

    def test_resolve_after_confirm_keeps_attack_label(self):
        inc = make_incident("203.0.113.4")
        incidents.decide(inc.pk, self.user, "confirm")
        incidents.decide(inc.pk, self.user, "resolve")
        for args in ((), ("--include-unlabeled",)):
            rows = self.rows(*args)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["label"], "attack")

    def test_latest_labeled_decision_wins(self):
        inc = make_incident("203.0.113.5")
        incidents.decide(inc.pk, self.user, "confirm")
        incidents.decide(inc.pk, self.user, "false_positive")
        rows = self.rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["label"], "false_positive")
        self.assertEqual(rows[0]["status_before"], "confirmed")

    def test_idle_close_is_not_exported(self):
        inc = make_incident("203.0.113.6")
        Incident.objects.filter(pk=inc.pk).update(last_seen=timezone.now() - timedelta(days=2))
        incidents.close_idle()
        self.assertEqual(self.rows("--include-unlabeled"), [])

    def test_no_ip_or_user_in_output(self):
        inc = make_incident("203.0.113.7")
        incidents.decide(inc.pk, self.user, "confirm")
        text = self.export()
        self.assertNotIn("203.0.113.7", text)
        self.assertNotIn(f"user:{self.user.pk}", text)

    def test_csv_has_one_hot_evidence_columns(self):
        inc = make_incident("203.0.113.8")
        incidents.decide(inc.pk, self.user, "confirm")
        reader = list(csv.DictReader(io.StringIO(self.export("--format", "csv"))))
        self.assertEqual(len(reader), 1)
        self.assertEqual(reader[0]["label"], "attack")
        self.assertEqual(reader[0]["e_recon_to_credential"], "3")

    def test_writes_file_and_reports_count(self):
        inc = make_incident("203.0.113.9")
        incidents.decide(inc.pk, self.user, "confirm")
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "out.jsonl")
            out = io.StringIO()
            call_command("export_decisions", "--out", path, stdout=out)
            self.assertIn("1 karar", out.getvalue())
            with open(path, encoding="utf-8") as fh:
                self.assertEqual(len(fh.read().splitlines()), 1)

    def test_bad_path_is_a_command_error(self):
        with self.assertRaises(CommandError):
            call_command("export_decisions", "--out", "/nonexistent-dir/x.jsonl", stdout=io.StringIO())

    def test_empty_store_exports_nothing(self):
        self.assertEqual(self.export(), "")
