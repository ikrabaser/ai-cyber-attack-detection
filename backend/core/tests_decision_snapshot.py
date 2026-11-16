import json
from datetime import timedelta
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from . import incidents, realtime, triage
from .models import AuditLog, Event, Incident

User = get_user_model()
TOP_KEYS = {"version", "verdict", "score", "confidence", "evidence", "tactics", "incident"}


def make_incident(ip="203.0.113.7", status=Incident.Status.NEW, ago=0, count=2):
    seen = timezone.now() - timedelta(seconds=ago)
    inc = Incident.objects.create(
        source_ip=ip, status=status, risk_level="high", max_risk=0.95, attack_type="x",
        event_count=count, first_seen=seen, last_seen=seen,
    )
    Event.objects.create(source_ip=ip, attack_type="port_scan", risk_score=0.8, risk_level="high", incident=inc,
                         features={"n_conns": 40, "fail_ratio": 0.9, "n_dst_ports": 30})
    Event.objects.create(source_ip=ip, attack_type="ssh_bruteforce", risk_score=0.95, risk_level="high", incident=inc,
                         features={"note": "<script>alert(1)</script>"})
    return inc


class SnapshotTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("ops", password="x", is_staff=True)

    def test_snapshot_shape_and_no_free_text(self):
        inc = make_incident()
        snap = triage.snapshot(inc)
        self.assertEqual(set(snap), TOP_KEYS)
        self.assertEqual(snap["version"], triage.SNAPSHOT_VERSION)
        for item in snap["evidence"]:
            self.assertEqual(set(item), {"code", "weight"})
        self.assertEqual(set(snap["incident"]), {"status_before", "event_count", "max_risk", "risk_level"})
        self.assertNotIn("script", json.dumps(snap))
        self.assertNotIn("text", json.dumps(snap["evidence"]))

    def test_snapshot_matches_live_triage(self):
        inc = make_incident()
        live = triage.triage(inc, list(inc.events.all()), [])
        snap = triage.snapshot(inc)
        self.assertEqual(snap["verdict"], live["verdict"])
        self.assertEqual(snap["score"], live["score"])
        self.assertEqual({e["code"] for e in snap["evidence"]}, {e["code"] for e in live["evidence"]})

    def test_confirm_stores_snapshot_before_change(self):
        inc = make_incident(status=Incident.Status.INVESTIGATING)
        incidents.decide(inc.pk, self.user, "confirm")
        row = AuditLog.objects.get(verb="confirm_incident")
        snap = row.detail["triage"]
        self.assertEqual(snap["incident"]["status_before"], "investigating")
        self.assertEqual(row.detail["incident_id"], inc.pk)
        self.assertIn("recon_to_credential", {e["code"] for e in snap["evidence"]})

    def test_false_positive_and_resolve_store_snapshot(self):
        for decision, status in (("false_positive", "false_positive"), ("resolve", "resolved")):
            inc = make_incident()
            incidents.decide(inc.pk, self.user, decision)
            row = AuditLog.objects.filter(verb="close_incident").latest("id")
            self.assertEqual(row.outcome, status)
            self.assertEqual(set(row.detail["triage"]), TOP_KEYS)
            self.assertEqual(row.detail["triage"]["incident"]["status_before"], "new")
            inc.delete()

    def test_confirmed_then_resolved_records_both_decisions(self):
        inc = make_incident()
        incidents.decide(inc.pk, self.user, "confirm")
        incidents.decide(inc.pk, self.user, "resolve")
        confirm = AuditLog.objects.get(verb="confirm_incident").detail["triage"]
        close = AuditLog.objects.get(verb="close_incident").detail["triage"]
        self.assertEqual(confirm["incident"]["status_before"], "new")
        self.assertEqual(close["incident"]["status_before"], "confirmed")

    def test_idle_close_has_no_snapshot(self):
        inc = make_incident(ago=100000)
        incidents.close_idle()
        row = AuditLog.objects.get(verb="close_incident")
        self.assertEqual(row.actor, "system:idle")
        self.assertNotIn("triage", row.detail)

    def test_rejected_decision_writes_nothing(self):
        inc = make_incident(status=Incident.Status.RESOLVED)
        with self.assertRaises(incidents.DecisionError):
            incidents.decide(inc.pk, self.user, "confirm")
        self.assertFalse(AuditLog.objects.filter(verb__in=["confirm_incident", "close_incident"]).exists())

    def test_snapshot_never_reaches_the_live_feed(self):
        inc = make_incident()
        with mock.patch("core.realtime.publish") as pub:
            with self.captureOnCommitCallbacks(execute=True):
                incidents.decide(inc.pk, self.user, "confirm")
        for call in pub.call_args_list:
            self.assertNotIn("triage", json.dumps(call.args[1]))
        entry = AuditLog.objects.get(verb="confirm_incident")
        self.assertNotIn("triage", realtime.pipeline_payload(entry))
