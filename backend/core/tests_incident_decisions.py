import json
from datetime import timedelta
from unittest import mock

from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.test import TestCase
from django.utils import timezone

from . import incidents, realtime
from .models import AuditLog, Incident

User = get_user_model()
SECRET = {"HTTP_X_CENTRIFUGO_PROXY_SECRET": "test-proxy-secret"}


def make_incident(status=Incident.Status.NEW, ip="203.0.113.7", ago=0):
    seen = timezone.now() - timedelta(seconds=ago)
    return Incident.objects.create(
        source_ip=ip, status=status, risk_level="high", max_risk=0.9, attack_type="brute_force",
        event_count=1, first_seen=seen, last_seen=seen,
    )


class DecideTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("ops", password="x", is_staff=True)
        self.actor = f"user:{self.user.pk}"

    def test_confirm_from_new_and_investigating(self):
        for status in (Incident.Status.NEW, Incident.Status.INVESTIGATING):
            inc = make_incident(status)
            out = incidents.decide(inc.pk, self.user, "confirm")
            inc.refresh_from_db()
            self.assertEqual(out.status, Incident.Status.CONFIRMED)
            self.assertEqual(inc.status, Incident.Status.CONFIRMED)
            self.assertEqual(inc.decided_by, self.actor)
            self.assertIsNotNone(inc.decided_at)
            self.assertIsNone(inc.closed_at)  # onay kapatmaz
            Incident.objects.all().delete()

    def test_confirm_audit_row(self):
        inc = make_incident()
        incidents.decide(inc.pk, self.user, "confirm")
        row = AuditLog.objects.get(verb="confirm_incident")
        self.assertEqual((row.actor, row.target, row.outcome), (self.actor, "203.0.113.7", "confirmed"))
        self.assertEqual(row.detail.get("incident_id"), inc.pk)

    def test_confirmed_can_be_resolved_and_keeps_open_slot_until_then(self):
        inc = make_incident()
        incidents.decide(inc.pk, self.user, "confirm")
        # Onaylı incident hâlâ açık: aynı IP için yeni açılamaz.
        with self.assertRaises(IntegrityError), transaction.atomic():
            Incident.objects.create(
                source_ip=inc.source_ip, status=Incident.Status.NEW, risk_level="low", max_risk=0.1,
                attack_type="x", event_count=1, first_seen=timezone.now(), last_seen=timezone.now())
        incidents.decide(inc.pk, self.user, "resolve")
        inc.refresh_from_db()
        self.assertEqual(inc.status, Incident.Status.RESOLVED)
        self.assertIsNotNone(inc.closed_at)

    def test_false_positive_and_resolve_close(self):
        for decision, status in (("false_positive", Incident.Status.FALSE_POSITIVE), ("resolve", Incident.Status.RESOLVED)):
            inc = make_incident()
            incidents.decide(inc.pk, self.user, decision)
            inc.refresh_from_db()
            self.assertEqual(inc.status, status)
            self.assertIsNotNone(inc.closed_at)
            self.assertEqual(inc.decided_by, self.actor)
            row = AuditLog.objects.filter(verb="close_incident").latest("id")
            self.assertEqual((row.actor, row.outcome), (self.actor, status))
            inc.delete()

    def test_closed_incident_rejects_every_decision(self):
        for status in (Incident.Status.RESOLVED, Incident.Status.FALSE_POSITIVE):
            inc = make_incident(status)
            for decision in incidents.DECISIONS:
                with self.assertRaises(incidents.DecisionError) as cm:
                    incidents.decide(inc.pk, self.user, decision)
                self.assertEqual(cm.exception.code, 409)
            inc.delete()

    def test_double_confirm_conflicts(self):
        inc = make_incident()
        incidents.decide(inc.pk, self.user, "confirm")
        with self.assertRaises(incidents.DecisionError) as cm:
            incidents.decide(inc.pk, self.user, "confirm")
        self.assertEqual(cm.exception.code, 409)
        self.assertEqual(AuditLog.objects.filter(verb="confirm_incident").count(), 1)

    def test_missing_incident_and_unknown_decision(self):
        with self.assertRaises(incidents.DecisionError) as cm:
            incidents.decide(999999, self.user, "confirm")
        self.assertEqual(cm.exception.code, 404)
        inc = make_incident()
        with self.assertRaises(ValueError):
            incidents.decide(inc.pk, self.user, "delete")
        inc.refresh_from_db()
        self.assertEqual(inc.status, Incident.Status.NEW)

    def test_idle_close_keeps_human_decider(self):
        inc = make_incident(ago=100000)
        incidents.decide(inc.pk, self.user, "confirm")
        incidents.close_idle()
        inc.refresh_from_db()
        self.assertEqual(inc.status, Incident.Status.RESOLVED)
        self.assertEqual(inc.decided_by, self.actor)

    def test_idle_close_of_undecided_is_system(self):
        inc = make_incident(ago=100000)
        incidents.close_idle()
        inc.refresh_from_db()
        self.assertEqual(inc.decided_by, "system:idle")

    def test_publishes_after_commit(self):
        inc = make_incident()
        with mock.patch("core.realtime.publish") as pub:
            with self.captureOnCommitCallbacks(execute=True):
                incidents.decide(inc.pk, self.user, "false_positive")
        sent = [c.args for c in pub.call_args_list if c.args[0] == realtime.CHANNEL_INCIDENTS]
        self.assertEqual(len(sent), 1)
        self.assertEqual(sent[0][1]["status"], "false_positive")

    def test_no_publish_before_commit(self):
        inc = make_incident()
        with mock.patch("core.realtime.publish") as pub:
            incidents.decide(inc.pk, self.user, "confirm")
        pub.assert_not_called()


class DecisionRpcTests(TestCase):
    def setUp(self):
        self.staff = User.objects.create_user("ops", password="x", is_staff=True)
        self.plain = User.objects.create_user("guest", password="x")

    def rpc(self, method, data, user=None, secret=True):
        body = {"user": str((user or self.staff).pk), "method": method, "data": data}
        extra = SECRET if secret else {}
        return self.client.post("/centrifugo/rpc/", json.dumps(body), content_type="application/json", **extra)

    def test_each_method(self):
        cases = (
            ("ids:confirm_incident", "confirmed"),
            ("ids:false_positive_incident", "false_positive"),
            ("ids:resolve_incident", "resolved"),
        )
        for method, status in cases:
            inc = make_incident()
            out = self.rpc(method, {"incident_id": inc.pk}).json()
            self.assertEqual(out, {"result": {"data": {"incident_id": inc.pk, "status": status}}})
            inc.delete()

    def test_non_staff_denied_and_nothing_changes(self):
        inc = make_incident()
        out = self.rpc("ids:confirm_incident", {"incident_id": inc.pk}, user=self.plain).json()
        self.assertEqual(out["error"]["code"], 403)
        inc.refresh_from_db()
        self.assertEqual(inc.status, Incident.Status.NEW)
        self.assertFalse(AuditLog.objects.filter(verb="confirm_incident").exists())

    def test_proxy_secret_required(self):
        inc = make_incident()
        resp = self.rpc("ids:confirm_incident", {"incident_id": inc.pk}, secret=False)
        self.assertEqual(resp.status_code, 403)
        inc.refresh_from_db()
        self.assertEqual(inc.status, Incident.Status.NEW)

    def test_bad_ids_are_400(self):
        for bad in (None, "", "abc", "-1", "1.5", "9" * 30, True, [1]):
            out = self.rpc("ids:resolve_incident", {"incident_id": bad}).json()
            self.assertEqual(out["error"]["code"], 400, bad)
        self.assertEqual(self.rpc("ids:resolve_incident", {}).json()["error"]["code"], 400)

    def test_missing_and_closed(self):
        self.assertEqual(self.rpc("ids:confirm_incident", {"incident_id": 424242}).json()["error"]["code"], 404)
        inc = make_incident(Incident.Status.RESOLVED)
        self.assertEqual(self.rpc("ids:confirm_incident", {"incident_id": inc.pk}).json()["error"]["code"], 409)

    def test_action_rpc_still_works_and_actions_untouched(self):
        # Incident kararı bekleyen eylemlere dokunmaz.
        from . import actions
        from .models import Action, Event
        inc = make_incident()
        ev = Event.objects.create(source_ip=inc.source_ip, attack_type="brute_force", risk_score=0.9,
                                  risk_level="high", incident=inc)
        action = actions.propose_action(ev, "block_ip", inc.source_ip)
        self.rpc("ids:false_positive_incident", {"incident_id": inc.pk})
        action.refresh_from_db()
        self.assertEqual(action.status, Action.Status.PENDING_APPROVAL)
        out = self.rpc("ids:approve_action", {"action_id": action.pk}).json()
        self.assertEqual(out["result"]["data"]["status"], "executed")
