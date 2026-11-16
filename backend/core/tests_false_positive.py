from datetime import timedelta
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from . import incident_detail, incidents
from .models import Action, AuditLog, Event, Incident
from .tasks import investigate_event

User = get_user_model()


def make_incident(ip="203.0.113.7", status=Incident.Status.NEW):
    now = timezone.now()
    return Incident.objects.create(
        source_ip=ip, status=status, risk_level="high", max_risk=0.9, attack_type="port_scan",
        event_count=0, first_seen=now, last_seen=now,
    )


def make_event(incident, status=Event.Status.NEW):
    return Event.objects.create(
        source_ip=incident.source_ip, attack_type="port_scan", risk_score=0.9, risk_level="high",
        incident=incident, status=status,
    )


class FalsePositiveEventsTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("ops", password="x", is_staff=True)

    def test_false_positive_dismisses_all_events_of_that_incident_only(self):
        inc = make_incident()
        mine = [make_event(inc, s) for s in (Event.Status.NEW, Event.Status.INVESTIGATING, Event.Status.RESOLVED)]
        other = make_event(make_incident(ip="203.0.113.8"))
        incidents.decide(inc.pk, self.user, "false_positive")
        for e in mine:
            e.refresh_from_db()
            self.assertEqual(e.status, Event.Status.DISMISSED)
        other.refresh_from_db()
        self.assertEqual(other.status, Event.Status.NEW)

    def test_audit_counts_only_events_that_changed(self):
        inc = make_incident()
        make_event(inc)
        make_event(inc, Event.Status.INVESTIGATING)
        make_event(inc, Event.Status.DISMISSED)  # zaten kapalı: sayılmaz
        incidents.decide(inc.pk, self.user, "false_positive")
        row = AuditLog.objects.get(verb="close_incident")
        self.assertEqual(row.detail["events_dismissed"], 2)
        self.assertIn("triage", row.detail)  # etiket kaydı bozulmadı

    def test_other_decisions_leave_events_alone(self):
        for decision in ("confirm", "resolve"):
            inc = make_incident()
            e = make_event(inc, Event.Status.INVESTIGATING)
            incidents.decide(inc.pk, self.user, decision)
            e.refresh_from_db()
            self.assertEqual(e.status, Event.Status.INVESTIGATING, decision)
            inc.delete()

    def test_pending_actions_are_not_touched(self):
        inc = make_incident()
        e = make_event(inc)
        a = Action.objects.create(event=e, kind="block_ip", target=inc.source_ip,
                                  status=Action.Status.PENDING_APPROVAL, requires_approval=True)
        incidents.decide(inc.pk, self.user, "false_positive")
        a.refresh_from_db()
        self.assertEqual(a.status, Action.Status.PENDING_APPROVAL)

    def test_rejected_decision_does_not_dismiss(self):
        inc = make_incident(status=Incident.Status.RESOLVED)
        e = make_event(inc)
        with self.assertRaises(incidents.DecisionError):
            incidents.decide(inc.pk, self.user, "false_positive")
        e.refresh_from_db()
        self.assertEqual(e.status, Event.Status.NEW)

    def test_worker_does_not_undo_dismissal_while_queued(self):
        inc = make_incident()
        e = make_event(inc)
        incidents.decide(inc.pk, self.user, "false_positive")
        with mock.patch("core.tasks.get_agent") as get, mock.patch("core.tasks.realtime.publish") as pub:
            get.return_value.name = "a"
            get.return_value.investigate.return_value = "özet"
            investigate_event(e.pk)
        e.refresh_from_db()
        self.assertEqual(e.status, Event.Status.DISMISSED)
        feed = [c.args[1] for c in pub.call_args_list if c.args[1].get("type") == "event"]
        self.assertEqual([p["status"] for p in feed], ["dismissed"])  # canlı akışa eski durum gitmez

    def test_worker_still_moves_new_event_to_investigating(self):
        e = make_event(make_incident())
        with mock.patch("core.tasks.get_agent") as get, mock.patch("core.tasks.realtime.publish"):
            get.return_value.name = "a"
            get.return_value.investigate.return_value = "özet"
            investigate_event(e.pk)
        e.refresh_from_db()
        self.assertEqual(e.status, Event.Status.INVESTIGATING)


class DeciderLabelTests(TestCase):
    def test_labels(self):
        user = User.objects.create_user("ops", password="x", is_staff=True)
        self.assertEqual(incident_detail.decider_label(""), "")
        self.assertEqual(incident_detail.decider_label(f"user:{user.pk}"), "ops")
        self.assertEqual(incident_detail.decider_label("user:99999"), "silinmiş kullanıcı #99999")
        self.assertEqual(incident_detail.decider_label("system:idle"), "otomatik (hareketsizlik)")
        self.assertEqual(incident_detail.decider_label("user:abc"), "sistem")
        self.assertEqual(incident_detail.decider_label("başka"), "sistem")

    def test_detail_exposes_decider_and_time(self):
        user = User.objects.create_user("ops", password="x", is_staff=True)
        inc = make_incident()
        self.assertEqual(incident_detail.build_incident(str(inc.pk))["decided_by_label"], "")
        incidents.decide(inc.pk, user, "resolve")
        d = incident_detail.build_incident(str(inc.pk))
        self.assertEqual(d["decided_by_label"], "ops")
        self.assertIsNotNone(d["decided_at"])

    def test_idle_close_label(self):
        inc = make_incident()
        Incident.objects.filter(pk=inc.pk).update(last_seen=timezone.now() - timedelta(hours=2))
        incidents.close_idle()
        d = incident_detail.build_incident(str(inc.pk))
        self.assertEqual(d["decided_by_label"], "otomatik (hareketsizlik)")

    def test_label_never_leaks_into_live_feed_payload(self):
        from . import realtime
        inc = make_incident()
        self.assertNotIn("decided_by", realtime.incident_payload(inc))
