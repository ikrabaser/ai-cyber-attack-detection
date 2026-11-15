from datetime import timedelta
from unittest import mock

from django.db import IntegrityError, transaction
from django.test import TestCase, override_settings
from django.utils import timezone

from . import incidents
from .ingest import ingest_event
from .models import AnalysisRun, AuditLog, Event, Incident
from .tasks import investigate_event

IP = "203.0.113.7"


def send(ip=IP, risk=0.92, attack="brute_force"):
    return ingest_event({"source_ip": ip, "risk_score": risk, "attack_type": attack})


def age(event, seconds):
    """Olayı (ve incident'in son görülmesini) geçmişe it."""
    past = timezone.now() - timedelta(seconds=seconds)
    Event.objects.filter(pk=event.pk).update(created_at=past)
    if event.incident_id:
        Incident.objects.filter(pk=event.incident_id).update(last_seen=past, first_seen=past)


@mock.patch("core.ingest.enqueue_investigation")
@mock.patch("core.realtime.publish")
class IngestIncidentTests(TestCase):
    def test_first_event_opens_incident(self, pub, enq):
        event = send()
        inc = event.incident
        self.assertEqual(inc.status, Incident.Status.NEW)
        self.assertEqual((inc.source_ip, inc.event_count, inc.max_risk), (IP, 1, 0.92))
        self.assertEqual((inc.risk_level, inc.attack_type), ("high", "brute_force"))
        self.assertEqual(inc.first_seen, event.created_at)
        self.assertTrue(AuditLog.objects.filter(verb="open_incident", detail__incident_id=inc.pk).exists())

    def test_same_ip_events_join_one_incident(self, pub, enq):
        first = send(risk=0.75, attack="port_scan")
        second = send(risk=0.95, attack="brute_force")
        third = send(risk=0.55, attack="port_scan")
        self.assertEqual(Incident.objects.count(), 1)
        inc = Incident.objects.get()
        self.assertEqual({first.incident_id, second.incident_id, third.incident_id}, {inc.pk})
        self.assertEqual(inc.event_count, 3)
        self.assertEqual((inc.max_risk, inc.risk_level, inc.attack_type), (0.95, "high", "brute_force"))
        self.assertEqual(AuditLog.objects.filter(verb="open_incident").count(), 1)  # eklemeler denetime yazılmaz

    def test_lower_risk_event_does_not_downgrade_incident(self, pub, enq):
        send(risk=0.95, attack="brute_force")
        send(risk=0.6, attack="port_scan")
        inc = Incident.objects.get()
        self.assertEqual((inc.max_risk, inc.attack_type), (0.95, "brute_force"))

    def test_different_ips_get_different_incidents(self, pub, enq):
        a, b = send("203.0.113.7"), send("203.0.113.8")
        self.assertNotEqual(a.incident_id, b.incident_id)

    def test_ipv6_is_matched_after_normalization(self, pub, enq):
        a, b = send("2001:db8::1"), send("2001:DB8:0:0:0:0:0:1")
        self.assertEqual(a.incident_id, b.incident_id)

    @override_settings(INCIDENT_IDLE_SECONDS=600)
    def test_stale_open_incident_is_closed_and_new_one_opened(self, pub, enq):
        old = send()
        age(old, 3600)
        new = send()
        self.assertNotEqual(old.incident_id, new.incident_id)
        old_inc = Incident.objects.get(pk=old.incident_id)
        self.assertEqual(old_inc.status, Incident.Status.RESOLVED)
        self.assertEqual(old_inc.decided_by, "system:idle")
        self.assertIsNotNone(old_inc.closed_at)
        self.assertEqual(new.incident.status, Incident.Status.NEW)

    def test_closed_incident_is_not_reused(self, pub, enq):
        first = send()
        Incident.objects.filter(pk=first.incident_id).update(status=Incident.Status.FALSE_POSITIVE)
        second = send()
        self.assertNotEqual(first.incident_id, second.incident_id)

    def test_event_payload_carries_incident_id(self, pub, enq):
        event = send()
        payloads = [c.args[1] for c in pub.call_args_list if c.args[0] == "events:feed"]
        self.assertEqual(payloads, [])  # on_commit TestCase'te çalışmaz; yük yine de doğru kurulur
        from .realtime import event_payload
        self.assertEqual(event_payload(event)["incident_id"], event.incident_id)


class ConstraintTests(TestCase):
    def make(self, status):
        now = timezone.now()
        return Incident.objects.create(source_ip=IP, status=status, risk_level="high", max_risk=0.9,
                                       event_count=1, first_seen=now, last_seen=now)

    def test_only_one_open_incident_per_ip(self):
        self.make(Incident.Status.NEW)
        for status in (Incident.Status.NEW, Incident.Status.INVESTIGATING, Incident.Status.CONFIRMED):
            with self.assertRaises(IntegrityError), transaction.atomic():
                self.make(status)

    def test_closed_incidents_do_not_block_a_new_one(self):
        self.make(Incident.Status.RESOLVED)
        self.make(Incident.Status.FALSE_POSITIVE)
        self.make(Incident.Status.NEW)
        self.assertEqual(Incident.objects.count(), 3)


class CloseIdleTests(TestCase):
    def make(self, ip, status, last_seen_ago):
        seen = timezone.now() - timedelta(seconds=last_seen_ago)
        return Incident.objects.create(source_ip=ip, status=status, risk_level="high", max_risk=0.9,
                                       event_count=1, first_seen=seen, last_seen=seen)

    @override_settings(INCIDENT_IDLE_SECONDS=600)
    def test_only_stale_open_incidents_are_closed(self):
        stale = self.make("203.0.113.1", Incident.Status.INVESTIGATING, 3600)
        fresh = self.make("203.0.113.2", Incident.Status.NEW, 60)
        done = self.make("203.0.113.3", Incident.Status.FALSE_POSITIVE, 7200)
        with mock.patch("core.realtime.publish"):
            self.assertEqual(incidents.close_idle(), 1)
            self.assertEqual(incidents.close_idle(), 0)  # tekrar çalışınca yeni kapanış yok
        for obj in (stale, fresh, done):
            obj.refresh_from_db()
        self.assertEqual(stale.status, Incident.Status.RESOLVED)
        self.assertEqual(fresh.status, Incident.Status.NEW)
        self.assertEqual(done.status, Incident.Status.FALSE_POSITIVE)
        self.assertEqual(AuditLog.objects.filter(verb="close_incident").count(), 1)


@mock.patch("core.realtime.publish")
class InvestigationRunTests(TestCase):
    def setUp(self):
        with mock.patch("core.ingest.enqueue_investigation"):
            self.event = send()

    def test_successful_run_is_recorded_and_incident_moves_to_investigating(self, pub):
        with mock.patch("core.tasks.get_agent") as get:
            get.return_value.name = "test-agent"
            get.return_value.investigate.return_value = "Özet: brute force şüphesi"
            investigate_event(self.event.pk)
        run = AnalysisRun.objects.get()
        self.assertEqual((run.agent, run.status, run.incident_id, run.event_id),
                         ("test-agent", "ok", self.event.incident_id, self.event.pk))
        self.assertEqual(run.summary, "Özet: brute force şüphesi")
        self.assertIsNotNone(run.finished_at)
        inc = Incident.objects.get()
        self.assertEqual(inc.status, Incident.Status.INVESTIGATING)
        self.assertEqual(inc.summary, "Özet: brute force şüphesi")

    def test_failed_run_is_recorded_without_error_text_and_reraised(self, pub):
        with mock.patch("core.tasks.get_agent") as get:
            get.return_value.name = "test-agent"
            get.return_value.investigate.side_effect = RuntimeError("anahtar=gizli")
            with self.assertRaises(RuntimeError):
                investigate_event(self.event.pk)
        run = AnalysisRun.objects.get()
        self.assertEqual(run.status, AnalysisRun.Status.FAILED)
        self.assertEqual(run.detail, {"error": "RuntimeError"})
        self.assertNotIn("gizli", str(run.detail) + run.summary)
        step = AuditLog.objects.get(verb="investigate_event", outcome="failed")
        self.assertNotIn("gizli", str(step.detail).replace("RuntimeError", ""))

    def test_second_run_does_not_reset_a_decided_incident(self, pub):
        Incident.objects.update(status=Incident.Status.CONFIRMED)
        with mock.patch("core.tasks.get_agent") as get:
            get.return_value.name = "a"
            get.return_value.investigate.return_value = "x"
            investigate_event(self.event.pk)
        self.assertEqual(Incident.objects.get().status, Incident.Status.CONFIRMED)

    def test_event_without_incident_still_works(self, pub):
        legacy = Event.objects.create(source_ip="198.51.100.1", attack_type="x", risk_score=0.9, risk_level="high")
        with mock.patch("core.tasks.get_agent") as get:
            get.return_value.name = "a"
            get.return_value.investigate.return_value = "x"
            investigate_event(legacy.pk)
        run = AnalysisRun.objects.get(event=legacy)
        self.assertIsNone(run.incident_id)
