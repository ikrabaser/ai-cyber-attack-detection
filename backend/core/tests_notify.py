from unittest import mock

from django.core import mail
from django.core.cache import cache
from django.test import TestCase, override_settings

from . import actions, notify
from .models import Action, AuditLog, Event

ON = dict(
    NOTIFY_EMAIL_TO=["ops@example.test"],
    NOTIFY_EMAIL_FROM="ids@example.test",
    PANEL_BASE_URL="http://panel.example.test:8000",
    NOTIFY_REFUSED_COOLDOWN_SECONDS=900,
    AUTO_REMEDIATION_MODE="advise",
)


def make_event(ip="203.0.113.7", attack="ssh_bruteforce", risk=0.92):
    return Event.objects.create(
        source_ip=ip, attack_type=attack, risk_score=risk, risk_level=Event.Level.HIGH
    )


@override_settings(**ON)
class NotificationTests(TestCase):
    def setUp(self):
        cache.clear()
        patcher = mock.patch("core.realtime.publish")  # Centrifugo'ya gerçek istek gitmesin
        patcher.start()
        self.addCleanup(patcher.stop)

    def propose(self, ip="203.0.113.7", **kw):
        with self.captureOnCommitCallbacks(execute=True):
            return actions.propose_action(make_event(ip, **kw), Action.Kind.BLOCK_IP, ip)

    def test_pending_action_sends_one_email_with_the_facts(self):
        self.propose()
        self.assertEqual(len(mail.outbox), 1)
        msg = mail.outbox[0]
        self.assertEqual(msg.to, ["ops@example.test"])
        self.assertEqual(msg.from_email, "ids@example.test")
        self.assertIn("Onay bekliyor", msg.subject)
        self.assertIn("203.0.113.7", msg.subject)
        for text in ("IP engelle", "203.0.113.7", "ssh_bruteforce", "0.92", "http://panel.example.test:8000/panel/"):
            self.assertIn(text, msg.body)
        self.assertIn("hiçbir şey eylemi onaylamaz", msg.body)
        self.assertTrue(AuditLog.objects.filter(verb="send_notification", outcome="sent").exists())

    def test_repeated_events_for_same_ip_send_only_one_email(self):
        for _ in range(4):
            self.propose()
        self.assertEqual(Action.objects.count(), 1)
        self.assertEqual(len(mail.outbox), 1)

    def test_nothing_is_sent_before_commit(self):
        with self.captureOnCommitCallbacks(execute=False) as callbacks:
            actions.propose_action(make_event(), Action.Kind.BLOCK_IP, "203.0.113.7")
        self.assertEqual(len(mail.outbox), 0)
        self.assertTrue(callbacks)  # commit olunca çalışacak bir geri çağrı kayıtlı

    @override_settings(NOTIFY_EMAIL_TO=[])
    def test_disabled_when_no_recipient(self):
        self.propose()
        self.assertEqual(len(mail.outbox), 0)
        self.assertFalse(AuditLog.objects.filter(verb="send_notification").exists())

    def test_attacker_controlled_text_cannot_inject_headers_or_links(self):
        evil = "x\r\nBcc: evil@example.test\nhttp://evil.example.test/<script>"
        self.propose(attack=evil)
        msg = mail.outbox[0]
        self.assertNotIn("\n", msg.subject)
        self.assertEqual(msg.bcc, [])
        self.assertNotIn("Bcc: evil", msg.body)
        self.assertNotIn("<script>", msg.body)
        self.assertNotIn("http://evil", msg.body)  # tıklanabilir bağlantı yok
        self.assertEqual(msg.body.count("http://"), 1)  # yalnızca bizim panel bağlantımız

    def test_event_summary_is_never_included(self):
        event = make_event()
        event.summary = "GİZLİ-SALDIRGAN-METNİ"
        event.save()
        with self.captureOnCommitCallbacks(execute=True):
            actions.propose_action(event, Action.Kind.BLOCK_IP, "203.0.113.7")
        self.assertNotIn("GİZLİ-SALDIRGAN-METNİ", mail.outbox[0].body)

    def test_smtp_failure_does_not_break_the_proposal(self):
        with mock.patch.object(notify, "send_mail", side_effect=OSError("smtp down")):
            action = self.propose()
        self.assertEqual(action.status, Action.Status.PENDING_APPROVAL)
        failed = AuditLog.objects.get(verb="send_notification", outcome="failed")
        self.assertEqual(failed.detail["error"], "OSError")
        self.assertNotIn("smtp down", str(failed.detail))  # hata ayrıntısı denetim kaydına sızmaz

    def test_refused_protected_target_emails_once_then_cooldown(self):
        for _ in range(3):
            with self.captureOnCommitCallbacks(execute=True):
                actions.propose_action(make_event("192.168.56.10"), Action.Kind.BLOCK_IP, "192.168.56.10")
        self.assertEqual(Action.objects.filter(status=Action.Status.REFUSED).count(), 3)
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("Korumalı hedef", mail.outbox[0].subject)
        self.assertIn("Hiçbir önlem uygulanmadı", mail.outbox[0].body)
        self.assertEqual(AuditLog.objects.filter(verb="send_notification", outcome="skipped").count(), 2)

    @override_settings(AUTO_REMEDIATION_MODE="dry_run")
    def test_auto_applied_action_does_not_email(self):
        action = self.propose()
        self.assertEqual(action.status, Action.Status.DRY_RUN)
        self.assertEqual(len(mail.outbox), 0)

    def test_notify_for_missing_or_decided_action_is_a_noop(self):
        self.assertFalse(notify.notify_action(999999))
        action = self.propose()
        mail.outbox.clear()
        Action.objects.filter(pk=action.pk).update(status=Action.Status.REJECTED)
        self.assertFalse(notify.notify_action(action.pk))
        self.assertEqual(len(mail.outbox), 0)
