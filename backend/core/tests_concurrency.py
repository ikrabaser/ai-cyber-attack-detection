"""Eşzamanlı öneri yarışı. Yalnızca PostgreSQL'de çalışır (sqlite'ta atlanır).

Çalıştır:  docker compose exec backend python manage.py test core.tests_concurrency

Aynı IP için birden fazla olay aynı anda işlenirse tek bir eylem açılmalı. Sensör aynı saldırgan
için her pencerede yeni olay ürettiği için bu pratikte olabilir (birden fazla worker).
"""

import threading
import time
from unittest import mock, skipUnless

from django.db import connection, connections
from django.test import TransactionTestCase, override_settings

from core import actions
from core.models import Action, Event

THREADS = 8


@skipUnless(connection.vendor == "postgresql", "kilit yalnızca PostgreSQL'de çalışır")
@override_settings(AUTO_REMEDIATION_MODE="advise", PROTECTED_IPS=[], PROTECTED_HOSTS=[])
class ConcurrentProposalTests(TransactionTestCase):
    def _event(self, ip):
        return Event.objects.create(
            source_ip=ip, attack_type="brute_force", risk_score=0.9, risk_level=Event.Level.HIGH
        )

    def _race(self, kind, target, make_event_ip):
        events = [self._event(make_event_ip) for _ in range(THREADS)]
        barrier = threading.Barrier(THREADS)
        real_active = actions._active_action
        results, errors = [], []

        def slow_active(k, t):
            found = real_active(k, t)
            time.sleep(0.2)  # kontrol ile oluşturma arasını genişlet: kilit yoksa herkes "yok" görür
            return found

        def worker(event):
            try:
                barrier.wait()
                results.append(actions.propose_action(event, kind, target).pk)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)
            finally:
                connections.close_all()

        with mock.patch.object(actions, "_active_action", slow_active), \
                mock.patch.object(actions.realtime, "publish"):
            threads = [threading.Thread(target=worker, args=(e,)) for e in events]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=60)
        return results, errors

    def test_parallel_block_proposals_for_same_ip_create_one_action(self):
        ip = "203.0.113.7"
        results, errors = self._race(Action.Kind.BLOCK_IP, ip, ip)
        self.assertEqual(errors, [])
        self.assertEqual(len(results), THREADS)
        self.assertEqual(Action.objects.filter(kind=Action.Kind.BLOCK_IP, target=ip).count(), 1)
        self.assertEqual(len(set(results)), 1)  # hepsi aynı eylemi döndürdü

    def test_different_targets_do_not_block_each_other(self):
        """Kilit hedef başınadır: farklı IP'ler birbirini beklemez ve ayrı eylem alır."""
        a = self._event("203.0.113.10")
        b = self._event("203.0.113.11")
        with mock.patch.object(actions.realtime, "publish"):
            first = actions.propose_action(a, Action.Kind.BLOCK_IP, "203.0.113.10")
            second = actions.propose_action(b, Action.Kind.BLOCK_IP, "203.0.113.11")
        self.assertNotEqual(first.pk, second.pk)
