"""Incident yaşam döngüsü: olayı açık incident'e bağlar, hareketsiz olanı kapatır.

IP başına en fazla bir açık incident vardır (kısmi unique kısıt). Eşzamanlı iki olay aynı anda
yeni incident açmaya kalkarsa kaybeden IntegrityError alır ve kazananın incident'ine katılır.
"""

from datetime import timedelta

from django.conf import settings
from django.db import IntegrityError, transaction
from django.utils import timezone

from . import audit, realtime
from .models import Incident

OPEN = [s.value for s in Incident.OPEN_STATUSES]
MAX_TRIES = 3


def _locked_open(ip):
    return Incident.objects.select_for_update().filter(source_ip=ip, status__in=OPEN).first()


def _publish_after_commit(incident):
    payload = realtime.incident_payload(incident)
    transaction.on_commit(lambda: realtime.publish(realtime.CHANNEL_INCIDENTS, payload))


def publish_state(incident_id):
    """Durumu/özeti dışarıdan (update ile) değişen incident'i panele yeniden yayınla."""
    incident = Incident.objects.filter(pk=incident_id).first()
    if incident is not None:
        _publish_after_commit(incident)


def _idle():
    return timedelta(seconds=settings.INCIDENT_IDLE_SECONDS)


def _close(incident, actor, now, status=Incident.Status.RESOLVED):
    incident.status = status
    incident.closed_at = now
    incident.decided_by = actor
    incident.decided_at = now
    incident.save(update_fields=["status", "closed_at", "decided_by", "decided_at"])
    audit.record(actor, "close_incident", incident.source_ip, status, incident_id=incident.pk)
    _publish_after_commit(incident)


def _absorb(incident, event):
    incident.event_count += 1
    incident.last_seen = max(incident.last_seen, event.created_at)
    fields = ["event_count", "last_seen"]
    if event.risk_score >= incident.max_risk:
        incident.max_risk = event.risk_score
        incident.risk_level = event.risk_level
        incident.attack_type = event.attack_type
        fields += ["max_risk", "risk_level", "attack_type"]
    incident.save(update_fields=fields)


def _open_new(event):
    try:
        with transaction.atomic():  # savepoint: kısıt hatası dış işlemi bozmasın
            incident = Incident.objects.create(
                source_ip=event.source_ip,
                status=Incident.Status.NEW,
                risk_level=event.risk_level,
                max_risk=event.risk_score,
                attack_type=event.attack_type,
                event_count=1,
                first_seen=event.created_at,
                last_seen=event.created_at,
            )
    except IntegrityError:
        return None
    audit.record("system", "open_incident", event.source_ip, "created",
                 incident_id=incident.pk, event_id=event.pk)
    return incident


def attach_event(event):
    """Olayı açık incident'e bağlar, yoksa açar. `transaction.atomic` içinde çağrılmalı."""
    incident = None
    for _ in range(MAX_TRIES):
        incident = _locked_open(event.source_ip)
        if incident is not None and incident.last_seen < event.created_at - _idle():
            _close(incident, "system:idle", event.created_at)
            incident = None
        if incident is not None:
            _absorb(incident, event)
            break
        incident = _open_new(event)
        if incident is not None:
            break
        # Başka bir işlem aynı anda açtı: döngü onu kilitleyip katılacak.
    if incident is None:
        raise RuntimeError(f"{event.source_ip} için incident bağlanamadı")
    event.incident = incident
    event.save(update_fields=["incident"])
    _publish_after_commit(incident)
    return incident


def close_idle(now=None):
    """Son olaydan beri INCIDENT_IDLE_SECONDS geçen açık incident'leri 'çözüldü' yapar."""
    now = now or timezone.now()
    cutoff = now - _idle()
    ids = list(
        Incident.objects.filter(status__in=OPEN, last_seen__lt=cutoff).values_list("pk", flat=True)
    )
    closed = 0
    for pk in ids:
        with transaction.atomic():
            incident = (
                Incident.objects.select_for_update()
                .filter(pk=pk, status__in=OPEN, last_seen__lt=cutoff)
                .first()
            )
            if incident is None:  # bu arada olay geldi ya da kapandı
                continue
            _close(incident, "system:idle", now)
            closed += 1
    return closed
