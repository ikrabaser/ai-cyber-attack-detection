"""Incident yaşam döngüsü: olayı açık incident'e bağlar, hareketsiz olanı kapatır.

IP başına en fazla bir açık incident vardır (kısmi unique kısıt). Eşzamanlı iki olay aynı anda
yeni incident açmaya kalkarsa kaybeden IntegrityError alır ve kazananın incident'ine katılır.
"""

from datetime import timedelta

from django.conf import settings
from django.db import IntegrityError, transaction
from django.utils import timezone

from . import audit, realtime, triage
from .models import Event, Incident

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


def _close(incident, actor, now, status=Incident.Status.RESOLVED, detail=None):
    incident.status = status
    incident.closed_at = now
    fields = ["status", "closed_at"]
    # Daha önce bir insan karar verdiyse (örn. onayladıysa) hareketsizlik kapanışı onu ezmez.
    if actor.startswith("user:") or not incident.decided_by:
        incident.decided_by = actor
        incident.decided_at = now
        fields += ["decided_by", "decided_at"]
    incident.save(update_fields=fields)
    audit.record(actor, "close_incident", incident.source_ip, status, incident_id=incident.pk, **(detail or {}))
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


class DecisionError(Exception):
    """Karar uygulanamadı; `code` HTTP benzeri durum kodu."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


DECISIONS = ("confirm", "false_positive", "resolve")


def decide(incident_id, user, decision):
    """İnsan kararı: onayla (gerçek saldırı), yanlış alarm ya da çöz.

    Yalnızca açık incident için geçerlidir; karar denetim kaydına ve panele yansır. Bekleyen eylemlere
    dokunmaz: onlar ayrı bir insan kararıdır ve politika katmanından geçer.
    """
    if decision not in DECISIONS:
        raise ValueError(f"bilinmeyen karar: {decision}")
    actor = f"user:{user.pk}"
    now = timezone.now()
    with transaction.atomic():
        incident = Incident.objects.select_for_update().filter(pk=incident_id).first()
        if incident is None:
            raise DecisionError(404, "incident bulunamadı")
        if incident.status not in OPEN:
            raise DecisionError(409, f"incident zaten kapalı: {incident.get_status_display()}")
        if decision == "confirm" and incident.status == Incident.Status.CONFIRMED:
            raise DecisionError(409, "incident zaten onaylı")
        # Karar anının kaydı (değişiklikten ÖNCE): öneri + kanıt kodları; ileride ML için etiketli veri.
        detail = {"triage": triage.snapshot(incident)}
        if decision == "confirm":
            incident.status = Incident.Status.CONFIRMED
            incident.decided_by = actor
            incident.decided_at = now
            incident.save(update_fields=["status", "decided_by", "decided_at"])
            audit.record(actor, "confirm_incident", incident.source_ip, "confirmed", incident_id=incident.pk, **detail)
            _publish_after_commit(incident)
        elif decision == "false_positive":
            # Yanlış alarm incident'in tüm olayları için de geçerlidir; kaç olayın etkilendiği denetim kaydına yazılır.
            detail["events_dismissed"] = incident.events.exclude(status=Event.Status.DISMISSED).update(
                status=Event.Status.DISMISSED
            )
            _close(incident, actor, now, Incident.Status.FALSE_POSITIVE, detail)
        else:
            _close(incident, actor, now, Incident.Status.RESOLVED, detail)
    return incident
