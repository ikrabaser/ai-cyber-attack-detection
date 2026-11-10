"""Sensörden gelen bir bulguyu olaya çevirir, panele yayınlar ve incelemeye sıraya koyar."""

import ipaddress
import logging

from django.conf import settings
from django.db import transaction

from . import audit, realtime
from .models import Event

log = logging.getLogger(__name__)

MAX_SUMMARY = 2000


class IngestError(ValueError):
    pass


def risk_level_for(score):
    if score >= settings.RISK_HIGH_THRESHOLD:
        return Event.Level.HIGH
    if score >= settings.RISK_MEDIUM_THRESHOLD:
        return Event.Level.MEDIUM
    return Event.Level.LOW


def _score(payload, name, required=False):
    value = payload.get(name)
    if value is None:
        if required:
            raise IngestError(f"{name} gerekli")
        return None
    try:
        value = float(value)
    except (TypeError, ValueError):
        raise IngestError(f"{name} sayı olmalı")
    if not 0.0 <= value <= 1.0:
        raise IngestError(f"{name} 0-1 aralığında olmalı")
    return value


def enqueue_investigation(event):
    """Aynı kaynak IP için bekleyen birden fazla inceleme görevi birikmesin."""
    from procrastinate.exceptions import AlreadyEnqueued

    from .tasks import investigate_event

    try:
        investigate_event.configure(queueing_lock=f"investigate:{event.source_ip}").defer(
            event_id=event.pk
        )
    except AlreadyEnqueued:
        audit.record("system", "enqueue_investigation", event.source_ip, "skipped",
                     reason="aynı IP için bekleyen görev var", event_id=event.pk)


def ingest_event(payload):
    """Eşiği aşan bulgu için Event döner; eşik altındaysa None."""
    if not isinstance(payload, dict):
        raise IngestError("gövde JSON nesnesi olmalı")

    source_ip = str(payload.get("source_ip", "")).strip()
    try:
        ipaddress.ip_address(source_ip)
    except ValueError:
        raise IngestError("source_ip geçerli bir IP olmalı")

    risk = _score(payload, "risk_score", required=True)
    if risk < settings.RISK_LOW_THRESHOLD:
        return None

    features = payload.get("features") or {}
    if not isinstance(features, dict):
        raise IngestError("features nesne olmalı")

    with transaction.atomic():
        event = Event.objects.create(
            source_ip=source_ip,
            target_host=str(payload.get("target_host", ""))[:255],
            attack_type=str(payload.get("attack_type", "unknown"))[:64],
            xgb_label=str(payload.get("xgb_label", ""))[:64],
            xgb_score=_score(payload, "xgb_score"),
            ae_score=_score(payload, "ae_score"),
            lstm_score=_score(payload, "lstm_score"),
            risk_score=risk,
            risk_level=risk_level_for(risk),
            features=features,
            summary=str(payload.get("summary", ""))[:MAX_SUMMARY],
        )
        audit.record("sensor", "ingest_event", event.source_ip, "created",
                     event_id=event.pk, risk_score=risk, risk_level=event.risk_level)
        data = realtime.event_payload(event)
        transaction.on_commit(lambda: realtime.publish(realtime.CHANNEL_FEED, data))
        transaction.on_commit(lambda: enqueue_investigation(event))
    return event
