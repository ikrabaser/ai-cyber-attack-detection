"""Centrifugo'ya yayın (sunucu HTTP API'si).

Yayın hatası ana akışı bozmamalı: panel anlık güncellenmese de olay ve eylemler
veritabanında durur. Bu yüzden hatalar yutulur ve loglanır.
"""

import logging

import requests
from django.conf import settings

log = logging.getLogger(__name__)

CHANNEL_FEED = "events:feed"
CHANNEL_ACTIONS = "events:actions"


def publish(channel, data):
    if not settings.RT_API_KEY:
        log.warning("RT_API_KEY tanımlı değil, yayın atlandı: %s", channel)
        return False
    try:
        resp = requests.post(
            f"{settings.RT_API_URL.rstrip('/')}/publish",
            json={"channel": channel, "data": data},
            headers={"X-API-Key": settings.RT_API_KEY},
            timeout=2,
        )
        resp.raise_for_status()
        body = resp.json()
        if body.get("error"):
            log.warning("Centrifugo yayın hatası (%s): %s", channel, body["error"])
            return False
        return True
    except (requests.RequestException, ValueError) as exc:
        log.warning("Centrifugo'ya yayın yapılamadı (%s): %s", channel, exc)
        return False


def event_payload(event):
    return {
        "type": "event",
        "id": event.pk,
        "created_at": event.created_at.isoformat(),
        "source_ip": event.source_ip,
        "target_host": event.target_host,
        "attack_type": event.attack_type,
        "risk_score": event.risk_score,
        "risk_level": event.risk_level,
        "status": event.status,
        "summary": event.summary[:500],
    }


def action_payload(action):
    return {
        "type": "action",
        "id": action.pk,
        "event_id": action.event_id,
        "kind": action.kind,
        "target": action.target,
        "status": action.status,
        "requires_approval": action.requires_approval,
        "ttl_seconds": action.ttl_seconds,
        "approval_deadline": action.approval_deadline.isoformat()
        if action.approval_deadline
        else None,
        "effect_expires_at": action.effect_expires_at.isoformat()
        if action.effect_expires_at
        else None,
    }
