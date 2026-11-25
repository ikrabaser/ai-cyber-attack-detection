"""Centrifugo'ya yayın (sunucu HTTP API'si).

Yayın hatası ana akışı bozmamalı: panel anlık güncellenmese de olay ve eylemler
veritabanında durur. Bu yüzden hatalar yutulur ve loglanır.
"""

import logging

import requests
from django.conf import settings

from .protection import same_ip
from .threat_intel import is_known_bad_ip

log = logging.getLogger(__name__)

CHANNEL_FEED = "events:feed"
CHANNEL_ACTIONS = "events:actions"
CHANNEL_PIPELINE = "events:pipeline"
CHANNEL_INCIDENTS = "events:incidents"

NOTE_MAX = 300


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


# Sensörün --model ile işaretlediği karar kaynakları. features sensör kontrollüdür; bilinmeyen değer panele geçmez.
DETECTED_BY = ("rules", "rules+model", "model")


def event_payload(event):
    features = event.features if isinstance(event.features, dict) else {}
    detected_by = features.get("detected_by")
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
        "incident_id": event.incident_id,
        "detected_by": detected_by if detected_by in DETECTED_BY else "",
        "xgb_label": event.xgb_label,
        "xgb_score": event.xgb_score,
    }


def action_payload(action):
    """Panelin onay kartı için eylem özeti. Kimlik ve neden yalnızca yapılandırılmış alanlardan gelir
    (olayın saldırı türü, risk, kaynak IP); serbest metin (özet, log alıntısı) kartta gösterilmez."""
    payload = {
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
        "proposed_by": str(action.proposed_by or "")[:64],
    }
    event = action.event
    if event is not None:
        payload["attack_type"] = str(event.attack_type or "")[:64]
        payload["risk_score"] = event.risk_score
        payload["risk_level"] = event.risk_level
        payload["event_source_ip"] = event.source_ip
        # Yalnızca IP engelinde anlamlı: engellenen adres olayın kaynağı mı?
        payload["target_is_source"] = (
            same_ip(action.target, event.source_ip) if action.kind == "block_ip" else None
        )
        # Statik, çevrimdışı liste ile ipucu; karar vermez (bkz. threat_intel.py).
        payload["source_known_bad"] = is_known_bad_ip(event.source_ip)
    return payload


def _int_or_none(value):
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def pipeline_payload(entry):
    """Denetim kaydından panele giden adım. Yalnızca izin verilen alanlar: `detail` olduğu gibi
    gönderilmez (hata metinleri, alıcı sayısı vb. dışarı çıkmaz)."""
    detail = entry.detail if isinstance(entry.detail, dict) else {}
    actor = entry.actor.split(":", 1)[0]  # "user:3" -> "user": kullanıcı numarası yayınlanmaz
    payload = {
        "type": "step",
        "id": entry.pk,
        "created_at": entry.created_at.isoformat(),
        "actor": actor[:32],
        "verb": entry.verb[:64],
        "target": entry.target[:100],
        "outcome": entry.outcome[:32],
        "event_id": _int_or_none(detail.get("event_id")),
        "action_id": _int_or_none(detail.get("action_id")),
        "incident_id": _int_or_none(detail.get("incident_id")),
    }
    note = detail.get("note")
    if entry.verb == "investigate_event" and isinstance(note, str):
        payload["note"] = note[:NOTE_MAX]
    return payload


def incident_payload(incident):
    """Panelin incident satırı. Ham özellik yok; özet kısaltılır."""
    return {
        "type": "incident",
        "id": incident.pk,
        "source_ip": incident.source_ip,
        "status": incident.status,
        "risk_level": incident.risk_level,
        "max_risk": incident.max_risk,
        "attack_type": incident.attack_type,
        "event_count": incident.event_count,
        "first_seen": incident.first_seen.isoformat(),
        "last_seen": incident.last_seen.isoformat(),
        "closed_at": incident.closed_at.isoformat() if incident.closed_at else None,
        "summary": incident.summary[:300],
    }
