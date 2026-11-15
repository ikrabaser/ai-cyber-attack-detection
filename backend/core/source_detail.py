"""Tek bir kaynak IP'nin ayrıntısı: panelin "zaman çizelgesi" kartı için.

Yalnızca sayı, kısa etiket ve olayın (500 karakterle sınırlı) özeti döner; olayın `features` alanı
(saldırgan kontrolündeki ham veri) hiçbir zaman dışarı çıkmaz.
"""

import ipaddress

from django.conf import settings
from django.db.models import Count, Max, Min, Q

from . import realtime
from .models import Action, Event
from .protection import is_protected_ip

TIMELINE_EVENTS = 200   # grafikte en yeni bu kadar olay (zaman sırasıyla)
TOP_ATTACK_TYPES = 8
MAX_ACTIONS = 50


class SourceError(ValueError):
    """Geçersiz IP (istemciye 400 olarak döner)."""


def normalize_ip(raw):
    raw = (raw or "").strip()
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        raise SourceError("geçersiz IP adresi")


def _action_item(action):
    item = realtime.action_payload(action)
    item["created_at"] = action.created_at.isoformat()
    return item


def build_source(raw_ip):
    ip = normalize_ip(raw_ip)
    events = Event.objects.filter(source_ip=ip)

    agg = events.aggregate(
        total=Count("id"), first=Min("created_at"), last=Max("created_at"), max_risk=Max("risk_score")
    )
    type_rows = list(
        events.order_by().values("attack_type").annotate(n=Count("id")).order_by("-n", "attack_type")
    )
    attack_types = [{"name": r["attack_type"], "count": r["n"]} for r in type_rows[:TOP_ATTACK_TYPES]]

    # En yeni N olay, grafikte soldan sağa (eskiden yeniye) çizilsin diye ters çevrilir.
    timeline = list(events.order_by("-created_at", "-id")[:TIMELINE_EVENTS])[::-1]

    actions = (
        Action.objects.filter(Q(target=ip) | Q(event__source_ip=ip)).distinct().order_by("-id")[:MAX_ACTIONS]
    )

    return {
        "ip": ip,
        "protected": is_protected_ip(ip),
        "thresholds": {
            "low": settings.RISK_LOW_THRESHOLD,
            "medium": settings.RISK_MEDIUM_THRESHOLD,
            "high": settings.RISK_HIGH_THRESHOLD,
        },
        "totals": {
            "events": agg["total"],
            "first_seen": agg["first"].isoformat() if agg["first"] else None,
            "last_seen": agg["last"].isoformat() if agg["last"] else None,
            "max_risk": round(agg["max_risk"], 3) if agg["max_risk"] is not None else None,
        },
        "attack_types": attack_types,
        "events": [realtime.event_payload(e) for e in timeline],
        "events_truncated": agg["total"] > len(timeline),
        "actions": [_action_item(a) for a in actions],
    }
