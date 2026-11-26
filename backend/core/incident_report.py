"""Bir incident'in zaman çizelgesi (olay raporunun ilk küçük parçası).

Yalnızca var olan Event/Action kayıtlarını zaman sırasına göre birleştirir; yeni
bir karar üretmez, hiçbir alanı yorumlamaz. ATT&CK etiketi zaten saklanan
attack_type'tan statik olarak türetilir (bkz. attck.py). Serbest metin (summary,
log alıntısı) rapora olduğu gibi girmez; yalnızca uzunluğu sınırlanır.
"""

from .attck import attck_for
from .models import Action

SUMMARY_MAX = 300


def _event_entry(event):
    return {
        "type": "event",
        "at": event.created_at,
        "id": event.pk,
        "attack_type": event.attack_type,
        "attck": attck_for(event.attack_type),
        "risk_score": event.risk_score,
        "risk_level": event.risk_level,
        "status": event.status,
        "summary": (event.summary or "")[:SUMMARY_MAX],
    }


def _action_entry(action):
    return {
        "type": "action",
        "at": action.created_at,
        "id": action.pk,
        "kind": action.kind,
        "target": action.target,
        "status": action.status,
        "proposed_by": action.proposed_by,
    }


def incident_timeline(incident):
    """Incident'e bağlı olaylar ve eylemler, en eskiden en yeniye, tek bir listede.

    Action'ın incident'e doğrudan bağı yok (yalnızca event üzerinden); bu yüzden
    event__incident ile sorgulanır.
    """
    entries = [_event_entry(e) for e in incident.events.all()]
    entries += [_action_entry(a) for a in Action.objects.filter(event__incident=incident)]
    entries.sort(key=lambda row: (row["at"], row["type"] == "action"))
    return entries


def stage_summary(incident):
    """Incident'te görülen farklı saldırı türleri, ilk görülme sırasına göre (korelasyonun ilk ipucu).

    Yalnızca sırayı gösterir; "bu bir zincir" demez, yorumu insan/ajan yapar. Tek
    saldırı türü varsa tek elemanlı liste döner (çok aşamalı olduğu anlamına gelmez).
    """
    seen = []
    for row in incident_timeline(incident):
        if row["type"] == "event" and row["attack_type"] not in seen:
            seen.append(row["attack_type"])
    return [{"attack_type": t, "attck": attck_for(t)} for t in seen]
