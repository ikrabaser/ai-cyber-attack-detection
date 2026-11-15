"""Tek bir incident'in ayrıntısı: panelin incident kartı için.

Olayın `features` alanı (saldırgan kontrollü ham veri) hiçbir zaman dışarı çıkmaz; triage yalnızca ondan türetilmiş
sayıları ve sabit metinleri döndürür.
"""

from . import realtime, triage
from .models import Action, AnalysisRun, Incident
from .protection import is_protected_ip

MAX_EVENTS = 100
MAX_RUNS = 20
MAX_ACTIONS = 50
RUN_SUMMARY_MAX = 2000


class IncidentError(ValueError):
    """Geçersiz numara (istemciye 400 olarak döner)."""


class IncidentNotFound(LookupError):
    """İstemciye 404 olarak döner."""


def parse_id(raw):
    raw = (raw or "").strip()
    if not raw.isascii() or not raw.isdigit() or len(raw) > 12:
        raise IncidentError("geçersiz incident numarası")
    return int(raw)


def _run_item(run):
    return {
        "id": run.pk,
        "agent": run.agent,
        "status": run.status,
        "started_at": run.started_at.isoformat(),
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        "summary": run.summary[:RUN_SUMMARY_MAX],
        "event_id": run.event_id,
    }


def _action_item(action):
    item = realtime.action_payload(action)
    item["created_at"] = action.created_at.isoformat()
    return item


def build_incident(raw_id):
    pk = parse_id(raw_id)
    try:
        incident = Incident.objects.get(pk=pk)
    except Incident.DoesNotExist:
        raise IncidentNotFound("incident bulunamadı")

    events = list(incident.events.order_by("-created_at", "-id")[:MAX_EVENTS])
    runs = AnalysisRun.objects.filter(incident=incident).order_by("-started_at", "-id")[:MAX_RUNS]
    actions = list(Action.objects.filter(event__incident=incident).order_by("-id")[:MAX_ACTIONS])

    return {
        "incident": realtime.incident_payload(incident),
        "protected": is_protected_ip(incident.source_ip),
        "decided_by": incident.decided_by,
        "events": [realtime.event_payload(e) for e in events],
        "events_truncated": incident.event_count > MAX_EVENTS,
        "runs": [_run_item(r) for r in runs],
        "actions": [_action_item(a) for a in actions],
        "triage": triage.triage(incident, events, actions),
    }
