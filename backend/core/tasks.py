from django.utils import timezone
from procrastinate.contrib.django import app

from . import actions, audit, incidents, realtime
from .agent import get_agent
from .models import AnalysisRun, Event, Incident


def _start_run(event, agent):
    """İncelemeyi kaydeder; incident 'yeni' ise 'inceleniyor' yapar."""
    name = getattr(agent, "name", None)
    if not isinstance(name, str) or not name:
        name = type(agent).__name__
    run = AnalysisRun.objects.create(incident_id=event.incident_id, event=event, agent=name[:64])
    if event.incident_id:
        moved = Incident.objects.filter(pk=event.incident_id, status=Incident.Status.NEW).update(
            status=Incident.Status.INVESTIGATING
        )
        if moved:
            incidents.publish_state(event.incident_id)
    return run


@app.task(queue="investigate")
def investigate_event(event_id):
    event = Event.objects.get(pk=event_id)
    # Sıradayken insan "yanlış alarm" dediyse bu karar worker tarafından geri alınmaz.
    Event.objects.filter(pk=event.pk).exclude(status=Event.Status.DISMISSED).update(
        status=Event.Status.INVESTIGATING
    )
    event.refresh_from_db(fields=["status"])

    agent = get_agent()
    run = _start_run(event, agent)
    try:
        summary = agent.investigate(event)
    except Exception as exc:
        run.status = AnalysisRun.Status.FAILED
        run.finished_at = timezone.now()
        run.detail = {"error": type(exc).__name__}  # ayrıntı yalnızca worker loguna gider
        run.save(update_fields=["status", "finished_at", "detail"])
        audit.record("worker", "investigate_event", event.source_ip, "failed",
                     event_id=event.pk, incident_id=event.incident_id, error=type(exc).__name__)
        raise

    event.summary = (summary or event.summary)[:2000]
    event.save(update_fields=["summary"])
    run.status = AnalysisRun.Status.OK
    run.finished_at = timezone.now()
    run.summary = event.summary
    run.save(update_fields=["status", "finished_at", "summary"])
    if event.incident_id:
        Incident.objects.filter(pk=event.incident_id).update(summary=event.summary)
        incidents.publish_state(event.incident_id)
    audit.record("worker", "investigate_event", event.source_ip, "done",
                 event_id=event.pk, incident_id=event.incident_id, note=event.summary[:300])
    event.refresh_from_db(fields=["status"])  # inceleme sürerken karar verilmiş olabilir
    realtime.publish(realtime.CHANNEL_FEED, realtime.event_payload(event))


@app.periodic(cron="* * * * *")
@app.task(queue="maintenance")
def close_idle_incidents(timestamp):
    """Her dakika: uzun süredir olay gelmeyen açık incident'leri kapat."""
    return incidents.close_idle()


@app.periodic(cron="* * * * *")
@app.task(queue="maintenance")
def expire_actions(timestamp):
    """Her dakika: onay süresi dolanları kapat, TTL'i dolan engelleri geri al."""
    return actions.expire_due_actions()
