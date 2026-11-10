from procrastinate.contrib.django import app

from . import actions, audit, realtime
from .agent import get_agent
from .models import Event


@app.task(queue="investigate")
def investigate_event(event_id):
    event = Event.objects.get(pk=event_id)
    event.status = Event.Status.INVESTIGATING
    event.save(update_fields=["status"])

    summary = get_agent().investigate(event)

    event.summary = (summary or event.summary)[:2000]
    event.save(update_fields=["summary"])
    audit.record("worker", "investigate_event", event.source_ip, "done", event_id=event.pk)
    realtime.publish(realtime.CHANNEL_FEED, realtime.event_payload(event))


@app.periodic(cron="* * * * *")
@app.task(queue="maintenance")
def expire_actions(timestamp):
    """Her dakika: onay süresi dolanları kapat, TTL'i dolan engelleri geri al."""
    return actions.expire_due_actions()
