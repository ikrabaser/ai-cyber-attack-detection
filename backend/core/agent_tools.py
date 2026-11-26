"""Ajanın (ileride Claude Agent SDK) kullanacağı SALT OKUNUR sorgu araçları.

Hiçbiri veritabanını değiştirmez; eylem önermek hâlâ yalnızca
`core.actions.propose_action` üzerinden olur (bkz. agent.py'deki not). Her
fonksiyon zaten sanitize edilmiş payload üreticilerini sarar (realtime.py,
source_detail.py, incident_report.py); ham `features`/log metni burada da
dışarı çıkmaz, çünkü o üreticiler zaten çıkarmıyor.

Bilinmeyen id için None döner (ajan "bulunamadı" diye yorumlasın); geçersiz
IP için source_detail.SourceError (ValueError) fırlatılır, çünkü bu girdi
hatasıdır, veri yokluğu değildir.
"""

from .incident_report import incident_timeline as _incident_timeline
from .models import Event, Incident
from .realtime import event_payload, incident_payload
from .source_detail import build_source


def get_event(event_id):
    """Tek bir olayın panel payload'u (bkz. realtime.event_payload); yoksa None."""
    event = Event.objects.filter(pk=event_id).first()
    return event_payload(event) if event else None


def get_incident(incident_id):
    """Tek bir incident'in panel payload'u (bkz. realtime.incident_payload); yoksa None."""
    incident = Incident.objects.filter(pk=incident_id).first()
    return incident_payload(incident) if incident else None


def get_incident_timeline(incident_id):
    """Incident'in olay + eylem zaman çizelgesi (bkz. incident_report.incident_timeline); yoksa None."""
    incident = Incident.objects.filter(pk=incident_id).first()
    if incident is None:
        return None
    return [dict(row, at=row["at"].isoformat()) for row in _incident_timeline(incident)]


def get_source_history(ip):
    """Bir kaynak IP'nin özeti (bkz. source_detail.build_source). Geçersiz IP: SourceError."""
    return build_source(ip)
