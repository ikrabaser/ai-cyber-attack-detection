import hmac
import json

from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST

from .ingest import IngestError, ingest_event


@require_GET
def healthz(request):
    return JsonResponse({"status": "ok"})


def _bearer_ok(request):
    expected = settings.SENSOR_API_TOKEN
    if not expected:  # güvenli varsayılan: token tanımlı değilse kapalı
        return False
    header = request.headers.get("Authorization", "")
    scheme, _, token = header.partition(" ")
    return scheme.lower() == "bearer" and hmac.compare_digest(token.strip(), expected)


@csrf_exempt
@require_POST
def ingest(request):
    """Sensör -> backend: eşiği aşan bulguyu olaya çevir."""
    if not _bearer_ok(request):
        return JsonResponse({"error": "yetkisiz"}, status=401)
    try:
        payload = json.loads(request.body or b"{}")
        event = ingest_event(payload)
    except (json.JSONDecodeError, IngestError) as exc:
        return JsonResponse({"error": str(exc)}, status=400)
    if event is None:
        return JsonResponse({"status": "ignored", "reason": "risk eşiğin altında"})
    return JsonResponse({"status": "created", "event_id": event.pk, "risk_level": event.risk_level},
                        status=201)
