"""Centrifugo proxy uç noktaları (connect, refresh, subscribe, rpc).

Güven modeli
- Bu uç noktalara yalnızca Centrifugo erişmeli. Her istekte ortak sır
  (X-Centrifugo-Proxy-Secret) doğrulanır; sır tanımlı değilse hepsi reddedilir.
- connect/refresh: Centrifugo, tarayıcının Cookie başlığını iletir; Django oturumu
  kullanıcıyı belirler. Yalnızca staff kullanıcılar bağlanabilir.
- subscribe/rpc: kullanıcı kimliği connect'te döndürülen `user` alanından gelir
  (istek gövdesindeki `user`), ardından veritabanından yeniden doğrulanır.
- Yanıtlarda daima açık `result`, `error` veya `disconnect` dön: Centrifugo,
  üçü de boş bir yanıtı "izin verildi" sayar.
"""

import hmac
import json
import time

from django.conf import settings
from django.contrib.auth import get_user_model
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from . import actions, realtime
from .actions import ActionError

ALLOWED_CHANNELS = {realtime.CHANNEL_FEED, realtime.CHANNEL_ACTIONS}

RPC_METHODS = {
    "ids:approve_action": actions.approve_action,
    "ids:reject_action": actions.reject_action,
    "ids:rollback_action": actions.rollback_by_user,
}


def _secret_ok(request):
    expected = settings.RT_PROXY_SECRET
    if not expected:
        return False
    got = request.headers.get("X-Centrifugo-Proxy-Secret", "")
    return hmac.compare_digest(got, expected)


def proxy_view(view):
    """csrf_exempt + POST + ortak sır + JSON gövde."""

    @csrf_exempt
    @require_POST
    def wrapper(request):
        if not _secret_ok(request):
            return JsonResponse({"error": "yetkisiz"}, status=403)
        try:
            body = json.loads(request.body or b"{}")
        except json.JSONDecodeError:
            return JsonResponse({"error": "geçersiz JSON"}, status=400)
        return view(request, body)

    wrapper.__name__ = view.__name__
    return wrapper


def _expire_at():
    # refresh proxy ile oturum iptali en geç bu sürede yansır
    return int(time.time()) + settings.RT_SESSION_TTL_SECONDS


def _staff_user_by_id(user_id):
    User = get_user_model()
    try:
        user = User.objects.get(pk=int(user_id))
    except (User.DoesNotExist, TypeError, ValueError):
        return None
    return user if user.is_active and user.is_staff else None


def _err(code, message):
    return JsonResponse({"error": {"code": code, "message": message}})


def _disconnect(code=4501, reason="unauthorized"):
    return JsonResponse({"disconnect": {"code": code, "reason": reason}})


@proxy_view
def connect(request, body):
    user = request.user
    if not (user.is_authenticated and user.is_active and user.is_staff):
        return _disconnect()
    return JsonResponse({"result": {"user": str(user.pk), "expire_at": _expire_at()}})


@proxy_view
def refresh(request, body):
    user = _staff_user_by_id(body.get("user"))
    # Cookie hâlâ geçerli mi? (iptal edilmiş oturum yenilenmemeli)
    if user is None or not request.user.is_authenticated or request.user.pk != user.pk:
        return JsonResponse({"result": {"expired": True}})
    return JsonResponse({"result": {"expire_at": _expire_at()}})


@proxy_view
def subscribe(request, body):
    user = _staff_user_by_id(body.get("user"))
    if user is None:
        return _err(403, "permission denied")
    if body.get("channel") not in ALLOWED_CHANNELS:
        return _err(403, "permission denied")
    return JsonResponse({"result": {}})


@proxy_view
def rpc(request, body):
    user = _staff_user_by_id(body.get("user"))
    if user is None:
        return _err(403, "permission denied")

    handler = RPC_METHODS.get(body.get("method"))
    if handler is None:
        return _err(404, "method not found")

    data = body.get("data") or {}
    try:
        action = handler(int(data.get("action_id")), user)
    except (TypeError, ValueError):
        return _err(400, "action_id gerekli")
    except ActionError as exc:
        return _err(exc.code, exc.message)
    return JsonResponse({"result": {"data": {"action_id": action.pk, "status": action.status}}})
