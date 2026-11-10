"""Müdahale politikası: önerme, onay, uygulama, geri alma.

Bu modül agent'ın ERİŞEMEDİĞİ, kod tarafındaki güvenlik katmanıdır. Agent
yalnızca `propose_action` çağırabilir; onay kararı doğrulanmış bir insan
kullanıcıdan (Centrifugo RPC -> approve_action) gelir.

Kurallar
- Korumalı hedefler (protection.py) hem önerirken hem uygularken reddedilir.
- Kademe (AUTO_REMEDIATION_MODE):
    advise  : her eylem onay bekler.
    dry_run : TTL'li tek IP engeli otomatik ve "yapılmış gibi" kaydedilir.
    enforce : TTL'li tek IP engeli otomatik ve gerçekten uygulanır.
  Host izolasyonu ve yapılandırma düzeltmesi her kademede insan onayı ister.
- Her engel TTL'lidir; süre dolunca expire_due_actions geri alır.
- Her adım denetim kaydına yazılır (reddedilenler dahil).
"""

import logging
from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from . import audit, realtime
from .firewall import get_backend
from .models import Action
from .protection import is_protected_target

log = logging.getLogger(__name__)

MAX_TTL_SECONDS = 24 * 3600
PROTECTABLE_KINDS = {Action.Kind.BLOCK_IP, Action.Kind.ISOLATE_HOST}
ROLLBACKABLE_KINDS = {Action.Kind.BLOCK_IP, Action.Kind.ISOLATE_HOST}


class ActionError(Exception):
    """Kod, Centrifugo RPC hata kodu olarak da kullanılır (400-1999 aralığı)."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


def _publish_after_commit(action):
    payload = realtime.action_payload(action)
    transaction.on_commit(lambda: realtime.publish(realtime.CHANNEL_ACTIONS, payload))


def _parse_ttl(params):
    raw = params.get("ttl_seconds", settings.AUTO_BLOCK_TTL_SECONDS)
    try:
        ttl = int(raw)
    except (TypeError, ValueError):
        raise ActionError(400, "ttl_seconds sayı olmalı")
    if not 1 <= ttl <= MAX_TTL_SECONDS:
        raise ActionError(400, f"ttl_seconds 1-{MAX_TTL_SECONDS} aralığında olmalı")
    return ttl


# --- Önerme ---------------------------------------------------------------


def _active_action(kind, target):
    """Aynı tür + hedef için hâlâ geçerli eylem: bekleyen öneri veya süresi dolmamış önlem."""
    now = timezone.now()
    live = Action.objects.filter(kind=kind, target=target)
    pending = live.filter(status=Action.Status.PENDING_APPROVAL).filter(
        Q(approval_deadline__isnull=True) | Q(approval_deadline__gte=now)
    )
    executed = live.filter(status=Action.Status.EXECUTED).filter(
        Q(effect_expires_at__isnull=True) | Q(effect_expires_at__gt=now)
    )
    # Kuru çalıştırmada gerçek bir etki süresi yoktur; "olsaydı" ne kadar sürerdi, TTL'e göre say.
    seconds = (settings.AUTO_BLOCK_TTL_SECONDS if kind == Action.Kind.BLOCK_IP
               else settings.APPROVAL_TTL_SECONDS)
    dry = live.filter(status=Action.Status.DRY_RUN,
                      created_at__gte=now - timedelta(seconds=seconds))
    return pending.first() or executed.first() or dry.first()


@transaction.atomic
def propose_action(event, kind, target, params=None, proposed_by="agent"):
    params = dict(params or {})
    target = str(target or "").strip()

    if kind not in Action.Kind.values:
        raise ActionError(400, f"bilinmeyen eylem türü: {kind}")
    if not target:
        raise ActionError(400, "hedef boş olamaz")

    if kind == Action.Kind.CONFIG_FIX:
        fix_id = params.get("fix_id")
        if fix_id not in settings.ALLOWED_CONFIG_FIXES:
            audit.record(proposed_by, "propose_config_fix", target, "refused",
                         reason="fix not allowlisted", fix_id=fix_id)
            raise ActionError(400, "bu düzeltme izin listesinde değil")

    event_id = getattr(event, "pk", None)

    if kind in PROTECTABLE_KINDS and is_protected_target(target):
        action = Action.objects.create(
            event=event, kind=kind, target=target, params=params,
            status=Action.Status.REFUSED, proposed_by=proposed_by,
            requires_approval=False, result={"reason": "korumalı hedef"},
        )
        audit.record(proposed_by, f"propose_{kind}", target, "refused",
                     reason="protected target", event_id=event_id, action_id=action.pk)
        _publish_after_commit(action)
        return action

    ttl = _parse_ttl(params) if kind == Action.Kind.BLOCK_IP else None

    # Sensör aynı saldırgan için her pencerede yeni olay üretir. Hedefte zaten geçerli bir
    # önlem (veya onay bekleyen öneri) varsa ikincisini açmayız.
    if kind in PROTECTABLE_KINDS:
        existing = _active_action(kind, target)
        if existing is not None:
            audit.record(proposed_by, f"propose_{kind}", target, "deduplicated",
                         event_id=event_id, action_id=existing.pk)
            return existing

    auto_eligible = (
        kind == Action.Kind.BLOCK_IP and ttl <= settings.MAX_AUTO_BLOCK_TTL_SECONDS
    )
    mode = settings.AUTO_REMEDIATION_MODE
    requires_approval = not (auto_eligible and mode in {"dry_run", "enforce"})

    now = timezone.now()
    action = Action.objects.create(
        event=event, kind=kind, target=target, params=params,
        status=Action.Status.PENDING_APPROVAL, proposed_by=proposed_by,
        requires_approval=requires_approval, ttl_seconds=ttl,
        approval_deadline=(now + timedelta(seconds=settings.APPROVAL_TTL_SECONDS))
        if requires_approval else None,
    )
    audit.record(proposed_by, f"propose_{kind}", target, "proposed",
                 event_id=event_id, action_id=action.pk,
                 requires_approval=requires_approval, mode=mode, ttl_seconds=ttl)

    if requires_approval:
        _publish_after_commit(action)
        return action
    return _execute_locked(action.pk, actor="system:auto")


# --- Uygulama -------------------------------------------------------------


def _apply(action):
    backend = get_backend()
    if action.kind == Action.Kind.BLOCK_IP:
        return backend.block_ip(action.target, action.ttl_seconds)
    if action.kind == Action.Kind.ISOLATE_HOST:
        return backend.isolate_host(action.target)
    if action.kind == Action.Kind.CONFIG_FIX:
        return backend.apply_config_fix(action.target, action.params["fix_id"], action.params)
    raise ActionError(400, f"uygulanamayan eylem türü: {action.kind}")


def _execute_locked(action_id, actor, decided_by=None):
    """Kilitli satır üzerinde uygular. Çağıran atomik blokta olmalı."""
    action = Action.objects.select_for_update().get(pk=action_id)
    if action.status != Action.Status.PENDING_APPROVAL:
        raise ActionError(409, f"eylem şu durumda uygulanamaz: {action.status}")

    now = timezone.now()
    if action.requires_approval and action.approval_deadline and action.approval_deadline < now:
        action.status = Action.Status.EXPIRED
        action.save(update_fields=["status"])
        audit.record(actor, f"execute_{action.kind}", action.target, "expired", action_id=action.pk)
        _publish_after_commit(action)
        raise ActionError(409, "onay süresi dolmuş")

    # Derinlemesine savunma: önerme anında geçse bile uygularken tekrar kontrol.
    if action.kind in PROTECTABLE_KINDS and is_protected_target(action.target):
        action.status = Action.Status.REFUSED
        action.result = {"reason": "korumalı hedef"}
        action.save(update_fields=["status", "result"])
        audit.record(actor, f"execute_{action.kind}", action.target, "refused",
                     reason="protected target", action_id=action.pk)
        _publish_after_commit(action)
        return action

    if decided_by is not None:
        action.decided_by = decided_by
        action.decided_at = now

    if settings.AUTO_REMEDIATION_MODE == "dry_run":
        action.status = Action.Status.DRY_RUN
        action.result = {"dry_run": True, "would": f"{action.kind} {action.target}"}
    else:
        try:
            action.result = _apply(action)
            action.status = Action.Status.EXECUTED
            if action.kind == Action.Kind.BLOCK_IP and action.ttl_seconds:
                action.effect_expires_at = now + timedelta(seconds=action.ttl_seconds)
        except Exception as exc:  # arka uç hatası eylemi FAILED yapar, akışı bozmaz
            log.exception("Eylem uygulanamadı: %s", action)
            action.status = Action.Status.FAILED
            action.result = {"error": str(exc)}
    action.save()
    audit.record(actor, f"execute_{action.kind}", action.target, action.status,
                 action_id=action.pk, mode=settings.AUTO_REMEDIATION_MODE)
    _publish_after_commit(action)
    return action


# --- İnsan kararı ---------------------------------------------------------


def _require_staff(user):
    if user is None or not getattr(user, "is_staff", False) or not user.is_active:
        raise ActionError(403, "yetkisiz")


@transaction.atomic
def approve_action(action_id, user):
    _require_staff(user)
    try:
        return _execute_locked(action_id, actor=f"user:{user.pk}", decided_by=user)
    except Action.DoesNotExist:
        raise ActionError(404, "eylem bulunamadı")


@transaction.atomic
def reject_action(action_id, user):
    _require_staff(user)
    try:
        action = Action.objects.select_for_update().get(pk=action_id)
    except Action.DoesNotExist:
        raise ActionError(404, "eylem bulunamadı")
    if action.status != Action.Status.PENDING_APPROVAL:
        raise ActionError(409, f"eylem şu durumda reddedilemez: {action.status}")
    action.status = Action.Status.REJECTED
    action.decided_by = user
    action.decided_at = timezone.now()
    action.save(update_fields=["status", "decided_by", "decided_at"])
    audit.record(f"user:{user.pk}", f"reject_{action.kind}", action.target, "rejected",
                 action_id=action.pk)
    _publish_after_commit(action)
    return action


# --- Geri alma ve süre dolumu --------------------------------------------


@transaction.atomic
def rollback_action(action_id, actor):
    try:
        action = Action.objects.select_for_update().get(pk=action_id)
    except Action.DoesNotExist:
        raise ActionError(404, "eylem bulunamadı")
    if action.status != Action.Status.EXECUTED or action.kind not in ROLLBACKABLE_KINDS:
        raise ActionError(409, "bu eylem geri alınamaz")
    backend = get_backend()
    try:
        if action.kind == Action.Kind.BLOCK_IP:
            result = backend.unblock_ip(action.target)
        else:
            result = backend.release_host(action.target)
    except Exception as exc:
        log.exception("Geri alma başarısız: %s", action)
        audit.record(actor, f"rollback_{action.kind}", action.target, "failed",
                     action_id=action.pk, error=str(exc))
        raise ActionError(500, "geri alma başarısız")
    action.status = Action.Status.ROLLED_BACK
    action.result = {**action.result, "rollback": result}
    action.save(update_fields=["status", "result"])
    audit.record(actor, f"rollback_{action.kind}", action.target, "rolled_back",
                 action_id=action.pk)
    _publish_after_commit(action)
    return action


def rollback_by_user(action_id, user):
    _require_staff(user)
    return rollback_action(action_id, actor=f"user:{user.pk}")


def expire_due_actions():
    """Periyodik görev: süresi dolan onayları kapat, süresi dolan engelleri kaldır."""
    now = timezone.now()
    expired = rolled_back = 0

    stale = Action.objects.filter(
        status=Action.Status.PENDING_APPROVAL, approval_deadline__lt=now
    ).values_list("pk", flat=True)
    for pk in stale:
        with transaction.atomic():
            a = Action.objects.select_for_update().get(pk=pk)
            if a.status == Action.Status.PENDING_APPROVAL:
                a.status = Action.Status.EXPIRED
                a.save(update_fields=["status"])
                audit.record("system:ttl", f"expire_{a.kind}", a.target, "expired", action_id=a.pk)
                _publish_after_commit(a)
                expired += 1

    due = Action.objects.filter(
        status=Action.Status.EXECUTED,
        kind=Action.Kind.BLOCK_IP,
        effect_expires_at__lte=now,
    ).values_list("pk", flat=True)
    for pk in due:
        try:
            rollback_action(pk, actor="system:ttl")
            rolled_back += 1
        except ActionError as exc:
            log.warning("TTL geri alması atlandı (%s): %s", pk, exc.message)

    return {"expired": expired, "rolled_back": rolled_back}
