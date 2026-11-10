from django.conf import settings
from django.db import models


class Event(models.Model):
    """Sensör katmanının eşiği aşan bir bulgusu. Agent bu olayı inceler."""

    class Level(models.TextChoices):
        LOW = "low", "Düşük"
        MEDIUM = "medium", "Orta"
        HIGH = "high", "Yüksek"

    class Status(models.TextChoices):
        NEW = "new", "Yeni"
        INVESTIGATING = "investigating", "İnceleniyor"
        RESOLVED = "resolved", "Çözüldü"
        DISMISSED = "dismissed", "Yanlış alarm"

    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    source_ip = models.GenericIPAddressField()
    target_host = models.CharField(max_length=255, blank=True)
    attack_type = models.CharField(max_length=64, default="unknown")

    # Model çıktıları (0-1). Hangi katmanın ne dediğini ayrı saklıyoruz ki
    # "XGBoost normal dedi ama Autoencoder anomali dedi" durumları görülebilsin.
    xgb_label = models.CharField(max_length=64, blank=True)
    xgb_score = models.FloatField(null=True, blank=True)
    ae_score = models.FloatField(null=True, blank=True)
    lstm_score = models.FloatField(null=True, blank=True)
    risk_score = models.FloatField()
    risk_level = models.CharField(max_length=8, choices=Level.choices)

    status = models.CharField(
        max_length=16, choices=Status.choices, default=Status.NEW, db_index=True
    )
    # GÜVENİLMEZ VERİ: akış özellikleri ve log alıntıları saldırgan kontrolünde
    # olabilir. Agent'a talimat olarak değil, veri olarak verilmelidir.
    features = models.JSONField(default=dict, blank=True)
    summary = models.TextField(blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"#{self.pk} {self.attack_type} {self.source_ip} ({self.risk_level})"


class Action(models.Model):
    """Agent'ın veya sistemin önerdiği / uyguladığı müdahale."""

    class Kind(models.TextChoices):
        BLOCK_IP = "block_ip", "IP engelle"
        ISOLATE_HOST = "isolate_host", "Host izole et"
        CONFIG_FIX = "config_fix", "Yapılandırma düzeltmesi"

    class Status(models.TextChoices):
        PENDING_APPROVAL = "pending_approval", "Onay bekliyor"
        EXECUTED = "executed", "Uygulandı"
        DRY_RUN = "dry_run", "Kuru çalıştırma (uygulanmadı)"
        REJECTED = "rejected", "Reddedildi"
        REFUSED = "refused", "Korumalı hedef, reddedildi"
        EXPIRED = "expired", "Onay süresi doldu"
        ROLLED_BACK = "rolled_back", "Geri alındı"
        FAILED = "failed", "Başarısız"

    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    event = models.ForeignKey(
        Event, null=True, blank=True, on_delete=models.SET_NULL, related_name="actions"
    )
    kind = models.CharField(max_length=16, choices=Kind.choices)
    target = models.CharField(max_length=255)
    params = models.JSONField(default=dict, blank=True)
    status = models.CharField(
        max_length=20, choices=Status.choices, db_index=True
    )
    proposed_by = models.CharField(max_length=64, default="agent")
    requires_approval = models.BooleanField(default=True)

    # Etki süresi (TTL): bittiğinde engel otomatik geri alınır.
    ttl_seconds = models.PositiveIntegerField(null=True, blank=True)
    effect_expires_at = models.DateTimeField(null=True, blank=True)
    # Onay beklerken son tarih; geçerse eylem EXPIRED olur.
    approval_deadline = models.DateTimeField(null=True, blank=True)

    decided_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="+",
    )
    decided_at = models.DateTimeField(null=True, blank=True)
    result = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"#{self.pk} {self.kind} {self.target} [{self.status}]"


class AuditLog(models.Model):
    """Kim, neyi, ne zaman, hangi sonuçla yaptı. Reddedilen denemeler de yazılır."""

    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    actor = models.CharField(max_length=128)
    verb = models.CharField(max_length=64)
    target = models.CharField(max_length=255, blank=True)
    outcome = models.CharField(max_length=32)
    detail = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.created_at:%Y-%m-%d %H:%M:%S} {self.actor} {self.verb} {self.target} -> {self.outcome}"
