from django.contrib import admin

from .models import Action, AuditLog, Event


@admin.register(Event)
class EventAdmin(admin.ModelAdmin):
    list_display = ("id", "created_at", "source_ip", "attack_type", "risk_score", "risk_level", "status")
    list_filter = ("risk_level", "status", "attack_type")
    search_fields = ("source_ip", "target_host", "summary")


@admin.register(Action)
class ActionAdmin(admin.ModelAdmin):
    list_display = ("id", "created_at", "kind", "target", "status", "proposed_by", "requires_approval")
    list_filter = ("kind", "status")
    search_fields = ("target",)
    # Durum değişiklikleri yalnızca politika katmanından (core.actions) yapılır.
    readonly_fields = [f.name for f in Action._meta.fields]

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ("created_at", "actor", "verb", "target", "outcome")
    list_filter = ("outcome", "verb")
    search_fields = ("actor", "target")
    readonly_fields = [f.name for f in AuditLog._meta.fields]

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
