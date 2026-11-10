"""Olay inceleme katmanı.

`investigate(event)` arayüzü sabit; arkasındaki uygulama AGENT_BACKEND ile seçilir.

RuleAgent, Claude agent bağlanana kadar boru hattını uçtan uca denemek için
kullanılan, deterministik bir yer tutucudur: LLM çağırmaz, sadece risk
düzeyine göre bir eylem önerir. Önerilen eylem yine politika katmanından
(core.actions) geçer: korumalı IP, kademe, onay, TTL.

Claude agent eklendiğinde dikkat:
- event.features, event.summary ve log alıntıları SALDIRGAN KONTROLÜNDE olabilir.
  Agent'a talimat olarak değil, işaretlenmiş veri bölümü olarak ver.
- Agent'ın araçları yalnızca core.actions.propose_action gibi politika
  katmanından geçen fonksiyonlar olmalı; güvenlik duvarına doğrudan erişim yok.
"""

from django.conf import settings
from django.utils.module_loading import import_string

from . import actions
from .models import Action, Event


class RuleAgent:
    name = "rule-agent"

    def investigate(self, event: Event) -> str:
        if event.risk_level in {Event.Level.MEDIUM, Event.Level.HIGH}:
            action = actions.propose_action(
                event,
                Action.Kind.BLOCK_IP,
                event.source_ip,
                params={"ttl_seconds": settings.AUTO_BLOCK_TTL_SECONDS},
                proposed_by=self.name,
            )
            return (
                f"{event.attack_type} şüphesi, risk {event.risk_score:.2f} ({event.risk_level}). "
                f"Öneri: {event.source_ip} için TTL'li engel -> {action.get_status_display()}."
            )
        return (
            f"{event.attack_type} şüphesi, risk {event.risk_score:.2f} (düşük). "
            "Eylem önerilmedi, izlemeye devam."
        )


def get_agent():
    return import_string(settings.AGENT_BACKEND)()
