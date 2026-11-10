"""Müdahale arka uçları.

İlk sürümde yalnızca LogOnlyBackend var: hiçbir şeyi gerçekten değiştirmez.
Gerçek uygulama (örn. lab ağ geçidinde iptables/nftables) ayrı bir sınıf olarak
eklenip FIREWALL_BACKEND ile seçilecek. Böylece politika, onay ve denetim
akışı güvenlik duvarına dokunmadan uçtan uca test edilebilir.
"""

import logging

from django.conf import settings
from django.utils.module_loading import import_string

log = logging.getLogger(__name__)


class FirewallBackend:
    def block_ip(self, ip, ttl_seconds) -> dict:
        raise NotImplementedError

    def unblock_ip(self, ip) -> dict:
        raise NotImplementedError

    def isolate_host(self, host) -> dict:
        raise NotImplementedError

    def release_host(self, host) -> dict:
        raise NotImplementedError

    def apply_config_fix(self, host, fix_id, params) -> dict:
        raise NotImplementedError


class LogOnlyBackend(FirewallBackend):
    """Sadece loglar; sistemde hiçbir değişiklik yapmaz."""

    def _noop(self, what, **kw):
        log.info("LogOnlyBackend: %s %s", what, kw)
        return {"applied": False, "note": "gerçek güvenlik duvarı arka ucu yapılandırılmadı", "op": what, **kw}

    def block_ip(self, ip, ttl_seconds):
        return self._noop("block_ip", ip=ip, ttl_seconds=ttl_seconds)

    def unblock_ip(self, ip):
        return self._noop("unblock_ip", ip=ip)

    def isolate_host(self, host):
        return self._noop("isolate_host", host=host)

    def release_host(self, host):
        return self._noop("release_host", host=host)

    def apply_config_fix(self, host, fix_id, params):
        return self._noop("apply_config_fix", host=host, fix_id=fix_id)


def get_backend() -> FirewallBackend:
    return import_string(settings.FIREWALL_BACKEND)()
