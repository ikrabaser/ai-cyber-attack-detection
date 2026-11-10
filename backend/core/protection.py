"""Korumalı hedefler.

Ağ geçidi, DNS, sensör ve yönetici makinesi gibi hedefler hiçbir koşulda
engellenmez veya izole edilmez. Bu kontrol agent'ın içinde DEĞİL, eylem
kodunun içindedir: agent yanılsa ya da loglara gömülmüş bir metinle
kandırılsa bile kural çalışır.

Güvenli varsayılan: ayrıştırılamayan bir IP "korumalı" sayılır (fail-closed).
"""

import ipaddress

from django.conf import settings


def _protected_networks():
    nets = []
    for raw in settings.PROTECTED_IPS:
        try:
            nets.append(ipaddress.ip_network(raw, strict=False))
        except ValueError:
            # Yapılandırma hatası sessizce yutulmasın.
            raise ValueError(f"PROTECTED_IPS içinde geçersiz değer: {raw!r}")
    return nets


def is_protected_ip(ip) -> bool:
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return True  # fail-closed
    # Bu adresler hiçbir zaman engelleme hedefi olmamalı.
    if addr.is_loopback or addr.is_unspecified or addr.is_multicast:
        return True
    return any(addr in net for net in _protected_networks())


def is_protected_target(target) -> bool:
    """IP ya da host adı olabilen bir hedef için kontrol."""
    value = str(target).strip()
    try:
        ipaddress.ip_address(value)
    except ValueError:
        # Host adı: PROTECTED_HOSTS listesinde mi?
        hosts = {h.lower() for h in settings.PROTECTED_HOSTS}
        return value.lower() in hosts
    return is_protected_ip(value)
