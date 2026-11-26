"""Bilinen kötü amaçlı IP kontrolü (statik liste).

Burada yapılan şey: THREAT_INTEL_BAD_IPS içindeki adres/ağlarla olayın kaynak
IP'sini karşılaştırmak. Yalnızca onay kartında ek bir ipucu göstermek için;
hiçbir eylemi engellemez ya da otomatik onaylamaz (karar yine politika
katmanında). Canlı besleme (CISA KEV/EPSS, abuse.ch vb.) ve otomatik
güncelleme sonraki bir aşama; bu yalnızca elle girilen, çevrimdışı bir liste.

protection.py'deki korumalı hedef kontrolünün tersine bu liste
bilgilendiricidir: ayrıştırılamayan ya da boş bir girdi güvenlik kararını
etkilemediği için sessizce atlanır (fail-open), fail-closed değil.
"""

import ipaddress

from django.conf import settings


def _bad_networks():
    nets = []
    for raw in settings.THREAT_INTEL_BAD_IPS:
        raw = raw.strip()
        if not raw:
            continue
        try:
            nets.append(ipaddress.ip_network(raw, strict=False))
        except ValueError:
            continue
    return nets


def is_known_bad_ip(ip) -> bool:
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    return any(addr in net for net in _bad_networks())
