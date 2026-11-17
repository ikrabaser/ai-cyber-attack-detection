"""Hedef koruması: koşu betikleri yalnızca özel (RFC 1918) adreslere trafik üretir.

Konteynerler zaten internete çıkamayan bir ağdadır; bu, yanlış yazılmış bir adrese karşı ikinci güvenlik
katmanıdır.
"""

import ipaddress


def require_private(target):
    try:
        addr = ipaddress.ip_address(target)
    except ValueError:
        raise ValueError(f"hedef bir IP adresi olmalı: {target!r}") from None
    if addr.version != 4 or not addr.is_private or addr.is_loopback:
        raise ValueError(f"hedef özel bir IPv4 adresi olmalı (lab ağı): {target}")
    return str(addr)
