#!/bin/sh
# SSH sunucusunu arka planda, web sunucusunu ön planda çalıştırır (konteyner nginx ile yaşar).
set -e
ssh-keygen -A
/usr/sbin/sshd
exec nginx -g 'daemon off;'
