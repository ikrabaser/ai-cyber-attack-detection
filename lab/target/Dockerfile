# Saldırı hedefi: SSH ve web. Zayıf parolalı bir test kullanıcısı bilerek vardır (yalnızca izole lab ağında).
FROM debian:12-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-server nginx \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd \
    && useradd -m -s /bin/bash labuser \
    && echo 'labuser:lab123' | chpasswd
COPY target/entrypoint.sh /entrypoint.sh
RUN sed -i 's/\r$//' /entrypoint.sh && chmod +x /entrypoint.sh
EXPOSE 22 80
ENTRYPOINT ["/entrypoint.sh"]
