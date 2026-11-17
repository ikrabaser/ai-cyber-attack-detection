# Normal trafik üreticisi: web istekleri ve ara sıra gerçek bir SSH girişi.
FROM debian:12-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 openssh-client sshpass iputils-ping \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /lab
COPY common/runlog.py /lab/runlog.py
COPY common/netguard.py /lab/netguard.py
COPY normal/normal_traffic.py /lab/normal_traffic.py
