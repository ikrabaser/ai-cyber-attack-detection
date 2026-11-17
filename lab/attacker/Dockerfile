# Saldırgan: nmap ve Hydra yalnızca bu konteynerde durur, ana makineye kurulmaz.
FROM debian:12-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap hydra python3 iputils-ping \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /lab
COPY common/runlog.py /lab/runlog.py
COPY common/netguard.py /lab/netguard.py
COPY attacker/attack.py /lab/attack.py
COPY attacker/wordlist.txt /lab/wordlist.txt
# Windows'ta CRLF'li gelirse parola listesi bozulmasın.
RUN sed -i 's/\r$//' /lab/wordlist.txt
