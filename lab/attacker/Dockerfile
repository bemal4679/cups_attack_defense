FROM kalilinux/kali-rolling
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-pip python3-venv \
      tcpdump iproute2 iputils-ping netcat-traditional \
    && rm -rf /var/lib/apt/lists/*
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir scapy==2.5.0
ENV PATH="/opt/venv/bin:${PATH}"
WORKDIR /lab
ENTRYPOINT ["sleep", "infinity"]
