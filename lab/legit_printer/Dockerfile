FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends tcpdump \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /printer
COPY lab/legit_printer/legit_ipp_printer.py /printer/legit_ipp_printer.py
COPY ipp_mini.py /lab/ipp_mini.py
COPY browse_proto.py /lab/browse_proto.py
ENTRYPOINT ["python3", "/printer/legit_ipp_printer.py"]
