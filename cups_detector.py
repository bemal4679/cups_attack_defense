#!/usr/bin/env python3
"""cups_detector.py looks for the fake printer attack in a saved pcap file
or in live traffic. Built with Scapy."""
import argparse
import csv
import ipaddress
import json
import logging
import sys
import time
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from typing import Optional

from scapy.all import rdpcap, sniff, IP, TCP, UDP, Raw  # type: ignore

from browse_proto import parse_browse_message
from ipp_mini import parse_ipp_request

log = logging.getLogger("cups_detector")

MAX_REASONABLE_FIELD_LEN = 512   # a location or info field longer than this counts as too long
BROWSE_LIKE_MIN_LEN = 4


@dataclass
class Alert:
    timestamp: float
    category: str
    severity: str
    src_ip: str
    dst_ip: str
    dst_port: int
    detail: str


class SlidingWindowCounter:
    """Counts how many times each sender shows up in a short time window."""
    def __init__(self, window_seconds: float):
        self.window = window_seconds
        self.hits = defaultdict(deque)

    def add(self, key, ts: float) -> int:
        dq = self.hits[key]
        dq.append(ts)
        cutoff = ts - self.window
        while dq and dq[0] < cutoff:
            dq.popleft()
        return len(dq)


class CupsDetector:
    def __init__(self, allowlist, browse_port: int, ipp_ports, flood_threshold: int,
                 flood_window: float):
        self.allowlist = set(allowlist)
        self.browse_port = browse_port
        self.ipp_ports = set(ipp_ports)
        self.flood_threshold = flood_threshold
        self.counter = SlidingWindowCounter(flood_window)
        self.alerts = []
        self.stats = defaultdict(int)

    def is_allowlisted(self, ip: str) -> bool:
        if not self.allowlist:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for entry in self.allowlist:
            try:
                if "/" in entry:
                    if addr in ipaddress.ip_network(entry, strict=False):
                        return True
                elif addr == ipaddress.ip_address(entry):
                    return True
            except ValueError:
                continue
        return False

    def _raise(self, ts, category, severity, src, dst, dport, detail):
        a = Alert(ts, category, severity, src, dst, dport, detail)
        self.alerts.append(a)
        self.stats[category] += 1
        log.warning("[%s/%s] %s to %s:%d : %s", severity.upper(), category, src, dst, dport, detail)

    def handle_packet(self, pkt):
        self.stats["packets_seen"] += 1
        if not pkt.haslayer(IP):
            return
        ts = float(pkt.time) if hasattr(pkt, "time") else time.time()
        src = pkt[IP].src
        dst = pkt[IP].dst

        if pkt.haslayer(UDP) and pkt.haslayer(Raw):
            udp = pkt[UDP]
            if udp.dport == self.browse_port:
                self._analyze_browse_udp(ts, src, dst, udp.dport, bytes(pkt[Raw].load))
            return

        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            tcp = pkt[TCP]
            if tcp.dport in self.ipp_ports or tcp.sport in self.ipp_ports:
                self._analyze_ipp_tcp(ts, src, dst, tcp.sport, tcp.dport, bytes(pkt[Raw].load))

    def _analyze_browse_udp(self, ts, src, dst, dport, payload: bytes):
        self.stats["browse_packets"] += 1

        count = self.counter.add(src, ts)
        if count > self.flood_threshold:
            self._raise(ts, "discovery_flood", "medium", src, dst, dport,
                        "%d browse messages from %s in the last %.0f seconds (limit %d)"
                        % (count, src, self.counter.window, self.flood_threshold))

        parsed = parse_browse_message(payload)
        if parsed is None:
            if len(payload) >= BROWSE_LIKE_MIN_LEN and self._looks_browse_ish(payload):
                self._raise(ts, "malformed_packet", "high", src, dst, dport,
                            "this looks like a printer message on port %d but it is written wrong: %r"
                            % (dport, payload[:120]))
            return

        oversized = [k for k in ("location", "info") if len(parsed[k]) > MAX_REASONABLE_FIELD_LEN]
        if oversized:
            self._raise(ts, "malformed_packet", "medium", src, dst, dport,
                        "field(s) %s are too long in an otherwise normal message (address %s)"
                        % (oversized, parsed["printer_uri"]))

        if not self.is_allowlisted(src):
            self._raise(ts, "unauthorized_advertisement", "high", src, dst, dport,
                        "a printer message came from an address not on the trusted list, "
                        "it claims to be printer address %s" % parsed["printer_uri"])
        else:
            self.stats["allowlisted_advertisements"] += 1

    @staticmethod
    def _looks_browse_ish(payload: bytes) -> bool:
        # A simple check for whether this payload was clearly trying to be a
        # printer message, even if it is written wrong. A printer address
        # inside the text is the strongest clue, so that is checked first.
        if b"://" in payload:
            return True
        head = payload[:8].decode(errors="replace")
        hexy = any(c in "0123456789abcdefABCDEF" for c in head[:2])
        return hexy and b'"' in payload

    def _analyze_ipp_tcp(self, ts, src, dst, sport, dport, payload: bytes):
        # CUPS sends its printer requests wrapped inside a normal web request.
        # Try to unwrap that first, then fall back to reading it plain.
        body = payload
        if payload[:4] in (b"POST", b"GET ", b"HTTP"):
            _head, _, rest = payload.partition(b"\r\n\r\n")
            body = rest if rest else payload
        req = parse_ipp_request(body)
        if req is None:
            return
        self.stats["ipp_requests"] += 1

        # Figure out which side is the printer and which side is the
        # computer asking for printer details. Only the printer side needs
        # to be on the trusted list.
        if dport in self.ipp_ports:
            printer_ip, client_ip = dst, src
        elif sport in self.ipp_ports:
            printer_ip, client_ip = src, dst
        else:
            printer_ip, client_ip = dst, src

        printer_trusted = self.is_allowlisted(printer_ip)
        severity = "low" if printer_trusted else "high"
        category = "suspicious_ipp_callback"
        detail = "request %s (id %d) from %s to printer %s:%d" % (
            req.operation_name, req.request_id, client_ip, printer_ip, dport if dport in self.ipp_ports else sport,
        )
        if not printer_trusted:
            self._raise(ts, category, severity, src, dst, dport, detail)
        else:
            self.stats["allowlisted_ipp"] += 1


def export_csv(alerts, path):
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["timestamp", "category", "severity", "src_ip", "dst_ip", "dst_port", "detail"])
        for a in alerts:
            w.writerow([a.timestamp, a.category, a.severity, a.src_ip, a.dst_ip, a.dst_port, a.detail])


def export_json(alerts, stats, path):
    with open(path, "w") as f:
        json.dump({
            "stats": dict(stats),
            "alert_count": len(alerts),
            "alerts": [asdict(a) for a in alerts],
        }, f, indent=2)


def parse_args(argv=None):
    ap = argparse.ArgumentParser(description="Look for the fake printer attack in network traffic")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--pcap", help="a saved pcap file to check")
    src.add_argument("--iface", help="a network interface to watch live")

    ap.add_argument("--duration", type=float, default=30.0, help="how many seconds to watch live traffic")
    ap.add_argument("--browse-port", type=int, default=631)
    ap.add_argument("--ipp-ports", default="631", help="comma separated list of ports to check for printer requests")
    ap.add_argument("--allowlist", default="", help="comma separated list of trusted addresses")
    ap.add_argument("--allowlist-file", default=None, help="file with one trusted address per line")
    ap.add_argument("--flood-threshold", type=int, default=5, help="how many messages from one sender counts as too many")
    ap.add_argument("--flood-window", type=float, default=30.0)

    ap.add_argument("--out-csv", default=None)
    ap.add_argument("--out-json", default=None)
    ap.add_argument("--log-file", default=None)
    ap.add_argument("-v", "--verbose", action="store_true")
    return ap.parse_args(argv)


def setup_logging(args):
    level = logging.DEBUG if args.verbose else logging.INFO
    handlers = [logging.StreamHandler(sys.stdout)]
    if args.log_file:
        handlers.append(logging.FileHandler(args.log_file))
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(message)s", handlers=handlers)


def load_allowlist(args):
    entries = [e.strip() for e in args.allowlist.split(",") if e.strip()]
    if args.allowlist_file:
        with open(args.allowlist_file) as f:
            entries += [line.strip() for line in f if line.strip() and not line.startswith("#")]
    return entries


def main():
    args = parse_args()
    setup_logging(args)

    ipp_ports = [int(p) for p in args.ipp_ports.split(",") if p.strip()]
    allowlist = load_allowlist(args)
    log.info("trusted addresses: %s", allowlist or "(none set, everything will be flagged)")

    detector = CupsDetector(
        allowlist=allowlist,
        browse_port=args.browse_port,
        ipp_ports=ipp_ports,
        flood_threshold=args.flood_threshold,
        flood_window=args.flood_window,
    )

    if args.pcap:
        log.info("reading pcap file: %s", args.pcap)
        packets = rdpcap(args.pcap)
        for pkt in packets:
            detector.handle_packet(pkt)
    else:
        bpf = "udp port %d or (%s)" % (
            args.browse_port, " or ".join("tcp port %d" % p for p in ipp_ports)
        )
        log.info("watching %s for %.0f seconds, filter: %s", args.iface, args.duration, bpf)
        sniff(iface=args.iface, filter=bpf, timeout=args.duration, prn=detector.handle_packet, store=False)

    log.info("done. packets seen %d, browse messages %d, ipp requests %d, alerts %d",
             detector.stats.get("packets_seen", 0), detector.stats.get("browse_packets", 0),
             detector.stats.get("ipp_requests", 0), len(detector.alerts))

    if args.out_csv:
        export_csv(detector.alerts, args.out_csv)
        log.info("wrote %d alerts to %s", len(detector.alerts), args.out_csv)
    if args.out_json:
        export_json(detector.alerts, detector.stats, args.out_json)
        log.info("wrote a JSON report to %s", args.out_json)

    if not args.out_csv and not args.out_json:
        for a in detector.alerts:
            print(json.dumps(asdict(a)))


if __name__ == "__main__":
    main()
