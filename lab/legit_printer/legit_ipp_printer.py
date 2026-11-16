#!/usr/bin/env python3
"""legit_ipp_printer.py acts like a normal, honest printer. It is used to
make normal traffic for the detector to check against, not part of the
graded attack or detection tools."""
import argparse
import logging
import socket
import sys
import threading
import time

sys.path.insert(0, "/lab")
from browse_proto import build_browse_message   # noqa: E402
from ipp_mini import (  # noqa: E402
    parse_ipp_request, build_get_printer_attributes_response,
    recv_http_ipp_request, build_http_ipp_response,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [legit printer] %(message)s")
log = logging.getLogger("legit_printer")


def ipp_server(bind_ip: str, port: int):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((bind_ip, port))
    srv.listen(5)
    log.info("listening on %s:%d", bind_ip, port)
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle_ipp_conn, args=(conn, addr), daemon=True).start()


def handle_ipp_conn(conn, addr):
    try:
        parsed = recv_http_ipp_request(conn)
        if not parsed:
            log.info("connection from %s closed early", addr)
            return
        _request_line, _headers, body = parsed
        req = parse_ipp_request(body)
        if req:
            log.info("request from %s: %s", addr, req)
            ipp_resp = build_get_printer_attributes_response(req.request_id)
            conn.sendall(build_http_ipp_response(ipp_resp))
        else:
            log.info("not an IPP request from %s (%d bytes)", addr, len(body))
    except Exception as exc:
        log.warning("error with connection from %s: %s", addr, exc)
    finally:
        conn.close()


def browse_announcer(target_ip: str, target_port: int, self_ip: str, interval: float):
    uri = "ipp://%s:631/printers/legit" % self_ip
    while True:
        msg = build_browse_message(0x0, 0x3, uri, "Office HQ", "Scapy Lab Virtual Printer (legit)")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.sendto(msg, (target_ip, target_port))
            log.info("sent a normal message to %s:%d about %s", target_ip, target_port, uri)
        finally:
            sock.close()
        time.sleep(interval)


def main():
    ap = argparse.ArgumentParser(description="A fake, but honest, printer used for normal traffic")
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=631)
    ap.add_argument("--self-ip", default="10.13.37.20")
    ap.add_argument("--target-ip", default="10.13.37.10", help="address of the victim to tell about this printer")
    ap.add_argument("--target-port", type=int, default=631)
    ap.add_argument("--announce-interval", type=float, default=10.0)
    args = ap.parse_args()

    t = threading.Thread(target=browse_announcer, args=(
        args.target_ip, args.target_port, args.self_ip, args.announce_interval
    ), daemon=True)
    t.start()
    ipp_server(args.bind, args.port)


if __name__ == "__main__":
    main()
