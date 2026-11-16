"""ipp_mini.py reads and builds small IPP printer messages. IPP is the
network language printers and computers use to talk to each other. This is
not a full IPP library, just enough for our two tools to work."""
import struct
import socket as _socket

# a few IPP request types we need to recognize
OP_PRINT_JOB = 0x0002
OP_VALIDATE_JOB = 0x0004
OP_GET_JOB_ATTRIBUTES = 0x0009
OP_GET_PRINTER_ATTRIBUTES = 0x000B

OPERATION_NAMES = {
    0x0002: "Print-Job",
    0x0003: "Print-URI",
    0x0004: "Validate-Job",
    0x0005: "Create-Job",
    0x0006: "Send-Document",
    0x0008: "Cancel-Job",
    0x0009: "Get-Job-Attributes",
    0x000A: "Get-Jobs",
    0x000B: "Get-Printer-Attributes",
}

STATUS_SUCCESSFUL_OK = 0x0000

# attribute value tags we use
TAG_INTEGER = 0x21
TAG_BOOLEAN = 0x22
TAG_ENUM = 0x23
TAG_URI = 0x45
TAG_KEYWORD = 0x44
TAG_NAME_WITHOUT_LANGUAGE = 0x42
TAG_TEXT_WITHOUT_LANGUAGE = 0x41
TAG_CHARSET = 0x47
TAG_NATURAL_LANGUAGE = 0x48
TAG_MIME_MEDIA_TYPE = 0x49

TAG_OPERATION_ATTRIBUTES = 0x01
TAG_PRINTER_ATTRIBUTES = 0x02
TAG_END_OF_ATTRIBUTES = 0x03


class ParsedIppRequest:
    def __init__(self, version, operation_id, request_id, raw):
        self.version = version
        self.operation_id = operation_id
        self.request_id = request_id
        self.raw = raw

    @property
    def operation_name(self):
        return OPERATION_NAMES.get(self.operation_id, "0x%04x" % self.operation_id)

    def __repr__(self):
        return "<IPP %s req_id=%d version=%d.%d %dB>" % (
            self.operation_name, self.request_id,
            self.version[0], self.version[1], len(self.raw),
        )


def parse_ipp_request(data: bytes):
    """Reads the start of an IPP request. Returns nothing if the data
    does not look like IPP at all."""
    if len(data) < 8:
        return None
    ver_major, ver_minor, op_id, req_id = struct.unpack(">BBHI", data[0:8])
    if ver_major not in (1, 2):
        return None
    return ParsedIppRequest((ver_major, ver_minor), op_id, req_id, data)


def _encode_attr(tag: int, name: str, value) -> bytes:
    """value can be plain bytes for one value, or a list of bytes for
    many values."""
    values = value if isinstance(value, (list, tuple)) else [value]
    out = bytearray()
    name_b = name.encode("utf-8")
    for i, v in enumerate(values):
        n = name_b if i == 0 else b""
        out += struct.pack(">B H", tag, len(n)) + n + struct.pack(">H", len(v)) + v
    return bytes(out)


def build_get_printer_attributes_response(request_id: int, extra_attrs=None) -> bytes:
    """Builds a normal, valid reply to a printer details request.

    extra_attrs lets the caller add extra fields to the reply, which is
    how our tools add a marker, or in the full public demo, a hidden
    command.
    """
    out = bytearray()
    out += struct.pack(">BB", 1, 1)                 # IPP version 1.1
    out += struct.pack(">H", STATUS_SUCCESSFUL_OK)  # status-code
    out += struct.pack(">I", request_id)            # request-id (echoed)

    out += bytes([TAG_OPERATION_ATTRIBUTES])
    out += _encode_attr(TAG_CHARSET, "attributes-charset", b"utf-8")
    out += _encode_attr(TAG_NATURAL_LANGUAGE, "attributes-natural-language", b"en")

    out += bytes([TAG_PRINTER_ATTRIBUTES])
    defaults = [
        (TAG_URI, "printer-uri-supported", b"ipp://10.13.37.20:631/printers/legit"),
        (TAG_KEYWORD, "uri-authentication-supported", b"none"),
        (TAG_KEYWORD, "uri-security-supported", b"none"),
        (TAG_NAME_WITHOUT_LANGUAGE, "printer-name", b"Legit Printer"),
        (TAG_TEXT_WITHOUT_LANGUAGE, "printer-info", b"Scapy Lab Virtual Printer"),
        (TAG_TEXT_WITHOUT_LANGUAGE, "printer-make-and-model", b"Scapy Lab Virtual Printer"),
        (TAG_ENUM, "printer-state", struct.pack(">i", 3)),       # idle
        (TAG_KEYWORD, "printer-state-reasons", b"none"),
        (TAG_KEYWORD, "ipp-versions-supported", b"1.1"),
        (TAG_MIME_MEDIA_TYPE, "document-format-default", b"application/pdf"),
        (TAG_MIME_MEDIA_TYPE, "document-format-supported", b"application/pdf"),
        (TAG_BOOLEAN, "multiple-document-jobs-supported", b"\x00"),
        (TAG_BOOLEAN, "printer-is-accepting-jobs", b"\x01"),
        (TAG_INTEGER, "queued-job-count", struct.pack(">i", 0)),
        (TAG_INTEGER, "printer-up-time", struct.pack(">i", 3600)),
        (TAG_KEYWORD, "compression-supported", b"none"),
        (TAG_KEYWORD, "pdl-override-supported", b"not-attempted"),
        (TAG_CHARSET, "charset-configured", b"utf-8"),
        (TAG_CHARSET, "charset-supported", b"utf-8"),
        (TAG_NATURAL_LANGUAGE, "natural-language-configured", b"en"),
        (TAG_NATURAL_LANGUAGE, "generated-natural-language-supported", b"en"),
        (TAG_ENUM, "operations-supported", [
            struct.pack(">i", op) for op in (
                OP_PRINT_JOB, OP_VALIDATE_JOB, 0x0008,  # Cancel-Job
                OP_GET_JOB_ATTRIBUTES, OP_GET_PRINTER_ATTRIBUTES,
            )
        ]),
    ]
    for tag, name, value in defaults:
        out += _encode_attr(tag, name, value)
    for tag, name, value in (extra_attrs or []):
        out += _encode_attr(tag, name, value)

    out += bytes([TAG_END_OF_ATTRIBUTES])
    return bytes(out)


# CUPS always wraps its printer messages inside a normal web request, so we
# need to read and write just enough of that web format too.

def recv_http_ipp_request(conn: "_socket.socket", timeout: float = 5.0):
    """Reads one web request from conn and returns its request line,
    headers, and body. Returns nothing if the connection closes early."""
    conn.settimeout(timeout)
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = conn.recv(65536)
        if not chunk:
            return None
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    request_line = lines[0]
    headers = {}
    for line in lines[1:]:
        if b":" in line:
            k, v = line.split(b":", 1)
            headers[k.strip().lower()] = v.strip()

    content_length = int(headers.get(b"content-length", b"0") or b"0")
    if headers.get(b"expect", b"").lower() == b"100-continue" and len(rest) < content_length:
        conn.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")

    body = rest
    while len(body) < content_length:
        chunk = conn.recv(65536)
        if not chunk:
            break
        body += chunk
    return request_line, headers, body


def build_http_ipp_response(ipp_body: bytes) -> bytes:
    headers = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/ipp\r\n"
        b"Content-Length: " + str(len(ipp_body)).encode() + b"\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )
    return headers + ipp_body
