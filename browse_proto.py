"""browse_proto.py builds and reads the old printer message format that
cups browsed still trusts without checking who sent it."""


def build_browse_message(printer_type: int, printer_state: int, printer_uri: str,
                          location: str, info: str) -> bytes:
    """Builds a normal, correctly written printer message."""
    msg = '%x %x %s "%s" "%s"' % (printer_type, printer_state, printer_uri, location, info)
    return msg.encode("utf-8")


import re  # noqa: E402

BROWSE_RE = re.compile(
    rb'^([0-9A-Fa-f]{1,8})\s+([0-9A-Fa-f]{1,8})\s+(\S+)\s+"([^"]*)"\s+"([^"]*)"\s*$'
)


def parse_browse_message(payload: bytes):
    """Returns the fields of the message if it is written correctly,
    otherwise returns nothing."""
    m = BROWSE_RE.match(payload)
    if not m:
        return None
    ptype, pstate, uri, location, info = m.groups()
    return {
        "type": ptype.decode(errors="replace"),
        "state": pstate.decode(errors="replace"),
        "printer_uri": uri.decode(errors="replace"),
        "location": location.decode(errors="replace"),
        "info": info.decode(errors="replace"),
    }
