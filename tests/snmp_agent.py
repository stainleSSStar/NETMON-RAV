"""Minimal SNMP v1/v2c test agent for NetMon development.

Speaks just enough SNMP (GET / GETNEXT / GETBULK over UDP) to exercise the
poller, the OID browser and the charts without real network equipment.
Counters increase on every read so charts show movement.

    python3 tests/snmp_agent.py [--port 1161] [--community public]

Serves a small subset of IF-MIB / SNMPv2-MIB.
"""
import argparse
import socket
import sys
import threading
import time

START = time.time()

# oid -> (kind, value) where kind in {"str", "int", "ticks", "counter", "gauge", "counter64"}
MIB = {
    "1.3.6.1.2.1.1.1.0": ("str", "NetMon test agent (mini-snmp)"),
    "1.3.6.1.2.1.1.3.0": ("ticks", lambda: int((time.time() - START) * 100)),
    "1.3.6.1.2.1.1.4.0": ("str", "lab admin"),
    "1.3.6.1.2.1.1.5.0": ("str", "netmon-test"),
    "1.3.6.1.2.1.1.6.0": ("str", "test rack"),
    "1.3.6.1.2.1.2.1.0": ("int", 3),
    "1.3.6.1.2.1.2.2.1.1.1": ("int", 1),
    "1.3.6.1.2.1.2.2.1.1.2": ("int", 2),
    "1.3.6.1.2.1.2.2.1.1.3": ("int", 3),
    "1.3.6.1.2.1.2.2.1.2.1": ("str", "lo"),
    "1.3.6.1.2.1.2.2.1.2.2": ("str", "eth0"),
    "1.3.6.1.2.1.2.2.1.2.3": ("str", "eth1"),
    "1.3.6.1.2.1.2.2.1.8.1": ("int", 1),
    "1.3.6.1.2.1.2.2.1.8.2": ("int", 1),
    "1.3.6.1.2.1.2.2.1.8.3": ("int", 2),
    "1.3.6.1.2.1.2.2.1.10.1": ("counter", lambda: int((time.time() - START) * 1000)),
    "1.3.6.1.2.1.2.2.1.10.2": ("counter", lambda: int((time.time() - START) * 250)),
    "1.3.6.1.2.1.2.2.1.10.3": ("counter", lambda: 42),
    "1.3.6.1.2.1.2.2.1.16.1": ("counter", lambda: int((time.time() - START) * 800)),
    "1.3.6.1.2.1.2.2.1.16.2": ("counter", lambda: int((time.time() - START) * 400)),
    "1.3.6.1.2.1.2.2.1.16.3": ("counter", lambda: 7),
    "1.3.6.1.2.1.31.1.1.1.6.1": ("counter64", lambda: int((time.time() - START) * 100000)),
    "1.3.6.1.2.1.31.1.1.1.6.2": ("counter64", lambda: int((time.time() - START) * 50000)),
}

SORTED_OIDS = sorted(MIB, key=lambda o: tuple(int(p) for p in o.split(".")))


# ------------------------------------------------------------------ BER codec
def enc_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def tlv(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + enc_len(len(payload)) + payload


def enc_int(value: int) -> bytes:
    if value == 0:
        return tlv(0x02, b"\x00")
    length = (value.bit_length() // 8) + 1
    return tlv(0x02, value.to_bytes(length, "big", signed=True))


def enc_octet(value: str) -> bytes:
    return tlv(0x04, value.encode())


def enc_oid(dotted: str) -> bytes:
    parts = [int(p) for p in dotted.split(".")]
    body = bytes([parts[0] * 40 + parts[1]])
    for part in parts[2:]:
        if part == 0:
            body += b"\x00"
            continue
        stack = []
        while part:
            stack.append(part & 0x7F)
            part >>= 7
        stack.reverse()
        body += bytes([0x80 | b for b in stack[:-1]]) + bytes([stack[-1]])
    return tlv(0x06, body)


def enc_null() -> bytes:
    return tlv(0x05, b"")


def enc_uint(tag: int, value: int, size: int) -> bytes:
    return tlv(tag, value.to_bytes(size, "big"))


def enc_value(oid: str) -> bytes:
    entry = MIB.get(oid)
    if entry is None:
        return tlv(0x80, b"")  # noSuchObject
    kind, raw = entry
    value = raw() if callable(raw) else raw
    if kind == "str":
        return enc_octet(str(value))
    if kind == "int":
        return enc_int(int(value))
    if kind == "ticks":
        return enc_uint(0x43, int(value), 4)
    if kind == "counter":
        return enc_uint(0x41, int(value), 4)
    if kind == "gauge":
        return enc_uint(0x42, int(value), 4)
    if kind == "counter64":
        return enc_uint(0x46, int(value), 8)
    raise ValueError(kind)


def read_tlv(data: bytes, offset: int):
    tag = data[offset]
    offset += 1
    length = data[offset]
    offset += 1
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(data[offset:offset + count], "big")
        offset += count
    return tag, data[offset:offset + length], offset + length


def decode_oid(payload: bytes) -> str:
    first = payload[0]
    parts = [first // 40, first % 40]
    value = 0
    for byte in payload[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(value)
            value = 0
    return ".".join(str(p) for p in parts)


def parse_message(data: bytes):
    _tag, seq, _ = read_tlv(data, 0)
    offset = 0
    _t, version_b, offset = read_tlv(seq, offset)
    _t, community_b, offset = read_tlv(seq, offset)
    pdu_tag, pdu, offset = read_tlv(seq, offset)
    pos = 0
    _t, reqid_b, pos = read_tlv(pdu, pos)
    _t, errstat_b, pos = read_tlv(pdu, pos)
    _t, erridx_b, pos = read_tlv(pdu, pos)
    _t, varbinds_b, pos = read_tlv(pdu, pos)
    request_id = int.from_bytes(reqid_b, "big", signed=True)
    version = int.from_bytes(version_b, "big", signed=True)
    err_status = int.from_bytes(errstat_b, "big")
    err_index = int.from_bytes(erridx_b, "big")
    oids = []
    pos = 0
    while pos < len(varbinds_b):
        _t, varbind, pos = read_tlv(varbinds_b, pos)
        _t, oid_b, _ = read_tlv(varbind, 0)
        oids.append(decode_oid(oid_b))
    return (
        pdu_tag,
        request_id,
        err_status,
        err_index,
        oids,
        community_b.decode(errors="replace"),
        version,
    )


def next_oids(oid: str, count: int):
    """Lexicographic successors of oid within the served MIB."""
    key = tuple(int(p) for p in oid.split("."))
    result = [o for o in SORTED_OIDS if tuple(int(p) for p in o.split(".")) > key]
    return result[:count]


# ContextSyntax [2] IMPLICIT NULL (RFC 3416 §4.2.1) — the varbind value an
# agent returns once a walk has run off the end of the MIB.
END_OF_MIB_VIEW = tlv(0x82, b"")


def build_response(request_id: int, community: str, pairs, version: int = 1):
    # VarBindList ::= SEQUENCE OF VarBind; each VarBind is itself a SEQUENCE.
    # ``pairs`` holds (oid, encoded value) so callers can supply endOfMibView.
    varbind_list = b"".join(tlv(0x30, enc_oid(oid) + value) for oid, value in pairs)
    varbinds = tlv(0x30, varbind_list)
    pdu = tlv(0xA2, enc_int(request_id) + enc_int(0) + enc_int(0) + varbinds)
    # SNMPv1 messages carry version 0; echoing the request's version keeps v1
    # clients (pysnmp rejects a version mismatch with a timeout).
    return tlv(0x30, enc_int(version) + enc_octet(community) + pdu)


# ------------------------------------------------------------------ server
def serve(port: int, stop: threading.Event):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    sock.settimeout(0.5)
    print(f"mini-snmp agent listening on 127.0.0.1:{port}/udp ({len(MIB)} oids)", flush=True)
    while not stop.is_set():
        try:
            data, addr = sock.recvfrom(65535)
        except socket.timeout:
            continue
        try:
            pdu_tag, request_id, non_repeaters, max_reps, oids, community, version = parse_message(data)
        except Exception as exc:  # malformed
            print(f"parse error: {exc}", flush=True)
            continue
        if pdu_tag == 0xA0:  # GET
            pairs = [(oid, enc_value(oid)) for oid in oids]
        elif pdu_tag == 0xA1:  # GETNEXT
            pairs = []
            for oid in oids:
                successors = next_oids(oid, 1)
                if successors:
                    nxt = successors[0]
                    pairs.append((nxt, enc_value(nxt)))
                else:
                    # Echoing the same OID here would spin a GETNEXT walk
                    # forever; endOfMibView ends it instead.
                    pairs.append((oid, END_OF_MIB_VIEW))
        elif pdu_tag == 0xA5:  # GETBULK
            pairs = []
            for oid in oids:
                successors = next_oids(oid, max(1, max_reps))
                if successors:
                    pairs.extend((o, enc_value(o)) for o in successors)
                else:
                    pairs.append((oid, END_OF_MIB_VIEW))
        else:
            print(f"unsupported pdu tag {pdu_tag:#x}", flush=True)
            continue
        # Every request must be answered. Dropping the final one (the old
        # ``if not pairs: continue``) left the client waiting for a reply that
        # never came, which it reported as a timeout instead of a clean
        # end-of-walk.
        sock.sendto(build_response(request_id, community, pairs, version), addr)
    sock.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=1161)
    args = parser.parse_args()
    stop = threading.Event()
    thread = threading.Thread(target=serve, args=(args.port, stop), daemon=True)
    thread.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop.set()


if __name__ == "__main__":
    main()
