#!/usr/bin/env python3
"""Malformed-DNS-response server, for testing gwproxy's raw resolver.

Answers every query with a deliberately malformed response chosen by mode.
Modes mirror the four findings in src/gwproxy/dns_parser.c.
"""
import socket, struct, sys

mode = sys.argv[1]
port = int(sys.argv[2])

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", port))
sys.stderr.write("ready\n"); sys.stderr.flush()


def qname_end(q, off):
    """Walk the question name, return offset just past the terminating 0."""
    while off < len(q) and q[off] != 0:
        off += q[off] + 1
    return off + 1


while True:
    q, peer = s.recvfrom(2048)
    if len(q) < 12:
        continue
    txid = q[:2]
    qend = qname_end(q, 12)
    question = q[12:qend + 4]          # name + qtype + qclass
    name = q[12:qend]

    if mode == "good":
        # Control: a perfectly ordinary compressed-name A record.
        rr = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([127, 0, 0, 1])
        resp = txid + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + question + rr

    elif mode == "uncompressed-name":
        # A perfectly legal answer whose owner NAME is a literal label rather
        # than a compression pointer. RFC 1035 permits this.
        rr = name + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([127, 0, 0, 1])
        resp = txid + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + question + rr

    elif mode == "cname-jump":
        # One CNAME whose RDLENGTH is enormous; the parser adds it to the
        # cursor and loops without ever re-checking the bound.
        rr = b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 60, 0xFFFF)
        resp = txid + struct.pack("!HHHHH", 0x8180, 1, 2, 0, 0) + question + rr

    elif mode == "rdata-truncated":
        # AAAA claiming 16 bytes of RDATA, response ends after one.
        rr = b"\xc0\x0c" + struct.pack("!HHIH", 28, 1, 60, 16) + b"\x01"
        resp = txid + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + question + rr

    elif mode == "question-label":
        # Echo a question whose second label length is 0xC0 (192): the question
        # walker has no notion of compression and strides 193 bytes forward.
        bad_q = b"\x01a\xc0" + b"\x00" * 3 + struct.pack("!HH", 1, 1)
        resp = txid + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + bad_q
        resp += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([127, 0, 0, 1])

    else:
        raise SystemExit("unknown mode " + mode)

    s.sendto(resp, peer)
