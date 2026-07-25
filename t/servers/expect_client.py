#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# A strict "Expect: 100-continue" client (RFC 9110 Section 10.1.1) for the
# forwarding-proxy test. Unlike curl -- which gives up waiting after a second
# and sends the body anyway, hiding whether the interim response ever arrived
# -- this client sends the request head and then blocks: it writes no body byte
# until the proxy relays the origin's "100 Continue". A proxy that withholds
# origin->client data until the client writes more deadlocks here, which is
# exactly the case a plain curl exchange cannot see.
#
# Usage: expect_client.py <proxy_port> <origin_port> [user] [pass] [body_len]
# Exits 0 only if the 100 Continue arrived and the final status was 200.
import base64, socket, sys

pport = int(sys.argv[1])
oport = int(sys.argv[2])
user = sys.argv[3] if len(sys.argv) > 3 else 'user'
password = sys.argv[4] if len(sys.argv) > 4 else 'pass'
blen = int(sys.argv[5]) if len(sys.argv) > 5 else 8000

cred = base64.b64encode(('%s:%s' % (user, password)).encode()).decode()
head = (
    'POST http://127.0.0.1:%d/x HTTP/1.1\r\n'
    'Host: 127.0.0.1:%d\r\n'
    'Proxy-Authorization: Basic %s\r\n'
    'Expect: 100-continue\r\n'
    'Content-Length: %d\r\n'
    '\r\n' % (oport, oport, cred, blen)
)

s = socket.create_connection(('127.0.0.1', pport))
s.settimeout(5)
s.sendall(head.encode())

# Block for the interim response BEFORE writing any body byte.
try:
    interim = s.recv(4096)
except socket.timeout:
    print('FAIL: proxy never relayed the origin 100 Continue')
    sys.exit(1)

if not interim:
    print('FAIL: proxy closed before any response')
    sys.exit(1)
if not interim.startswith(b'HTTP/1.1 100'):
    print('FAIL: expected 100 Continue, got %r' % interim[:40])
    sys.exit(1)

s.sendall(b'x' * blen)

rest = interim.split(b'\r\n\r\n', 1)[1] if b'\r\n\r\n' in interim else b''
while b'\r\n\r\n' not in rest:
    try:
        chunk = s.recv(4096)
    except socket.timeout:
        print('FAIL: no final response after the body')
        sys.exit(1)
    if not chunk:
        break
    rest += chunk

if not rest.startswith(b'HTTP/1.1 200'):
    print('FAIL: final status was %r' % rest[:40])
    sys.exit(1)

print('OK: 100 Continue relayed, final 200')
