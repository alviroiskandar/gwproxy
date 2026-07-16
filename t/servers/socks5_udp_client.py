#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# SOCKS5 UDP ASSOCIATE client for the integration test. Opens a TCP control
# connection to the proxy, issues UDP ASSOCIATE, then relays datagrams of the
# requested sizes to a UDP echo server through the proxy's relay socket and
# checks each is echoed back byte-exact. Args: proxy_port echo_port size...
import socket, struct, sys, time

argv = sys.argv[1:]
delay = 0.0
if '--delay' in argv:
    i = argv.index('--delay')
    delay = float(argv[i + 1])
    del argv[i:i + 2]
pp = int(argv[0]); ep = int(argv[1])
sizes = [int(x) for x in argv[2:]] or [64]

t = socket.create_connection(('127.0.0.1', pp)); t.settimeout(10)
t.sendall(b'\x05\x01\x00')
assert t.recv(2) == b'\x05\x00', 'method selection failed'
# UDP ASSOCIATE, DST 0.0.0.0:0 (source not yet known)
t.sendall(b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00')
rep = t.recv(10)
assert len(rep) == 10 and rep[0] == 5, 'bad assoc reply'
assert rep[1] == 0, 'UDP ASSOCIATE refused (REP=0x%02x)' % rep[1]
bnd_ip = socket.inet_ntoa(rep[4:8]); bnd_port = struct.unpack('!H', rep[8:10])[0]

if delay:
    time.sleep(delay)			# outlast the handshake timeout
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(2)
hdr = b'\x00\x00\x00\x01' + socket.inet_aton('127.0.0.1') + struct.pack('!H', ep)
for sz in sizes:
    payload = bytes((i * 7 + sz) & 0xff for i in range(sz))
    got = None
    for _ in range(5):			# UDP is lossy; retry a few times
        u.sendto(hdr + payload, (bnd_ip, bnd_port))
        try:
            data, _ = u.recvfrom(65535)
        except socket.timeout:
            continue
        assert data[:4] == b'\x00\x00\x00\x01', 'bad reply header'
        got = data[10:]
        break
    assert got == payload, 'echo mismatch at size %d' % sz
print('OK: %d datagram size(s) relayed' % len(sizes))
