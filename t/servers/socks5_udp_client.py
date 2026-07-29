#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# SOCKS5 UDP ASSOCIATE client for the integration test. Opens a TCP control
# connection to the proxy, issues UDP ASSOCIATE, then relays datagrams of the
# requested sizes to a UDP echo server through the proxy's relay socket and
# checks each is echoed back byte-exact.
#
# Usage: socks5_udp_client.py [--delay S] [--proxy-host H] [--target-host H] \
#            [--user U --pass P] [--expect-drop] proxy_port echo_port size...
# The proxy and target hosts default to 127.0.0.1; pass an IPv6 literal (e.g.
# ::1) to exercise IPv6 and cross-address-family relaying.
#
# With --user/--pass the control connection authenticates with RFC 1929
# username/password instead of the "no authentication" method, which is what
# an ACL "-m user" rule needs in order to see a username.
#
# With --expect-drop the relay is expected NOT to forward the datagrams: the
# client succeeds only if no echo comes back. Use it to assert that a datagram
# is denied (by an ACL) or discarded (an unsupported header), as opposed to
# merely asserting that some unrelated failure occurred.
import socket, struct, sys, time

argv = sys.argv[1:]
delay = 0.0
proxy_host = '127.0.0.1'
target_host = '127.0.0.1'
user = None
password = None
expect_drop = False


def take_opt(name):
    if name in argv:
        i = argv.index(name)
        val = argv[i + 1]
        del argv[i:i + 2]
        return val
    return None


v = take_opt('--delay')
if v is not None:
    delay = float(v)
v = take_opt('--proxy-host')
if v is not None:
    proxy_host = v
v = take_opt('--target-host')
if v is not None:
    target_host = v
user = take_opt('--user')
password = take_opt('--pass')
if '--expect-drop' in argv:
    argv.remove('--expect-drop')
    expect_drop = True

pp = int(argv[0]); ep = int(argv[1])
sizes = [int(x) for x in argv[2:]] or [64]


def atyp_addr(host):
    """SOCKS5 ATYP + packed address for a numeric host."""
    if ':' in host:
        return b'\x04' + socket.inet_pton(socket.AF_INET6, host)
    return b'\x01' + socket.inet_aton(host)


def skip_reply_hdr(data):
    """Return the payload offset after a SOCKS5 UDP reply header."""
    atyp = data[3]
    if atyp == 1:
        return 4 + 4 + 2
    if atyp == 4:
        return 4 + 16 + 2
    raise AssertionError('bad reply ATYP 0x%02x' % atyp)


pfam = socket.AF_INET6 if ':' in proxy_host else socket.AF_INET
t = socket.socket(pfam, socket.SOCK_STREAM)
t.settimeout(10)
t.connect((proxy_host, pp))
if user is not None:
    t.sendall(b'\x05\x02\x00\x02')	# offer no-auth and username/password
else:
    t.sendall(b'\x05\x01\x00')
sel = t.recv(2)
assert len(sel) == 2 and sel[0] == 5, 'method selection failed'
if sel[1] == 0x02:
    assert user is not None, 'proxy demanded auth but no credentials given'
    u8 = user.encode(); p8 = (password or '').encode()
    t.sendall(b'\x01' + bytes([len(u8)]) + u8 + bytes([len(p8)]) + p8)
    st = t.recv(2)
    assert st[:1] == b'\x01' and st[1] == 0, 'username/password auth rejected'
else:
    assert sel[1] == 0x00, 'proxy selected method 0x%02x' % sel[1]
# UDP ASSOCIATE, DST 0.0.0.0:0 (source not yet known).
t.sendall(b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00')
rep = t.recv(4)
assert len(rep) == 4 and rep[0] == 5, 'bad assoc reply'
assert rep[1] == 0, 'UDP ASSOCIATE refused (REP=0x%02x)' % rep[1]
if rep[3] == 1:
    bnd_ip = socket.inet_ntoa(t.recv(4)); bfam = socket.AF_INET
elif rep[3] == 4:
    bnd_ip = socket.inet_ntop(socket.AF_INET6, t.recv(16)); bfam = socket.AF_INET6
else:
    raise AssertionError('bad BND ATYP 0x%02x' % rep[3])
bnd_port = struct.unpack('!H', t.recv(2))[0]

if delay:
    time.sleep(delay)			# outlast the handshake timeout
u = socket.socket(bfam, socket.SOCK_DGRAM); u.settimeout(2)
hdr = b'\x00\x00\x00' + atyp_addr(target_host) + struct.pack('!H', ep)
for sz in sizes:
    payload = bytes((i * 7 + sz) & 0xff for i in range(sz))
    got = None
    for _ in range(5):			# UDP is lossy; retry a few times
        u.sendto(hdr + payload, (bnd_ip, bnd_port))
        try:
            data, _ = u.recvfrom(65535)
        except socket.timeout:
            if expect_drop:		# no echo is the expected outcome
                break
            continue
        got = data[skip_reply_hdr(data):]
        break
    if expect_drop:
        assert got is None, 'datagram of size %d was relayed, want dropped' % sz
    else:
        assert got == payload, 'echo mismatch at size %d' % sz
if expect_drop:
    print('OK: %d datagram size(s) dropped' % len(sizes))
else:
    print('OK: %d datagram size(s) relayed' % len(sizes))
