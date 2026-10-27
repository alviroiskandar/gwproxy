# SPDX-License-Identifier: GPL-2.0-only
#
# TLS CONNECT-tunnel client for the HTTPS-proxy tests. It runs its own echo
# origin on 127.0.0.1, opens a TLS connection to the proxy and asks it to
# CONNECT to that origin, then runs one scenario on the established tunnel.
#
# Usage: tls_tunnel_client.py <scenario> <proxy_port> [args...]
#
# Scenarios:
#   isolation
#       Check that the tunnel echoes, let a second client fail its TLS
#       handshake on the same proxy, then check that the tunnel still echoes.
#       A failed handshake must not affect any other session.
#
# Exits 0 on success, 1 on failure (with a message on stderr).

import socket
import ssl
import sys
import threading
import time


def echo_origin(lsock):
    def serve(c):
        try:
            while True:
                d = c.recv(65536)
                if not d:
                    break
                c.sendall(d)
        except OSError:
            pass
        c.close()

    while True:
        c, _ = lsock.accept()
        threading.Thread(target=serve, args=(c,), daemon=True).start()


def start_origin(fn):
    lsock = socket.socket()
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(16)
    threading.Thread(target=fn, args=(lsock,), daemon=True).start()
    return lsock.getsockname()[1]


def tunnel(pport, oport):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    s = socket.create_connection(("127.0.0.1", pport), timeout=10)
    a = ctx.wrap_socket(s)
    a.sendall(b"CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: x\r\n\r\n" % oport)
    rep = b""
    while b"\r\n\r\n" not in rep:
        d = a.recv(1)
        if not d:
            die("proxy closed the tunnel before the CONNECT reply")
        rep += d
    if b" 200 " not in rep.split(b"\r\n")[0]:
        die("CONNECT refused: %r" % rep)
    return a


def die(msg):
    sys.stderr.write("tls_tunnel_client: %s\n" % msg)
    sys.exit(1)


def echo(a, msg):
    try:
        a.sendall(msg)
        got = b""
        while len(got) < len(msg):
            d = a.recv(len(msg) - len(got))
            if not d:
                break
            got += d
    except (OSError, ssl.SSLError) as e:
        return repr(e)
    return got


def scen_isolation(pport):
    oport = start_origin(echo_origin)
    a = tunnel(pport, oport)
    got = echo(a, b"ping1")
    if got != b"ping1":
        die("tunnel did not echo before the bad handshake: %r" % (got,))

    # A ClientHello header followed by garbage: the handshake fails.
    b = socket.create_connection(("127.0.0.1", pport), timeout=5)
    b.sendall(bytes([0x16, 3, 1, 0, 8, 1, 0, 0, 4, 0xde, 0xad, 0xbe, 0xef]))
    try:
        while b.recv(4096):
            pass
    except OSError:
        pass
    b.close()
    time.sleep(0.2)

    got = echo(a, b"ping2")
    if got != b"ping2":
        die("tunnel broke after another client's failed handshake: %r"
            % (got,))


def main():
    scen = sys.argv[1]
    pport = int(sys.argv[2])
    if scen == "isolation":
        scen_isolation(pport)
    else:
        die("unknown scenario %s" % scen)


if __name__ == "__main__":
    main()
