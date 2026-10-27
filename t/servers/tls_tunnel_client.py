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
#   noread <pid> <max_kib>
#       The origin sends without pause while this client never reads. Watch
#       the proxy's resident memory (VmRSS of <pid>) for a few seconds and
#       fail if it grows by more than <max_kib> KiB: the proxy must stop
#       reading from the origin once the client stops reading.
#   slowread <nbytes>
#       The origin sends <nbytes> bytes and closes. This client waits a
#       while before it starts reading, then must get all <nbytes> bytes and
#       a clean end of stream.
#   upload <nbytes>
#       Send <nbytes> bytes to an origin that reads them with short pauses,
#       then, without closing, wait for the origin to confirm it got them
#       all. Whatever the proxy decrypted it must also deliver, even when the
#       client has nothing more to send.
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


def blast_origin(lsock):
    c, _ = lsock.accept()
    chunk = b"y" * 65536
    try:
        while True:
            c.sendall(chunk)
    except OSError:
        pass


def sized_origin(nbytes):
    def fn(lsock):
        c, _ = lsock.accept()
        left = nbytes
        try:
            while left:
                n = min(left, 65536)
                c.sendall(b"z" * n)
                left -= n
        except OSError:
            pass
        c.close()
    return fn


def counting_origin(nbytes):
    def fn(lsock):
        c, _ = lsock.accept()
        got = 0
        try:
            while got < nbytes:
                d = c.recv(65536)
                if not d:
                    break
                # Pause every 64 KiB so the proxy's buffer to us fills up.
                if got // 65536 != (got + len(d)) // 65536:
                    time.sleep(0.01)
                got += len(d)
            c.sendall(b"got %d\n" % got)
        except OSError:
            pass
        c.close()
    return fn


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


def vmrss_kib(pid):
    with open("/proc/%d/status" % pid) as f:
        for line in f:
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    die("no VmRSS for pid %d" % pid)


def scen_noread(pport, pid, max_kib):
    oport = start_origin(blast_origin)
    a = tunnel(pport, oport)
    # Let the socket buffers on both legs fill before taking the baseline.
    time.sleep(0.5)
    base = vmrss_kib(pid)
    peak = base
    for _ in range(15):
        time.sleep(0.2)
        peak = max(peak, vmrss_kib(pid))
    if peak - base > max_kib:
        die("proxy RSS grew from %d KiB to %d KiB with a client that does "
            "not read" % (base, peak))
    a.close()


def scen_slowread(pport, nbytes):
    oport = start_origin(sized_origin(nbytes))
    a = tunnel(pport, oport)
    time.sleep(2)
    got = 0
    try:
        while True:
            d = a.recv(65536)
            if not d:
                break
            got += len(d)
    except (OSError, ssl.SSLError) as e:
        die("read failed after %d of %d bytes: %r" % (got, nbytes, e))
    if got != nbytes:
        die("got %d of %d bytes" % (got, nbytes))


def scen_upload(pport, nbytes):
    oport = start_origin(counting_origin(nbytes))
    a = tunnel(pport, oport)
    a.sendall(b"x" * nbytes)
    want = b"got %d\n" % nbytes
    a.settimeout(15)
    rep = b""
    try:
        while not rep.endswith(b"\n"):
            d = a.recv(64)
            if not d:
                break
            rep += d
    except (OSError, ssl.SSLError) as e:
        die("no confirmation from the origin: %r" % e)
    if rep != want:
        die("origin reported %r, want %r" % (rep, want))


def main():
    scen = sys.argv[1]
    pport = int(sys.argv[2])
    if scen == "isolation":
        scen_isolation(pport)
    elif scen == "noread":
        scen_noread(pport, int(sys.argv[3]), int(sys.argv[4]))
    elif scen == "slowread":
        scen_slowread(pport, int(sys.argv[3]))
    elif scen == "upload":
        scen_upload(pport, int(sys.argv[3]))
    else:
        die("unknown scenario %s" % scen)


if __name__ == "__main__":
    main()
