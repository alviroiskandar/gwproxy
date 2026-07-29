#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# An origin that records the request head it was sent, so a test can assert on
# what the proxy actually forwarded rather than only on the response body.
# Writes one "<Header-Name>: <value>" line per received request for the header
# named on the command line, then answers 200.
#
# Usage: header_origin.py <port> <logfile> [header-name]
import socket, sys, threading

port = int(sys.argv[1])
logpath = sys.argv[2]
want = (sys.argv[3] if len(sys.argv) > 3 else 'Host').lower()
lock = threading.Lock()


def handle(c):
    buf = b''
    try:
        while b'\r\n\r\n' not in buf:
            chunk = c.recv(4096)
            if not chunk:
                c.close()
                return
            buf += chunk
        head = buf.split(b'\r\n\r\n', 1)[0].decode('latin-1')
        found = '(absent)'
        for line in head.split('\r\n')[1:]:
            name, _, val = line.partition(':')
            if name.strip().lower() == want:
                found = val.strip()
                break
        with lock:
            with open(logpath, 'a') as f:
                f.write(found + '\n')
                f.flush()
        body = b'ok'
        c.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: %d\r\n'
                  b'Connection: close\r\n\r\n%s' % (len(body), body))
    except OSError:
        pass
    finally:
        try:
            c.close()
        except OSError:
            pass


s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', port))
s.listen(16)
while True:
    conn, _ = s.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
