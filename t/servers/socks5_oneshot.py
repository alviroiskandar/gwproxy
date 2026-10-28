#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# Send raw bytes to the proxy in one write, then read until the proxy
# closes the connection (or the timeout runs out) and print what came back
# as hex, followed by " CLOSED" or " OPEN" for how the read ended.
#
# Usage: socks5_oneshot.py [--timeout S] port hexbytes
import socket, sys

argv = sys.argv[1:]
timeout = 3.0
if argv and argv[0] == '--timeout':
    timeout = float(argv[1])
    argv = argv[2:]

port = int(argv[0])
data = bytes.fromhex(argv[1])

s = socket.create_connection(('127.0.0.1', port), timeout=10)
s.sendall(data)
s.settimeout(timeout)
got = b''
end = 'CLOSED'
try:
    while True:
        b = s.recv(4096)
        if not b:
            break
        got += b
except socket.timeout:
    end = 'OPEN'
except ConnectionResetError:
    end = 'CLOSED'
s.close()
print(got.hex(), end)
