#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# Report the peer (source) address of each incoming TCP connection: on accept,
# send the peer IP back as one line and close. Used to verify that the proxy's
# -j BIND --to-source pinned the outgoing source address.
import socket
import sys

host, port = sys.argv[1], int(sys.argv[2])
fam = socket.AF_INET6 if ":" in host else socket.AF_INET
s = socket.socket(fam, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((host, port))
s.listen(16)
while True:
    c, addr = s.accept()
    try:
        c.sendall((addr[0] + "\n").encode())
    finally:
        c.close()
