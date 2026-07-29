#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# A trivial UDP echo server for the SOCKS5 UDP ASSOCIATE test.
import socket, sys

fam = socket.AF_INET6 if ':' in sys.argv[1] else socket.AF_INET
s = socket.socket(fam, socket.SOCK_DGRAM)
s.bind((sys.argv[1], int(sys.argv[2])))
while True:
    data, addr = s.recvfrom(65535)
    s.sendto(data, addr)
