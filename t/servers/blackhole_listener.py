#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# A TCP endpoint that never completes a connection. It listens with the
# smallest possible backlog and then saturates its own accept queue, so every
# further connect() stays in SYN_SENT instead of being refused -- which is what
# a connect-timeout test needs (a closed port would give an immediate RST).
#
# Prints the bound port on stdout, then sleeps until killed.
import socket, sys, time

host = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'

fam = socket.AF_INET6 if ':' in host else socket.AF_INET
s = socket.socket(fam, socket.SOCK_STREAM)
s.bind((host, 0))
s.listen(0)
port = s.getsockname()[1]

# Fill the accept queue (Linux rounds a 0 backlog up to a small value) so no
# later SYN is answered. These sockets are never read or accepted.
fillers = []
for _ in range(16):
    c = socket.socket(fam, socket.SOCK_STREAM)
    c.setblocking(False)
    try:
        c.connect_ex((host, port))
    except OSError:
        pass
    fillers.append(c)

print(port, flush=True)
while True:
    time.sleep(3600)
