#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# Report the peer (source) address of each incoming TCP connection: on accept,
# send the peer IP back as one line and close. Used to verify that the proxy's
# -j BIND --to-source (or the global --bind-source) pinned the outgoing source
# address.
#
# Usage: peer_addr.py <host> <port> [--with-port] [--log <file>]
#
#   --with-port   also report the peer's source PORT, as "<ip> <port>". The
#                 port half of --bind-source=ip:port is otherwise invisible.
#   --log <file>  append every reported line to <file> as well. This is what
#                 lets the server stand in for an upstream proxy: there gwproxy
#                 dials it instead of the test dialling through, so the reply
#                 goes to gwproxy and the source is only observable out of band.
import socket
import sys

host, port = sys.argv[1], int(sys.argv[2])
argv = sys.argv[3:]
with_port = "--with-port" in argv
logpath = argv[argv.index("--log") + 1] if "--log" in argv else None

fam = socket.AF_INET6 if ":" in host else socket.AF_INET
s = socket.socket(fam, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((host, port))
s.listen(16)
while True:
    try:
        c, addr = s.accept()
    except OSError:
        continue
    line = "%s %d" % (addr[0], addr[1]) if with_port else addr[0]
    try:
        if logpath:
            with open(logpath, "a") as f:
                f.write(line + "\n")
                f.flush()
        c.sendall((line + "\n").encode())
    except OSError:
        # One connection must never take the server down. A proxy that is
        # killed mid-reply, or a client that vanishes, resets this socket and
        # sendall() raises; letting that escape ends the accept loop, and then
        # every later connection is refused. The test that first notices then
        # reports whatever assertion it was making -- "the source was not
        # pinned" -- when the truth is that the origin died several cases ago.
        pass
    finally:
        c.close()
