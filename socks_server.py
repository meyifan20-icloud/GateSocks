#!/usr/bin/env python3
import argparse
import os
import sys
import select
import socket
import socketserver
import struct

SO_BINDTODEVICE = getattr(socket, "SO_BINDTODEVICE", 25)


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("unexpected EOF")
        data.extend(chunk)
    return bytes(data)


def bind_socket_to_interface(sock: socket.socket, interface: str) -> None:
    if not interface:
        raise ValueError("SOCKS5 outbound interface is required")
    sock.setsockopt(
        socket.SOL_SOCKET,
        SO_BINDTODEVICE,
        interface.encode("utf-8") + b"\0",
    )


def interface_connect(host: str, port: int, interface: str, timeout: float = 20.0) -> socket.socket:
    infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    infos.sort(key=lambda item: 0 if item[0] == socket.AF_INET else 1)
    last_error = None
    for family, socktype, proto, _, sockaddr in infos:
        upstream = socket.socket(family, socktype, proto)
        try:
            upstream.settimeout(timeout)
            bind_socket_to_interface(upstream, interface)
            upstream.connect(sockaddr)
            upstream.settimeout(None)
            return upstream
        except OSError as exc:
            last_error = exc
            upstream.close()
    raise OSError(str(last_error or "unable to connect"))


def reply_address(sock: socket.socket) -> bytes:
    try:
        address, port = sock.getsockname()[:2]
        return b"\x05\x00\x00\x01" + socket.inet_pton(socket.AF_INET, address) + struct.pack("!H", int(port))
    except OSError:
        try:
            address, port = sock.getsockname()[:2]
            return b"\x05\x00\x00\x04" + socket.inet_pton(socket.AF_INET6, address) + struct.pack("!H", int(port))
        except OSError:
            return b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"


class SocksHandler(socketserver.BaseRequestHandler):
    def handle(self):
        client = self.request
        client.settimeout(30)
        try:
            version, count = recv_exact(client, 2)
            if version != 5:
                return
            methods = recv_exact(client, count)
            if 2 not in methods:
                client.sendall(b"\x05\xff")
                return
            client.sendall(b"\x05\x02")
            if recv_exact(client, 1)[0] != 1:
                return
            ulen = recv_exact(client, 1)[0]
            username = recv_exact(client, ulen).decode("utf-8", errors="replace")
            plen = recv_exact(client, 1)[0]
            password = recv_exact(client, plen).decode("utf-8", errors="replace")
            if username != self.server.username or password != self.server.password:
                client.sendall(b"\x01\x01")
                return
            client.sendall(b"\x01\x00")

            version, command, _, atyp = recv_exact(client, 4)
            if version != 5 or command != 1:
                client.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            if atyp == 1:
                host = socket.inet_ntop(socket.AF_INET, recv_exact(client, 4))
            elif atyp == 3:
                length = recv_exact(client, 1)[0]
                host = recv_exact(client, length).decode("idna")
            elif atyp == 4:
                host = socket.inet_ntop(socket.AF_INET6, recv_exact(client, 16))
            else:
                client.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            port = struct.unpack("!H", recv_exact(client, 2))[0]

            try:
                upstream = interface_connect(host, port, self.server.interface)
            except OSError:
                client.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
                return

            with upstream:
                client.sendall(reply_address(upstream))
                client.settimeout(None)
                sockets = [client, upstream]
                while True:
                    readable, _, exceptional = select.select(sockets, [], sockets, 300)
                    if exceptional or not readable:
                        return
                    for src in readable:
                        data = src.recv(65536)
                        if not data:
                            return
                        (upstream if src is client else client).sendall(data)
        except (ConnectionError, OSError, ValueError, UnicodeError):
            return


class ThreadingSocksServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, handler, username: str, password: str, interface: str):
        super().__init__(address, handler)
        self.username = username
        self.password = password
        self.interface = interface


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--interface", required=True)
    parser.add_argument("--username", default=None)
    parser.add_argument("--password", default=None)
    args = parser.parse_args()

    username = args.username if args.username is not None else os.getenv("GATESOCKS_PROXY_USERNAME", "")
    password = args.password if args.password is not None else os.getenv("GATESOCKS_PROXY_PASSWORD", "")
    if not username or not password:
        raise RuntimeError("SOCKS5 credentials are missing")

    try:
        with ThreadingSocksServer(
            (args.bind, args.port),
            SocksHandler,
            username,
            password,
            args.interface,
        ) as server:
            print(
                f"GateSocks SOCKS5 listening on {args.bind}:{args.port} via {args.interface}",
                file=sys.stderr,
                flush=True,
            )
            server.serve_forever(poll_interval=0.5)
    except Exception as exc:
        print(f"SOCKS5 startup failed: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
        raise


if __name__ == "__main__":
    main()
