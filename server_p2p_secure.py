#!/usr/bin/env python3
"""
server_p2p_secure.py

Simple TCP relay server for exactly two clients.
- Forwards framed binary messages between the two clients without decrypting.
- Prints Base64 of encrypted MESSAGE packets ONLY on server terminal.

Protocol framing: [4-byte big-endian length][payload]
Payload types (first byte):
  0x01 - HANDSHAKE  payload: [1][32 master][8 session]
  0x02 - MESSAGE    payload: [1][4 key_index][16 iv][ciphertext...][32 hmac]
"""
import socket
import threading
import struct
import sys
import base64

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 5000
BACKLOG = 10

TYPE_HANDSHAKE = 0x01
TYPE_MESSAGE = 0x02


def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed")
        buf += chunk
    return buf


def frame_recv(sock: socket.socket) -> bytes:
    hdr = recv_exact(sock, 4)
    length = struct.unpack(">I", hdr)[0]
    if length <= 0 or length > 10_000_000:
        raise ConnectionError("Invalid frame length")
    return recv_exact(sock, length)


def frame_send(sock: socket.socket, payload: bytes):
    sock.sendall(struct.pack(">I", len(payload)) + payload)


class RelayServer:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.listen(BACKLOG)

    def log(self, msg: str):
        print(msg)
        sys.stdout.flush()

    def handle_pair(self, c1: socket.socket, a1, c2: socket.socket, a2):
        self.log(f"[CONNECTED] {a1} <-> {a2}")
        stop_event = threading.Event()

        def forward(src: socket.socket, dst: socket.socket, src_addr):
            try:
                while not stop_event.is_set():
                    payload = frame_recv(src)
                    if not payload:
                        break

                    ptype = payload[0]

                    if ptype == TYPE_HANDSHAKE:
                        self.log(f"[RELAY] HANDSHAKE from {src_addr}")

                    elif ptype == TYPE_MESSAGE:
                        # ALWAYS log encrypted packet here
                        b64_pkt = base64.b64encode(payload).decode("utf-8")
                        self.log(f"[RELAY] MESSAGE from {src_addr}")
                        self.log(f"[ENCRYPTED_B64] {b64_pkt}")

                    frame_send(dst, payload)

            except Exception:
                pass
            finally:
                stop_event.set()

        t1 = threading.Thread(target=forward, args=(c1,c2,a1), daemon=True)
        t2 = threading.Thread(target=forward, args=(c2,c1,a2), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        try:
            c1.close()
        except Exception:
            pass
        try:
            c2.close()
        except Exception:
            pass
        self.log("[DISCONNECT] Pair ended. Waiting for next pair...")

    def serve_forever(self):
        self.log(f"[LISTENING] {self.host}:{self.port}")
        while True:
            try:
                c1, a1 = self.sock.accept()
                self.log(f"[NEW] Client1 connected: {a1}")

                c2, a2 = self.sock.accept()
                self.log(f"[NEW] Client2 connected: {a2}")

                # Handle this pair, then loop back to accept next pair
                self.handle_pair(c1, a1, c2, a2)

            except KeyboardInterrupt:
                self.log("[STOP] Server shutting down")
                break
            except Exception:
                continue


if __name__ == "__main__":
    RelayServer(LISTEN_HOST, LISTEN_PORT).serve_forever()