#!/usr/bin/env python3
"""
client_p2p_secure.py

Minimal one-to-one secure chat over TCP using PyCryptodome.
- AES-CBC encryption
- HMAC-SHA256 integrity
- Session handshake (initiator -> server -> peer)
- Key rotation via key_index; MESSAGE includes key_index
- Length-framed TCP protocol
- Tkinter GUI; receiver runs in background thread
- Logging requirements:
  - Initiator terminal prints MASTER_KEY + SESSION_ID on start
  - All clients print "1 key rotated", "2 key rotated", etc
  - Encrypted packet is NOT printed in client terminal

Usage:
  py -3.11 client_p2p_secure.py --id A --init
  py -3.11 client_p2p_secure.py --id B

Override host if needed:
  py -3.11 client_p2p_secure.py --id B --host 192.168.1.10

Requirements:
  pip install pycryptodome
"""
import argparse
import socket
import struct
import threading
import secrets
import hashlib
import hmac
from datetime import datetime
import sys
import tkinter as tk
from tkinter import scrolledtext, messagebox

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

TYPE_HANDSHAKE = 0x01
TYPE_MESSAGE = 0x02

# rotate after N messages
MESSAGES_PER_KEY = 1

# Default server target (change once, then run without --host)
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5000


# ---------------- framing ----------------
def frame_send(sock: socket.socket, payload: bytes):
    sock.sendall(struct.pack(">I", len(payload)) + payload)


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


# ---------------- core client ----------------
class P2PClient:
    def __init__(self, client_id: str, host: str, port: int, is_initiator: bool):
        self.id = client_id
        self.host = host
        self.port = port
        self.is_initiator = is_initiator

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.master_key: bytes | None = None
        self.session_id: bytes | None = None

        self.key_index = 0
        self.message_count = 0
        self.rotation_count = 0

        self.running = True
        self.lock = threading.Lock()

    def connect(self):
        self.sock.connect((self.host, self.port))

    def send_handshake(self):
        # initiator creates master/session and sends to server
        self.master_key = secrets.token_bytes(32)
        self.session_id = secrets.token_bytes(8)

        # Print ONLY on initiator terminal
        print("\n=== INITIATOR SESSION INFO ===")
        print("MASTER_KEY (hex):", self.master_key.hex())
        print("SESSION_ID (hex):", self.session_id.hex())
        print("==============================\n")

        payload = bytes([TYPE_HANDSHAKE]) + self.master_key + self.session_id
        frame_send(self.sock, payload)

    def adopt_handshake(self, master: bytes, session: bytes):
        with self.lock:
            self.master_key = master
            self.session_id = session
            self.key_index = 0
            self.message_count = 0
            self.rotation_count = 0

    def derive_aes_key(self, key_index: int) -> bytes:
        assert self.master_key is not None and self.session_id is not None
        return hashlib.sha256(self.master_key + self.session_id + key_index.to_bytes(4, "big")).digest()

    def encrypt_and_mac(self, plaintext: str, key_index: int) -> bytes:
        aes_key = self.derive_aes_key(key_index)
        iv = secrets.token_bytes(16)
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        ct = cipher.encrypt(pad(plaintext.encode("utf-8"), AES.block_size))
        mac = hmac.new(aes_key, iv + ct, hashlib.sha256).digest()
        return iv, ct, mac

    def send_message(self, plaintext: str):
        if self.master_key is None or self.session_id is None:
            return False, "Waiting for session key..."

        with self.lock:
            kidx = self.key_index

        try:
            iv, ct, mac = self.encrypt_and_mac(plaintext, kidx)
            payload = bytes([TYPE_MESSAGE]) + kidx.to_bytes(4, "big") + iv + ct + mac
            frame_send(self.sock, payload)

            # rotation counter (client terminal only)
            with self.lock:
                self.message_count += 1
                if self.message_count >= MESSAGES_PER_KEY:
                    self.key_index += 1
                    self.message_count = 0
                    self.rotation_count += 1
                    print(f"{self.rotation_count} key rotated")

            return True, None
        except Exception as e:
            return False, str(e)

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass


# ---------------- GUI ----------------
class ChatGUI:
    def __init__(self, client: P2PClient):
        self.client = client
        self.root = tk.Tk()
        self.root.title(f"QTalk Secure P2P - {client.id}")
        self.root.geometry("560x460")

        self.chat_area = scrolledtext.ScrolledText(self.root, state="disabled", height=22)
        self.chat_area.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        bottom = tk.Frame(self.root)
        bottom.pack(fill=tk.X, padx=10, pady=8)

        self.entry = tk.Entry(bottom)
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        tk.Button(bottom, text="Send", command=self.on_send).pack(side=tk.LEFT, padx=8)

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def log(self, msg: str):
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{now}] {msg}\n"
        self.chat_area.configure(state="normal")
        self.chat_area.insert(tk.END, line)
        self.chat_area.configure(state="disabled")
        self.chat_area.yview(tk.END)

    def on_send(self):
        text = self.entry.get().strip()
        if not text:
            return

        ok, err = self.client.send_message(text)
        if not ok:
            self.log(f"[ERROR] {err}")
            return

        self.log(f"You: {text}")
        self.entry.delete(0, tk.END)

    def on_close(self):
        if messagebox.askokcancel("Quit", "Quit QTalk?"):
            self.client.running = False
            self.client.close()
            self.root.destroy()


# ---------------- receiver thread ----------------
def receive_loop(client: P2PClient, gui: ChatGUI):
    while client.running:
        try:
            payload = frame_recv(client.sock)
            if not payload:
                continue

            ptype = payload[0]

            if ptype == TYPE_HANDSHAKE:
                if len(payload) != 1 + 32 + 8:
                    continue
                master = payload[1:33]
                session = payload[33:41]
                client.adopt_handshake(master, session)
                gui.root.after(0, gui.log, f"[SESSION] Adopted session: {session.hex()}")

            elif ptype == TYPE_MESSAGE:
                if len(payload) < 1 + 4 + 16 + 32:
                    continue

                if client.master_key is None or client.session_id is None:
                    gui.root.after(0, gui.log, "[ERROR] Received message but no session key yet")
                    continue

                kidx = int.from_bytes(payload[1:5], "big")
                iv = payload[5:21]
                mac = payload[-32:]
                ct = payload[21:-32]

                aes_key = client.derive_aes_key(kidx)
                expected = hmac.new(aes_key, iv + ct, hashlib.sha256).digest()
                if not hmac.compare_digest(expected, mac):
                    gui.root.after(0, gui.log, "[HMAC FAILED] Dropped message")
                    continue

                try:
                    pt = unpad(AES.new(aes_key, AES.MODE_CBC, iv).decrypt(ct), AES.block_size)
                    text = pt.decode("utf-8", errors="replace")
                    gui.root.after(0, gui.log, f"Friend: {text}")
                except Exception:
                    gui.root.after(0, gui.log, "[DECRYPT FAILED] Dropped message")

        except ConnectionError:
            gui.root.after(0, gui.log, "[DISCONNECT] Server closed connection")
            client.running = False
            break
        except Exception:
            continue


# ---------------- main ----------------
def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--id", required=True, help="Client ID (A/B)")
    p.add_argument("--host", default=DEFAULT_HOST, help=f"Server IP (default: {DEFAULT_HOST})")
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.add_argument("--init", action="store_true", help="Initiator sends handshake")
    return p.parse_args()


def main():
    args = parse_args()

    client = P2PClient(args.id, args.host, args.port, is_initiator=args.init)
    try:
        client.connect()
    except Exception as e:
        print("Failed to connect:", e)
        sys.exit(1)

    if client.is_initiator:
        client.send_handshake()

    gui = ChatGUI(client)
    threading.Thread(target=receive_loop, args=(client, gui), daemon=True).start()
    gui.root.mainloop()


if __name__ == "__main__":
    main()