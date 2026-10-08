import tkinter as tk
import base64
import hashlib
import hmac
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def derive_aes_key(master_key, session_id, key_index):
    material = master_key + session_id + key_index.to_bytes(4, 'big')
    return hashlib.sha256(material).digest()

def decrypt_message():
    try:
        master_hex = master_entry.get().strip()
        session_hex = session_entry.get().strip()
        encrypted_b64 = encrypted_entry.get().strip()

        packet = base64.b64decode(encrypted_b64)

        key_index = int.from_bytes(packet[:4], 'big')
        iv = packet[4:20]
        mac = packet[-32:]
        ciphertext = packet[20:-32]

        MASTER_KEY = bytes.fromhex(master_hex)
        SESSION_ID = bytes.fromhex(session_hex)

        aes_key = derive_aes_key(MASTER_KEY, SESSION_ID, key_index)

        expected_mac = hmac.new(
            aes_key, iv + ciphertext, hashlib.sha256).digest()

        if not hmac.compare_digest(mac, expected_mac):
            result_label.config(text="HMAC Verification Failed", fg="red")
            return

        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(ciphertext), 16).decode()

        result_label.config(text=f"Decrypted:\n{decrypted}", fg="green")

    except Exception as e:
        result_label.config(text=str(e), fg="red")

root = tk.Tk()
root.title("Q-Talk Decryption Proof")
root.geometry("520x400")

tk.Label(root, text="Master Key (Hex)").pack()
master_entry = tk.Entry(root, width=70)
master_entry.pack()

tk.Label(root, text="Session ID (Hex)").pack()
session_entry = tk.Entry(root, width=40)
session_entry.pack()

tk.Label(root, text="Encrypted Packet (Base64)").pack()
encrypted_entry = tk.Entry(root, width=70)
encrypted_entry.pack()

tk.Button(root, text="Decrypt",
          bg="#0078D7", fg="white",
          command=decrypt_message).pack(pady=10)

result_label = tk.Label(root, text="", wraplength=480)
result_label.pack()

root.mainloop()
