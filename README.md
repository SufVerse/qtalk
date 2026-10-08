# Q-Talk 🔒⚛️

**Q-Talk** is a secure, lightweight peer-to-peer (P2P) desktop chat application built in Python. It features end-to-end encryption (E2EE), cryptographically enforced message authentication, and dynamic, quantum-inspired per-message key rotation.

---

## 🚀 Key Features

- **End-to-End Encryption (E2EE)**: Payloads are encrypted client-side using **AES-256 (CBC mode)** with PKCS7 padding.
- **Message Integrity & Authentication**: Every packet includes an **HMAC-SHA256** checksum calculated over the initialization vector (IV) and ciphertext to protect against tampering.
- **Dynamic Key Rotation**: Keys automatically rotate deterministically with each sent message (`key_index` increments), providing forward secrecy across message exchanges.
- **Zero-Knowledge Relay Server**: The relay server forwards length-framed binary messages between connected peers without possessing session keys or plaintext data.
- **Desktop Graphical Interface**: Clean, threaded **Tkinter** GUI for instant messaging and real-time session logging.
- **Decryption Proof & Verification Tool**: Includes a standalone verification GUI (`decryption.py`) to demonstrate how packets, master keys, and HMAC verification operate under the hood.

---

## 📐 Architecture & Cryptographic Protocol

### Packet Framing
All network communication uses 4-byte big-endian length prefixing:
```
[ 4-byte Length ] [ Payload (N bytes) ]
```

### Protocol Payloads
1. **Handshake (`0x01`)**:
   - Sent by initiator upon connection.
   - Format: `[0x01 (1 byte)] [Master Key (32 bytes)] [Session ID (8 bytes)]`
2. **Message (`0x02`)**:
   - Encrypted chat messages.
   - Format: `[0x02 (1 byte)] [Key Index (4 bytes)] [IV (16 bytes)] [Ciphertext (N bytes)] [HMAC-SHA256 (32 bytes)]`

### Key Derivation Function (KDF)
For every message transmission and reception, the specific AES key is derived dynamically:
$$\text{AES\_Key} = \text{SHA-256}(\text{Master\_Key} \mathbin{\Vert} \text{Session\_ID} \mathbin{\Vert} \text{uint32}(\text{Key\_Index}))$$

---

## 📁 Project Structure

```plaintext
qtalk/
├── .gitignore               # Git ignore rules for Python, cache, and IDEs
├── .gitattributes          # Line ending normalization
├── client_p2p_secure.py     # Desktop GUI client & cryptographic engine
├── server_p2p_secure.py     # Zero-knowledge TCP relay server
├── decryption.py            # GUI proof tool for verifying & decrypting packets
├── quantumKey.py            # Quantum-inspired random key generator
├── requirements.txt         # Project dependencies
└── README.md                # Project documentation
```

---

## 🛠️ Prerequisites & Installation

### Requirements
- **Python**: Version 3.10 or higher (Python 3.11 recommended).
- **Tkinter**: Standard GUI library (bundled with standard Python installers on Windows and macOS; on Linux, install via `sudo apt install python3-tk`).

### Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/<your-username>/qtalk.git
   cd qtalk
   ```

2. **Create and activate a virtual environment** (optional but recommended):
   ```bash
   # Windows (PowerShell)
   python -m venv venv
   .\venv\Scripts\Activate.ps1

   # Linux / macOS
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

---

## 💻 How to Run

### 1. Start the Relay Server
Start the relay server first. By default, it listens on `0.0.0.0:5000`:
```bash
python server_p2p_secure.py
```

### 2. Start Client A (Initiator)
The initiator creates the session keys and broadcasts the initial handshake:
```bash
python client_p2p_secure.py --id A --init
```
*(On launch, Client A prints the generated `MASTER_KEY` and `SESSION_ID` to its terminal).*

### 3. Start Client B (Receiver)
In another terminal, connect the second client:
```bash
python client_p2p_secure.py --id B
```

### 4. Chatting across Different Computers on a Network
To chat between two computers across a Local Area Network (LAN):
- Run the server on Computer 1 (find its IP, e.g. `192.168.1.50`).
- Run the clients passing the `--host` flag:
  ```bash
  python client_p2p_secure.py --id A --init --host 192.168.1.50
  python client_p2p_secure.py --id B --host 192.168.1.50
  ```

---

## 🔍 Standalone Decryption Proof Tool

A dedicated debugging and demonstration tool is included in `decryption.py`:
```bash
python decryption.py
```
This utility opens a GUI that allows you to paste:
- **Master Key (Hex)** (from Client A's startup terminal)
- **Session ID (Hex)** (from Client A's startup terminal)
- **Encrypted Packet (Base64)** (from the relay server terminal log)

Clicking **Decrypt** validates the HMAC-SHA256 signature and reveals the recovered plaintext, demonstrating how the zero-knowledge relay forwards raw encrypted bytes that can only be decrypted with matching session parameters.

---

## 📤 Pushing to GitHub

To push this repository to GitHub:

1. **Stage and commit your files**:
   ```bash
   git add .
   git commit -m "feat: setup project with documentation, gitignore, and dependencies"
   ```

2. **Link your remote repository** (create an empty repository on GitHub first):
   ```bash
   git remote add origin https://github.com/<your-username>/qtalk.git
   ```

3. **Push to main branch**:
   ```bash
   git branch -M main
   git push -u origin main
   ```

---

## 🛡️ License

This project is licensed under the MIT License — feel free to use, modify, and distribute.
