import os
import hashlib
import base64

def generate_quantum_key():
    """
    Quantum-inspired random key generator
    """
    quantum_bits = os.urandom(32)
    hashed_key = hashlib.sha256(quantum_bits).digest()
    return base64.urlsafe_b64encode(hashed_key)
