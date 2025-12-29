import os
import json
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

VAULT_FILE = "vault.enc"
SALT_FILE = "salt.bin"

# ---------------- Key Derivation ----------------
def derive_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=300_000,
        backend=default_backend()
    )
    return kdf.derive(master_password.encode())

# ---------------- Encryption / Decryption ----------------
def encrypt_data(data: dict, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    iv = os.urandom(12)
    ciphertext = aesgcm.encrypt(iv, json.dumps(data).encode(), None)
    return iv + ciphertext

def decrypt_data(encrypted: bytes, key: bytes) -> dict:
    aesgcm = AESGCM(key)
    iv = encrypted[:12]
    ciphertext = encrypted[12:]
    plaintext = aesgcm.decrypt(iv, ciphertext, None)
    return json.loads(plaintext.decode())

# ---------------- Vault Handling ----------------
def load_or_create_salt() -> bytes:
    if not os.path.exists(SALT_FILE):
        salt = os.urandom(16)
        with open(SALT_FILE, "wb") as f:
            f.write(salt)
        return salt
    return open(SALT_FILE, "rb").read()

def load_vault(key: bytes) -> dict:
    if not os.path.exists(VAULT_FILE):
        return {"entries": []}
    encrypted = open(VAULT_FILE, "rb").read()
    return decrypt_data(encrypted, key)

def save_vault(vault: dict, key: bytes):
    encrypted = encrypt_data(vault, key)
    with open(VAULT_FILE, "wb") as f:
        f.write(encrypted)

# ---------------- Vault Operations ----------------
def add_entry(vault: dict, site: str, username: str, password: str):
    vault["entries"].append({
        "site": site,
        "username": username,
        "password": password
    })
