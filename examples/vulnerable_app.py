"""
Sample application with a realistic mix of cryptography.

This exists purely as a test fixture for pqscan. It is intentionally
vulnerable and should never be deployed.
"""

import hashlib
import ssl
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# --- key generation -------------------------------------------------------

def generate_signing_key():
    # RSA-2048: broken by Shor's algorithm
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def generate_legacy_key():
    # ECDSA on P-256: broken by Shor's algorithm
    return ec.generate_private_key(ec.SECP256R1())


# --- signing --------------------------------------------------------------

def sign_payload(key, payload: bytes) -> bytes:
    return key.sign(payload, padding.PKCS1v15(), hashes.SHA256())


# --- hashing --------------------------------------------------------------

def fingerprint(data: bytes) -> str:
    # SHA-1: classically broken, replace regardless of quantum
    return hashlib.sha1(data).hexdigest()


def weak_checksum(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def strong_digest(data: bytes) -> str:
    return hashlib.sha384(data).hexdigest()


# --- symmetric ------------------------------------------------------------

def encrypt_aes128(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    # AES-128: security level halved by Grover's algorithm
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc = cipher.encryptor()
    return enc.update(plaintext) + enc.finalize()


def encrypt_aes256(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    # AES-256: post-quantum safe
    cipher = Cipher(algorithms.AES256(key), modes.GCM(iv))
    enc = cipher.encryptor()
    return enc.update(plaintext) + enc.finalize()


# --- TLS ------------------------------------------------------------------

def build_context(certfile: str, keyfile: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile, keyfile)
    # ECDHE key exchange: broken by Shor's algorithm
    ctx.set_ciphers("ECDHE-RSA-AES128-GCM-SHA256")
    return ctx


# --- config ---------------------------------------------------------------

CONFIG = {
    "signing_algorithm": "RSA-2048",
    "hash": "SHA-1",
    "symmetric": "AES-128",
    "kex": "ECDH",
    "jwt_alg": "ES256",
}
