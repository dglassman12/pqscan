"""
Test fixture for pqscan: the migrated key exchange.

Hybrid ML-KEM-768 + X25519, so the session stays secure if either holds.
"""

import oqs

KEM_NAME = "ML-KEM-768"
TLS_GROUP = "X25519MLKEM768"
SIGNATURE = "ML-DSA-65"


def encapsulate(peer_public_key: bytes):
    with oqs.KeyEncapsulation(KEM_NAME) as kem:
        return kem.encap_secret(peer_public_key)
