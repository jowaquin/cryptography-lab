# Experiment 1: Signed handshake for a two-party secure chat.
# "The System Designer" series, Part 1 - Joaquin Thiogo

import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

CURVE = ec.SECP256R1()


def raw(public_key: ec.EllipticCurvePublicKey) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )


def sha256(data: bytes) -> bytes:
    h = hashes.Hash(hashes.SHA256())
    h.update(data)
    return h.finalize()


# Long-term identity keys. The public halves are compared out of band.
id_a = ec.generate_private_key(CURVE)
id_b = ec.generate_private_key(CURVE)
fp_a = sha256(raw(id_a.public_key()))
fp_b = sha256(raw(id_b.public_key()))

# Message 1: Alice -> Bob, her ephemeral public key A and a fresh nonce n_a
x = ec.generate_private_key(CURVE)
A = raw(x.public_key())
n_a = os.urandom(16)

# Message 2: Bob -> Alice, his ephemeral public key B, a nonce n_b and a signature
y = ec.generate_private_key(CURVE)
B = raw(y.public_key())
n_b = os.urandom(16)
transcript = b"chat/v1" + fp_a + fp_b + A + n_a + B + n_b
sig_b = id_b.sign(b"responder " + transcript, ec.ECDSA(hashes.SHA256()))

# Message 3: Alice -> Bob, her signature over the same transcript
sig_a = id_a.sign(b"initiator " + transcript, ec.ECDSA(hashes.SHA256()))

# Each side verifies the other signature with the pinned public key
ok_b = ok_a = True
try:
    id_b.public_key().verify(
        sig_b, b"responder " + transcript, ec.ECDSA(hashes.SHA256())
    )
except InvalidSignature:
    ok_b = False
try:
    id_a.public_key().verify(
        sig_a, b"initiator " + transcript, ec.ECDSA(hashes.SHA256())
    )
except InvalidSignature:
    ok_a = False

# Both sides compute the same shared secret Z and run it through HKDF
Z_alice = x.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(CURVE, B))
Z_bob = y.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(CURVE, A))

salt = sha256(transcript)
k_ab_alice = HKDF(hashes.SHA256(), 32, salt, b"chat/v1 a2b").derive(Z_alice)
k_ba_alice = HKDF(hashes.SHA256(), 32, salt, b"chat/v1 b2a").derive(Z_alice)
k_ab_bob = HKDF(hashes.SHA256(), 32, salt, b"chat/v1 a2b").derive(Z_bob)
k_ba_bob = HKDF(hashes.SHA256(), 32, salt, b"chat/v1 b2a").derive(Z_bob)

print("=== Compared out of band (SHA-256 of identity public key) ===")
print(f"Alice fingerprint : {fp_a.hex()[:32]}...")
print(f"Bob fingerprint   : {fp_b.hex()[:32]}...")

print("\n=== Handshake ===")
print(f"Bob's signature valid for Alice   : {ok_b}")
print(f"Alice's signature valid for Bob   : {ok_a}")

print("\n=== Derived keys ===")
print(f"Alice and Bob share k_ab          : {k_ab_alice == k_ab_bob}")
print(f"Alice and Bob share k_ba          : {k_ba_alice == k_ba_bob}")
print(f"k_ab differs from k_ba            : {k_ab_alice != k_ba_alice}")
print(f"Key length                        : {len(k_ab_alice)} bytes")
