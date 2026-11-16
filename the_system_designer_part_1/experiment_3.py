# Experiment 3: Man-in-the-middle attack against two designs.
# "The System Designer" series, Part 1 - Joaquin Thiogo

import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
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


def valid(public_key: ec.EllipticCurvePublicKey, sig: bytes, data: bytes) -> bool:
    try:
        public_key.verify(sig, data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


# ---------------------------------------------------------------- design 1
print("=== Design 1: ECDH without signatures ===")
x = ec.generate_private_key(CURVE)  # Alice
y = ec.generate_private_key(CURVE)  # Bob
m1 = ec.generate_private_key(CURVE)  # Charlie, facing Alice
m2 = ec.generate_private_key(CURVE)  # Charlie, facing Bob

# Charlie replaces both public keys on the wire
Z_alice = x.exchange(ec.ECDH(), m1.public_key())
Z_bob = y.exchange(ec.ECDH(), m2.public_key())
Z_charlie_alice = m1.exchange(ec.ECDH(), x.public_key())
Z_charlie_bob = m2.exchange(ec.ECDH(), y.public_key())

k_alice = HKDF(hashes.SHA256(), 32, None, b"chat/v1").derive(Z_alice)
k_bob = HKDF(hashes.SHA256(), 32, None, b"chat/v1").derive(Z_bob)
k_charlie_alice = HKDF(hashes.SHA256(), 32, None, b"chat/v1").derive(Z_charlie_alice)
k_charlie_bob = HKDF(hashes.SHA256(), 32, None, b"chat/v1").derive(Z_charlie_bob)

nonce = os.urandom(12)
C = AESGCM(k_alice).encrypt(nonce, b"The password is 1234", None)
P_charlie = AESGCM(k_charlie_alice).decrypt(nonce, C, None)
C_forward = AESGCM(k_charlie_bob).encrypt(nonce, P_charlie, None)
P_bob = AESGCM(k_bob).decrypt(nonce, C_forward, None)

print(f"Alice and Bob share a key       : {k_alice == k_bob}")
print(f"Charlie holds Alice's key       : {k_charlie_alice == k_alice}")
print(f"Charlie holds Bob's key         : {k_charlie_bob == k_bob}")
print(f"Charlie reads the message       : {P_charlie.decode()}")
print(f"Bob receives (nothing unusual)  : {P_bob.decode()}")

# ---------------------------------------------------------------- design 2
print("\n=== Design 2: signed handshake ===")
id_a = ec.generate_private_key(CURVE)
id_b = ec.generate_private_key(CURVE)
id_m = ec.generate_private_key(CURVE)  # Charlie's own identity key
fp_a = sha256(raw(id_a.public_key()))
fp_b = sha256(raw(id_b.public_key()))
pinned_b = id_b.public_key()  # what Alice trusts after the fingerprint check

# An earlier honest session between Alice and Bob that Charlie recorded
x_old = ec.generate_private_key(CURVE)
y_old = ec.generate_private_key(CURVE)
A_old, n_a_old = raw(x_old.public_key()), os.urandom(16)
B_old, n_b_old = raw(y_old.public_key()), os.urandom(16)
t_old = b"chat/v1" + fp_a + fp_b + A_old + n_a_old + B_old + n_b_old
sig_b_old = id_b.sign(b"responder " + t_old, ec.ECDSA(hashes.SHA256()))

# The new session that Alice starts now
x = ec.generate_private_key(CURVE)
A, n_a = raw(x.public_key()), os.urandom(16)
y = ec.generate_private_key(CURVE)
B, n_b = raw(y.public_key()), os.urandom(16)
t = b"chat/v1" + fp_a + fp_b + A + n_a + B + n_b
sig_b = id_b.sign(b"responder " + t, ec.ECDSA(hashes.SHA256()))

# What Alice would verify in each situation
B_m, n_b_m = raw(m1.public_key()), os.urandom(16)
t_m = b"chat/v1" + fp_a + fp_b + A + n_a + B_m + n_b_m
sig_m = id_m.sign(b"responder " + t_m, ec.ECDSA(hashes.SHA256()))
t_replay = b"chat/v1" + fp_a + fp_b + A + n_a + B_old + n_b_old

rows = [
    ("0", "nothing (control)", valid(pinned_b, sig_b, b"responder " + t)),
    (
        "1",
        "swaps B, keeps Bob's signature",
        valid(pinned_b, sig_b, b"responder " + t_m),
    ),
    ("2", "swaps B, signs with own key", valid(pinned_b, sig_m, b"responder " + t_m)),
    (
        "3",
        "replays Bob's old signature",
        valid(pinned_b, sig_b_old, b"responder " + t_replay),
    ),
]

print("+---------+---------------------------------+-----------------+")
print("| attempt | what Charlie does               | Alice accepts   |")
print("+---------+---------------------------------+-----------------+")
for attempt, action, accepted in rows:
    print(f"| {attempt:^7} | {action:<31} | {str(accepted):<15} |")
print("+---------+---------------------------------+-----------------+")

fp_m = sha256(raw(id_m.public_key()))
print(f"\nCharlie's key matches the pinned fingerprint: {fp_m == fp_b}")
