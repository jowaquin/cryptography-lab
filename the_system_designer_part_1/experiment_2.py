# Experiment 2: Chat messages protected with AES-GCM.
# "The System Designer" series, Part 2 - Joaquin Thiogo

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# In the real protocol these two keys come from the handshake in Experiment 1
k_ab = AESGCM.generate_key(bit_length=256)
k_ba = AESGCM.generate_key(bit_length=256)


def seal(k: bytes, direction: bytes, n: int, plaintext: bytes) -> bytes:
    nonce = bytes(4) + n.to_bytes(8, "big")
    aad = direction + n.to_bytes(8, "big")
    return AESGCM(k).encrypt(nonce, plaintext, aad)


def open_(k: bytes, direction: bytes, n: int, ciphertext: bytes) -> bytes:
    nonce = bytes(4) + n.to_bytes(8, "big")
    aad = direction + n.to_bytes(8, "big")
    return AESGCM(k).decrypt(nonce, ciphertext, aad)


# Alice sends three messages to Bob (counters 0, 1 and 2)
messages = [b"Hello Bob", b"The report is ready", b"Meet at nine"]
C = [seal(k_ab, b"a2b", n, messages[n]) for n in range(3)]

print("=== Normal delivery (Bob expects counter 0, 1, 2 in order) ===")
for n in range(3):
    P = open_(k_ab, b"a2b", n, C[n])
    print(
        f"message {n}: {len(messages[n]):>2} bytes plain, {len(C[n]):>2} bytes cipher -> {P.decode()}"
    )
print(
    f"Same text, different counter, different ciphertext: {seal(k_ab, b'a2b', 0, b'Hi') != seal(k_ab, b'a2b', 1, b'Hi')}"
)

# Bob also sends one message back to Alice with the other key
reply = seal(k_ba, b"b2a", 0, b"Got it")

wrong_key = AESGCM.generate_key(bit_length=256)
flipped = C[1][:-1] + bytes([C[1][-1] ^ 1])

attacks = [
    ("Charlie decrypts with a wrong key", lambda: open_(wrong_key, b"a2b", 0, C[0])),
    ("Charlie flips one bit of message 1", lambda: open_(k_ab, b"a2b", 1, flipped)),
    ("Charlie replays message 0 as the fourth", lambda: open_(k_ab, b"a2b", 3, C[0])),
    ("Charlie swaps message 1 and message 2", lambda: open_(k_ab, b"a2b", 1, C[2])),
    ("Charlie reflects Bob's reply back to Bob", lambda: open_(k_ab, b"a2b", 0, reply)),
]

print("\n=== Attacks on the channel ===")
print("+-------------------------------------------+----------+")
print("| attack                                    | result   |")
print("+-------------------------------------------+----------+")
for name, attack in attacks:
    try:
        attack()
        result = "ACCEPTED"
    except InvalidTag:
        result = "rejected"
    print(f"| {name:<41} | {result:<8} |")
print("+-------------------------------------------+----------+")
