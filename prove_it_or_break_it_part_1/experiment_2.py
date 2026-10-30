# Experiment 2: ECB vs CBC in a Guessing Game
# "Prove It or Break It" series, Part 1 - Joaquin Thiogo

import random

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# M0 has two identical blocks, M1 has two different blocks
M0: bytes = b"A" * 16 + b"A" * 16
M1: bytes = b"A" * 16 + b"B" * 16


def encrypt_ecb(key: bytes, plaintext: bytes) -> bytes:
    return AES.new(key, AES.MODE_ECB).encrypt(plaintext)


def encrypt_cbc(key: bytes, plaintext: bytes) -> bytes:
    # a fresh random IV for every message
    iv = get_random_bytes(16)
    return AES.new(key, AES.MODE_CBC, iv).encrypt(plaintext)


def attacker_guess(ciphertext: bytes) -> int:
    # the attacker only compares the first two ciphertext blocks
    block_1 = ciphertext[0:16]
    block_2 = ciphertext[16:32]
    if block_1 == block_2:
        return 0  # guess M0
    return 1  # guess M1


rounds = 10000

# play the same game against ECB and against CBC
for name, encrypt in [("ECB", encrypt_ecb), ("CBC", encrypt_cbc)]:
    correct = 0
    for _ in range(rounds):
        # a fresh key in every round
        key = get_random_bytes(16)

        # pick M0 (0) or M1 (1) at random and encrypt it
        b = random.getrandbits(1)
        message = M0 if b == 0 else M1
        ciphertext = encrypt(key, message)

        if attacker_guess(ciphertext) == b:
            correct += 1

    print(f"{name}: attacker is right in {correct}/{rounds} rounds ({correct / rounds:.1%})")
