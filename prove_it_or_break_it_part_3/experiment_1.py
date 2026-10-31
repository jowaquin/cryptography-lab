# Experiment 1: The Avalanche Effect
# "Prove It or Break It" series, Part 3 - Joaquin Thiogo

import hashlib
import random
import statistics

TESTS: int = 1000


# weak hash for comparison
def weak_hash(data: bytes) -> bytes:
    return (sum(data) % 2**32).to_bytes(4, "big")


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def md5(data: bytes) -> bytes:
    return hashlib.md5(data).digest()


# count how many bits differ between two digests of the same length
def bit_difference(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


functions = {"SHA-256": sha256, "MD5": md5, "weak_hash": weak_hash}
results: dict[str, list[float]] = {name: [] for name in functions}

rng = random.Random(2026)  # fixed seed so the result can be repeated

for _ in range(TESTS):
    # random message of 32 bytes
    message: bytes = rng.randbytes(32)

    # flip exactly one bit of the message
    position: int = rng.randrange(256)
    changed = bytearray(message)
    changed[position // 8] ^= 1 << (position % 8)
    changed = bytes(changed)

    # percentage of digest bits that changed, for each function
    for name, f in functions.items():
        d1, d2 = f(message), f(changed)
        results[name].append(bit_difference(d1, d2) / (len(d1) * 8) * 100)

print("+------------+-------+-------+-------+")
print(f"| {'function':<10} | {'mean':>5} | {'min':>5} | {'max':>5} |")
print("+------------+-------+-------+-------+")
for name, values in results.items():
    mean: float = statistics.mean(values)
    print(
        f"| {name:<10} | {mean:>4.1f}% | {min(values):>4.1f}% | {max(values):>4.1f}% |")
print("+------------+-------+-------+-------+")

# the weak hash ignores the order of the bytes, so "ab" and "ba" collide
print()
print("weak_hash(b'ab') =", weak_hash(b"ab").hex())
print("weak_hash(b'ba') =", weak_hash(b"ba").hex())
