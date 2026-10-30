# Experiment 1: An Attacker Reading a Database Without the Key
# "Prove It or Break It" series, Part 1 - Joaquin Thiogo

from Crypto.Cipher import AES

# fixed key (demo only)
key: bytes = b"0123456789abcdef"

# one record per student (name and exam result)
records = [
    ("bob", "FAILED"),
    ("carol", "PASSED"),
    ("dave", "FAILED"),
    ("erin", "FAILED"),
    ("frank", "PASSED"),
    ("alice", "PASSED"),
]

# build the file
plaintext = b""
for name, result in records:
    plaintext += name.ljust(16).encode() + result.ljust(16).encode()

# encrypt the whole file at once with AES in ECB mode
cipher = AES.new(key, AES.MODE_ECB)
ciphertext = cipher.encrypt(plaintext)

# cut the ciphertext into 16-byte blocks and write each one as hex
blocks = [ciphertext[i:i + 16].hex() for i in range(0, len(ciphertext), 16)]

print("=== What the attacker sees (no key) ===")
print("+-----+--------------+--------------+")
print("| row | block 1      | block 2      |")
print("+-----+--------------+--------------+")
for row in range(len(records)):
    b1 = blocks[row * 2][:8] + "..."
    b2 = blocks[row * 2 + 1][:8] + "..."
    print(f"| {row + 1:>3} | {b1:<12} | {b2:<12} |")
print("+-----+--------------+--------------+")

# the attacker knows two rows: row 1 (FAILED) and row 6 (her own, PASSED)
known = {0: "FAILED", 5: "PASSED"}

# remember which result block belongs to which result
labels = {}
for row, result in known.items():
    labels[blocks[row * 2 + 1]] = result

print("\nThe attacker knows only two rows: row 1 (FAILED) and row 6 (her own, PASSED)")

# every other row with the same result block must have the same result
print("\n=== Result of every row, recovered without the key ===")
for row in range(len(records)):
    guess = labels.get(blocks[row * 2 + 1], "unknown")
    print(f"row {row + 1} -> {guess}")
