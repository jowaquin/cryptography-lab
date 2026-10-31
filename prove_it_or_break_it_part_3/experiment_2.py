# Experiment 2: Two Different Inputs, One MD5 Hash
# "Prove It or Break It" series, Part 3 - Joaquin Thiogo

import hashlib

# two blocks of 128 bytes from Wang et al. (2004)
BLOCK_A: bytes = bytes.fromhex(
    "d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f89"
    "55ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5b"
    "960b1dd1dc417b9ce4d897f45a6555d535739ac7f0ebfd0c3029f166d109b18f"
    "75277f7930d55ceb22e8adba79cc155ced74cbdd5fc5d36db19b0ad835cca7e3"
)
BLOCK_B: bytes = bytes.fromhex(
    "d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f89"
    "55ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5b"
    "960b1dd1dc417b9ce4d897f45a6555d535739a47f0ebfd0c3029f166d109b18f"
    "75277f7930d55ceb22e8adba794c155ced74cbdd5fc5d36db19b0a5835cca7e3"
)
assert len(BLOCK_A) == len(BLOCK_B) == 128


def md5(data: bytes) -> bytes:
    return hashlib.md5(data).digest()


# weak hash from Experiment 1
def weak_hash(data: bytes) -> bytes:
    return (sum(data) % 2**32).to_bytes(4, "big")


# where the blocks differ
print("different bytes at positions:", [
      i for i in range(128) if BLOCK_A[i] != BLOCK_B[i]])

# same hash? only MD5 says yes
for name in ("md5", "sha1", "sha256", "sha3_256"):
    same: bool = hashlib.new(name, BLOCK_A).digest(
    ) == hashlib.new(name, BLOCK_B).digest()
    print(f"{name:<9} same hash: {same}")

# same text after both blocks
suffix: bytes = b" Transfer to account 1234567890, amount 1,000,000"
print("same suffix appended :", md5(BLOCK_A + suffix) == md5(BLOCK_B + suffix))

# same letter before both blocks
print("same prefix in front :", md5(b"Z" + BLOCK_A) == md5(b"Z" + BLOCK_B))

# chosen-prefix idea with the weak hash
p1: bytes = b"Certificate for microsoft.com"
p2: bytes = b"Certificate for evil.com"
print()
print(weak_hash(p1).hex(), weak_hash(p2).hex(), weak_hash(p2 + b"zzzz>").hex())
