# Experiment 3: A Plain Hash Does Not Authenticate
# "Prove It or Break It" series, Part 3 - Joaquin Thiogo

import hashlib
import hmac
import secrets

# real file and official digest
release: bytes = b"MZ" + bytes(range(256)) * 1000
official_digest: str = hashlib.sha256(release).hexdigest()

# attacker changes the file and the digest on the page
fake_release: bytes = release + b"<malicious payload>"
fake_digest: str = hashlib.sha256(fake_release).hexdigest()

print("official SHA-256 :", official_digest[:32] + "...")
print("fake SHA-256     :", fake_digest[:32] + "...")

# user checks the hash
print("user check (hash):", hashlib.sha256(
    fake_release).hexdigest() == fake_digest)

# secret key, the server never has it
key: bytes = secrets.token_bytes(32)

# attacker can only guess
guessed_key: bytes = secrets.token_bytes(32)

# attacker's tag
fake_tag: bytes = hmac.new(guessed_key, fake_release, hashlib.sha256).digest()

# tag the user expects
expected_tag: bytes = hmac.new(key, fake_release, hashlib.sha256).digest()

# user checks the tag
print("user check (HMAC):", hmac.compare_digest(expected_tag, fake_tag))
