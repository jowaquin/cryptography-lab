# Experiment 2: The Passive Attacker (Eavesdropper)
# "Prove It or Break It" series, Part 2 - Joaquin Thiogo

# public values the attacker sees
p: int = 104729
g: int = 12
A: int = 90610
B: int = 5702

# try every possible a until g^a mod p matches A
attempts: int = 0
for a in range(1, p):
    attempts += 1
    if pow(g, a, p) == A:
        break

# compute the key from Bob's B, exactly like Alice does
K: int = pow(B, a, p)

print("=== Passive attacker: brute force on A ===")
print(f"Recovered a = {a} after {attempts} attempts")
print(f"Shared key from B = {B} -> {K}")
