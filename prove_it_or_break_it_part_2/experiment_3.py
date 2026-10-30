# Experiment 3: The Man-in-the-Middle (MITM) Attack
# "Prove It or Break It" series, Part 2 - Joaquin Thiogo

# public values
p: int = 104729
g: int = 12

# secret numbers of Alice and Bob
a: int = 12345
b: int = 54321

# secret numbers of the attacker
x: int = 7777
y: int = 2468

# the real values sent by Alice and Bob
A: int = pow(g, a, p)
B: int = pow(g, b, p)

# the attacker swaps them for its own values
X: int = pow(g, x, p)  # Alice receives X instead of B
Y: int = pow(g, y, p)  # Bob receives Y instead of A

# Alice and Bob each compute a key from what they received
K_alice: int = pow(X, a, p)
K_bob: int = pow(Y, b, p)

# the attacker uses the real A and B it copied
K_attacker_alice: int = pow(A, x, p)
K_attacker_bob: int = pow(B, y, p)

print("=== Values on the wire ===")
print(f"Alice sends A = {A}, but Bob receives Y = {Y}")
print(f"Bob sends B = {B}, but Alice receives X = {X}")
print()
print("=== Keys ===")
print(f"Alice's key                : {K_alice}")
print(f"Attacker's key with Alice  : {K_attacker_alice}")
print(f"Bob's key                  : {K_bob}")
print(f"Attacker's key with Bob    : {K_attacker_bob}")
print("Alice and Bob share a key  :", K_alice == K_bob)
