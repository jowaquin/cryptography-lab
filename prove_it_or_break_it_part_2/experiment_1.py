# Experiment 1: The Baseline
# "Prove It or Break It" series, Part 2 - Joaquin Thiogo

# public values
p: int = 104729
g: int = 12

# secret numbers
a: int = 12345  # Alice
b: int = 54321  # Bob

# values sent over the network
A: int = pow(g, a, p)
B: int = pow(g, b, p)

# each side computes the shared key
K_alice: int = pow(B, a, p)
K_bob: int = pow(A, b, p)

print("=== Seen by an eavesdropper ===")
print(f"p = {p}, g = {g}, A = {A}, B = {B}")
print()
print("=== Kept secret ===")
print(f"a = {a} (Alice), b = {b} (Bob)")
print()
print("=== Shared key ===")
print(f"Alice computes B^a mod p = {K_alice}")
print(f"Bob computes   A^b mod p = {K_bob}")
print("Match:", K_alice == K_bob)
