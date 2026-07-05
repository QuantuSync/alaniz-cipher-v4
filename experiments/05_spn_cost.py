"""
experiments/05_spn_cost.py — Phase 4: cost of the AO SPN vs Poseidon2, given the
secure round count R* derived from the verified CICO law (experiment 04).

Cost model (standard AO accounting):
  * R1CS/Plonk constraints count MULTIPLICATIONS only. A LINEAR layer (any txt
    matrix, dense OR MDS) is affine => 0 constraints. So the sheaf mixing layer
    and an MDS layer have IDENTICAL R1CS cost. Only S-boxes cost constraints.
  * x^7 via the addition chain 1->2->4->6->7 = 4 multiplications => 4 constraints
    per S-box (same as Plonky2's x^7).
  * Native / MPC / FHE evaluation DOES pay for the linear layer: a dense txt
    matrix costs ~nnz(M) field mults per round, where an MDS-with-cheap-structure
    layer (Poseidon2 M4) costs ~O(t) additions. This is where a dense sheaf layer
    is penalised.

R* comes from experiment 04: D_I = 7^(R*m), attack cost ~ D_I^2 (sparse-FGLM,
omega=2), so R*(m) = ceil(128 / (2*m*log2 7)). D_I is INDEPENDENT of t and of the
mixing branch number => R* is the SAME for t=4 and t=6 at equal capacity m.

Reference: Poseidon2 over Goldilocks ~234 R1CS constraints per permutation
(prompt figure). Run:  python experiments/05_spn_cost.py
"""
import os
import sys
from math import ceil, log2

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from core.complex2d import Complex2D
from crypto.spn_field import GOLDILOCKS_P
from crypto.spn_mix import nnz, sheaf_mix_matrix

LOG2_7 = log2(7)
SBOX_CONSTRAINTS = 4   # x^7 addition chain 1->2->4->6->7
POSEIDON2_REF = 234    # R1CS constraints per permutation, Goldilocks (prompt)


def r_star(m, target=128, omega=2):
    return ceil(target / (omega * m * LOG2_7))


def report():
    p = GOLDILOCKS_P
    complexes = [("tetrahedron (MDS control)", Complex2D.tetrahedron()),
                 ("octahedron  (sheaf principal)", Complex2D.octahedron())]

    print("=== Secure round count R* (extrapolated from verified D_I=7^(R*m)) ===")
    print("cost ~ D_I^2 (sparse-FGLM, omega=2); R* is t-independent.\n")
    print(f"{'capacity m':>12}{'D_I=7^(R**m) bits':>20}{'R* (any t)':>12}")
    for m in (1, 2, 3):
        R = r_star(m)
        print(f"{m:>12}{2 * R * m * LOG2_7:>19.0f}{R:>12}")
    print("\n(m=2 = 128-bit sponge capacity over Goldilocks: the design point.)\n")

    print("=== R1CS/Plonk constraints (only S-boxes count; linear layer = free) ===")
    print(f"reference Poseidon2-Goldilocks: {POSEIDON2_REF} constraints/perm\n")
    print(f"{'construction':>16}{'cap m':>7}{'t':>3}{'R*':>4}{'S-boxes':>9}{'R1CS':>7}{'xPos2':>8}")
    for m, Rlabel in ((2, "design"), (1, "consrv")):
        R = r_star(m)
        for name, K in complexes:
            sboxes = K.n * R
            r1cs = sboxes * SBOX_CONSTRAINTS
            tag = "tetra" if K.n == 4 else "octa"
            print(f"{tag+'/'+Rlabel:>16}{m:>7}{K.n:>3}{R:>4}{sboxes:>9}"
                  f"{r1cs:>7}{r1cs / POSEIDON2_REF:>7.2f}x")
        print()

    print("=== Native/MPC/FHE mults per permutation (linear layer IS paid) ===")
    print(f"{'construction':>26}{'t':>3}{'R*':>4}{'sbox mults':>11}{'lin mults':>11}{'total':>8}")
    for name, K in complexes:
        R = r_star(2)  # design point
        M = sheaf_mix_matrix(K, p, b"cost/seed")
        sbox_mults = K.n * R * SBOX_CONSTRAINTS
        lin_mults = nnz(M) * R
        print(f"{name[:24]:>26}{K.n:>3}{R:>4}{sbox_mults:>11}{lin_mults:>11}"
              f"{sbox_mults + lin_mults:>8}")
    print("\nPoseidon2 M4 external layer applies in ~8 add + doublings (~0 generic")
    print("mults); the dense sheaf layer pays ~nnz(M) mults/round natively.")

    print("\n=== Verdict inputs ===")
    print(" * Branch deficit (t=6 sheaf: 6/7 vs MDS 7) => 0 extra rounds vs MDS")
    print("   control against FreeLunch/CheapLunch/resultant (D_I is t-independent).")
    print(" * R1CS: sheaf layer as cheap as MDS (both free); full-SPN round count is")
    print("   the cost driver. Partial rounds (Poseidon2's lever) need an MDS layer;")
    print("   the sub-MDS sheaf makes that optimization harder to justify.")
    print(" * Native/MPC/FHE: dense sheaf layer strictly costlier than Poseidon2 M4.")


if __name__ == "__main__":
    report()
