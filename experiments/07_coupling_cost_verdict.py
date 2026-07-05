"""
experiments/07_coupling_cost_verdict.py — Camino 1, Step 4: does the verified
input-coupling acceleration (+1 ideal-degree bit/round) beat its extra per-round cost?

Verified law (experiment 06 + Step-3 measurements, msolve real, two independent
modelings a-variable and x-only; the (R=1,m=3) point disambiguated it):
  baseline (indep) : D_I = 7^(R*m)
  input-coupled    : D_I = 7^(R*m) * m * 2^(R-1)
The coupling multiplies D_I by m*2^(R-1): an ADDITIVE +1 bit of ideal degree per
round (the 2^(R-1) factor). At m=1 this equals base-doubling 7->14; for larger m
the relative gain shrinks. Confirmed REAL, not a nominal-degree trap: the F4
solving degree is HIGHER for input (9-10 vs 7-9), and the x-only model reproduces
D_I exactly (so the a-variables do not inflate it).

Cost model (as experiment 05): R1CS counts multiplications; the linear layer is
free; x^7 = 4 mults. The coupling adds ONE multiplication per distinct product
x_u*x_u' per round (shared across triangles). CRUCIAL: the +1 bit/round security
gain is INDEPENDENT of coupling density (any input-coupling that raises the round
degree gives it), but the COST scales with #coupling-terms -> a minimal (1-term)
coupling gives the same gain far cheaper. We report the measured triangle coupling
AND a minimal-coupling projection.

Attacker cost ~ D_I^omega (omega=2, sparse-FGLM). R* = min rounds for 128-bit.
Run:  python experiments/07_coupling_cost_verdict.py
"""
import os
import sys
from math import ceil, log2

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from core.complex2d import Complex2D
from crypto import spn_coupling as C

SBOX_MULTS = 4
POSEIDON2_REF = 234
OMEGA = 2
LOG2_7 = log2(7)


def coupling_mults(K):
    """Distinct products x_u*x_u' needed per round (shared across triangles)."""
    at = C.triangle_coupling(K)
    pairs = set()
    for v, plist in at.items():
        for (a, b) in plist:
            pairs.add((a, b))
    return len(pairs)


def r_star_baseline(m, target=128, omega=OMEGA):
    return ceil(target / (omega * m * LOG2_7))


def r_star_input(m, target=128, omega=OMEGA):
    """min R with omega*log2(7^(Rm)*m*2^(R-1)) >= target."""
    R = 1
    while omega * (R * m * LOG2_7 + (R - 1) + log2(m)) < target:
        R += 1
    return R


def main():
    print("=== Verified ideal-degree law (msolve real, two modelings) ===")
    print(" baseline (indep): D_I = 7^(R*m)")
    print(" input-coupled   : D_I = 7^(R*m)*m*2^(R-1)  (+1 bit ideal-degree/round)")
    print(" REAL, not a trap: input F4 solving degree HIGHER (9-10 vs 7-9);")
    print(" x-only model reproduces D_I exactly.\n")

    print("=== Secure rounds R* (128-bit, omega=2) ===")
    print(f"{'capacity m':>11}{'R*(baseline)':>14}{'R*(input)':>11}{'rounds saved':>14}")
    for m in (1, 2, 3):
        rb, ri = r_star_baseline(m), r_star_input(m)
        print(f"{m:>11}{rb:>14}{ri:>11}{f'{rb}->{ri} ({100*(rb-ri)/rb:.0f}%)':>14}")
    print()

    for m in (1, 2):
        print(f"=== R1CS per permutation at capacity m={m} "
              f"(R*_base={r_star_baseline(m)}, R*_input={r_star_input(m)}) ===")
        print(f"reference Poseidon2-Goldilocks: {POSEIDON2_REF}")
        print(f"{'complex':>13}{'t':>3}{'cpl/rd':>7}{'base':>7}{'input':>7}"
              f"{'net':>7}{'input/Pos2':>11}{'minimal-cpl':>12}")
        Rb, Ri = r_star_baseline(m), r_star_input(m)
        for name, K in (("tetrahedron", Complex2D.tetrahedron()),
                        ("octahedron", Complex2D.octahedron())):
            cm = coupling_mults(K)
            base = SBOX_MULTS * K.n * Rb
            inp = (SBOX_MULTS * K.n + cm) * Ri
            mini = (SBOX_MULTS * K.n + 1) * Ri     # 1-term (sparse) coupling
            print(f"{name:>13}{K.n:>3}{cm:>7}{base:>7}{inp:>7}{inp/base:>6.2f}x"
                  f"{inp/POSEIDON2_REF:>10.2f}x{mini/base:>10.2f}x")
        print()

    print("Reading: the +1 bit/round gain cuts R* (22% at m=1, ~17% at m=2). With")
    print("the measured triangle coupling the per-round surcharge ~cancels it in")
    print("R1CS at m=2 (net ~wash). A MINIMAL 1-term coupling keeps the full gain at")
    print("+1 mult/round -> net win (see 'minimal-cpl' column): the actionable design.")
    print("VERIFIED (experiment 08): the minimal coupling reproduces D_I EXACTLY at")
    print("every density, so 'minimal-cpl' is measured, not assumed; and the law")
    print("itself is backed by a resolved large point (R=2,m=2)=9604 (not a timeout).")


if __name__ == "__main__":
    main()
