"""
experiments/14_hades_cost.py — cost of the HADES (full-partial-full) Alaniz-AO
vs the full construction and Poseidon2, given the measured partial-round law.

Measured (experiment 13, m=1): a PARTIAL round multiplies the CICO ideal degree by
the same ~14 as a full round -> D_I depends on the TOTAL round count R_total, not
the full/partial split (each round's single S-boxed lane diffuses through the MDS
layer). So HADES with R_total rounds has the same algebraic D_I as R_total full
rounds, at far fewer S-boxes.

Caveat (Poseidon lesson, OPEN): partial rounds can enable dedicated attacks that
D_I does not capture; a minimum of full rounds R_f is needed as protection. The
exact minimal R_f is NOT derived here -- we tabulate cost vs R_f and flag it.

R1CS cost = 4 per S-box + 1 per coupling multiplication; linear layer free.
Run:  python experiments/14_hades_cost.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from crypto.alaniz_hades import HadesAO
from crypto.spn_field import GOLDILOCKS_P

POSEIDON2 = 234
SBOX_R1CS = 4
T = 8
R_TOTAL = 8   # = R*_alg(m=4)=6 + margin 2; D_I(R_total) same as full (partial=full)


def r1cs(h):
    return h.sbox_count() * SBOX_R1CS + h.coupling_mults()


def main():
    print("HADES Alaniz-AO cost (t=8, R_total=8 => same D_I as full R=8 at m=4).")
    print("Partial round == full round for D_I (measured, m=1). R_f = # full rounds")
    print("(open: minimal R_f vs partial-round attacks; Poseidon uses 6-8).\n")

    full = HadesAO(T, R_TOTAL, 0, p=GOLDILOCKS_P)   # all-full = the current spec
    base = r1cs(full)
    print(f"reference: full Alaniz-AO R=8 -> {full.sbox_count()} S-boxes, "
          f"{base} R1CS = {base/POSEIDON2:.2f}x Poseidon2\n")
    print(f"{'R_f':>4}{'R_p':>4}{'S-boxes':>9}{'R1CS':>7}{'vs full':>9}{'vs Poseidon2':>14}")
    for r_f in (2, 4, 6, 8):
        r_p = R_TOTAL - r_f
        if r_p < 0:
            continue
        h = HadesAO(T, r_f, r_p, p=GOLDILOCKS_P)
        c = r1cs(h)
        print(f"{r_f:>4}{r_p:>4}{h.sbox_count():>9}{c:>7}{c/base:>8.2f}x"
              f"{c/POSEIDON2:>13.2f}x")

    print("\nReading: partial rounds cut S-boxes sharply. At a MODERATE split")
    print("(R_f=4, R_p=4) HADES Alaniz-AO reaches ~0.74x Poseidon2 -- below 1x, the")
    print("target. A conservative R_f=6 gives ~parity (1.0x). The exact secure R_f is")
    print("the one open parameter; both bracket a competitive primitive.")


if __name__ == "__main__":
    main()
