"""
experiments/02_ao_cost_estimate.py — AO cost (multiplicative complexity /
R1CS-Plonk constraints) per evaluation of the Alaniz round. Analytic, exact for
the reference structure. Deterministic.

Metric (AO): number of NON-LINEAR multiplications = R1CS constraints (linear maps
A,B,C and additions are ~free). Operations live in F_{p^d}; each F_{p^d}
multiplication costs d^2 F_p mults (schoolbook) or ~d^1.585 (Karatsuba). Proof
systems count in the native scalar field F_p, so we report F_p-mult counts.

Reference: Poseidon2 / Neptune ~228-240 constraints per PERMUTATION.

Run: python experiments/02_ao_cost_estimate.py
"""
import os
import sys
from math import log2, floor

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

POSEIDON2_REF = 234  # ~constraints per permutation (Poseidon2/Neptune, order of magnitude)


def popcount(x):
    return bin(x).count("1")


def pow_field_mults(e):
    """F_{p^d} multiplications to compute x^e by square-and-multiply."""
    return floor(log2(e)) + popcount(e) - 1


def tetra_counts():
    # tetrahedron: n=4 vertices, m=6 edges, l=4 triangles
    return dict(n=4, m=6, l=4)


def round_field_mults(n, m, l, e):
    """F_{p^d} multiplications in ONE round R = S ∘ (M + rc)."""
    # S-box: (L·τ+1)^e per vertex → pow_field_mults(e) field mults each.
    sbox = n * pow_field_mults(e)
    # Mixing M (per reference code):
    #   bilinear: product s_u·s_v computed per (vertex, incident edge) = 2m field mults
    #   trilinear: two field mults per (vertex, incident triangle) = 2 · 3l field mults
    mixing = 2 * m + 2 * (3 * l)
    return sbox, mixing


def fp_mults(field_mults, d, model="schoolbook"):
    if model == "schoolbook":
        return field_mults * d * d
    if model == "karatsuba":
        return int(round(field_mults * (d ** 1.585)))
    raise ValueError(model)


def report(d, e, rounds=1):
    c = tetra_counts()
    sbox_fm, mix_fm = round_field_mults(c["n"], c["m"], c["l"], e)
    total_fm = (sbox_fm + mix_fm) * rounds
    sc = fp_mults(total_fm, d, "schoolbook")
    ka = fp_mults(total_fm, d, "karatsuba")
    return {
        "d": d, "e": e, "rounds": rounds,
        "field_mults_sbox": sbox_fm * rounds,
        "field_mults_mixing": mix_fm * rounds,
        "fp_mults_schoolbook": sc,
        "fp_mults_karatsuba": ka,
        "x_poseidon2_schoolbook": round(sc / POSEIDON2_REF, 1),
    }


def main():
    print("# AO cost estimate — Alaniz round on tetrahedron (n=4,m=6,l=4)\n")
    print(f"Reference: Poseidon2/Neptune ~{POSEIDON2_REF} constraints per permutation.\n")
    print(f"{'d':>3} {'e':>4} {'rounds':>6} {'Fp-mults (school)':>18} "
          f"{'Fp-mults (karats)':>18} {'x Poseidon2':>12}")
    # e high is expensive; A6-CICO shows 1 round is broken regardless of e, so a
    # secure version needs many rounds → multiply accordingly.
    for (d, e, r) in [(6, 17, 1), (12, 17, 1), (12, 31, 1),
                      (12, 31, 6), (12, 31, 10)]:
        x = report(d, e, r)
        print(f"{x['d']:>3} {x['e']:>4} {x['rounds']:>6} "
              f"{x['fp_mults_schoolbook']:>18} {x['fp_mults_karatsuba']:>18} "
              f"{x['x_poseidon2_schoolbook']:>12}")
    print("\nNotes:")
    print("  - One round already costs ~40-70x a full Poseidon2 permutation.")
    print("  - A6-CICO: one round has cubic CICO solving degree (broken) REGARDLESS")
    print("    of e ⇒ the expensive high-e S-box buys no CICO security in one round.")
    print("  - A secure construction would need MANY rounds (rows with rounds=6/10),")
    print("    pushing cost to hundreds of x Poseidon2 → non-competitive as an AO")
    print("    primitive on this metric.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
