"""
experiments/03_mix_branch_number.py — Phase 2b MINI-GATE: exact branch number
of the sheaf-patterned mixing layer vs Poseidon2 M4 / Cauchy MDS at equal t.

Measures, for K in {tetrahedron (t=4), double tetrahedron (t=5), octahedron
(t=6)} over Goldilocks p = 2^64-2^32+1 (cross-checked over the 30-bit msolve
proxy prime):

  * zero entries of the sheaf matrix (each is a broken 1×1 minor),
  * MDS-ness (all minors non-zero) and exact differential branch number,
  * the same for the references: Poseidon2 M4 (t=4) and Cauchy MDS (all t),
  * nnz = F_p multiplications per matrix application (cost proxy),
  * zero entries of M^2 (does one extra round complete diffusion?).

Reproducible: fixed seeds SEEDS, deterministic PRG. Run:
    python experiments/03_mix_branch_number.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from core.complex2d import Complex2D
from crypto.linalg_fp import matrix_mul_fp
from crypto.spn_field import GOLDILOCKS_P, PROXY_PRIME_30
from crypto.spn_mix import (
    branch_number, cauchy_mds, is_mds, nnz, poseidon2_m4, sheaf_mix_matrix,
    zero_entries,
)

SEEDS = [b"spn-mix-seed-%d" % i for i in range(5)]
COMPLEXES = [
    ("tetrahedron", Complex2D.tetrahedron()),
    ("double_tet", Complex2D.double_tetrahedron()),
    ("octahedron", Complex2D.octahedron()),
]


def analyze(name, M, p):
    t = len(M)
    b = branch_number(M, p)
    mds = is_mds(M, p)
    assert mds == (b == t + 1), "cross-check failed: is_mds vs branch_number"
    z = zero_entries(M)
    M2 = matrix_mul_fp(M, M, p)
    return {
        "name": name, "t": t, "branch": b, "mds_bound": t + 1, "is_mds": mds,
        "zeros": len(z), "nnz": nnz(M), "zeros_M2": len(zero_entries(M2)),
    }


def report(rows):
    hdr = f"{'matrix':<28}{'t':>3}{'branch':>8}{'bound':>7}{'MDS':>6}{'zeros':>7}{'nnz':>6}{'zeros(M^2)':>12}"
    print(hdr)
    print("-" * len(hdr))
    for r in rows:
        print(f"{r['name']:<28}{r['t']:>3}{r['branch']:>8}{r['mds_bound']:>7}"
              f"{str(r['is_mds']):>6}{r['zeros']:>7}{r['nnz']:>6}{r['zeros_M2']:>12}")


def main():
    for p, plabel in [(GOLDILOCKS_P, "Goldilocks 2^64-2^32+1"),
                      (PROXY_PRIME_30, "msolve proxy 1073742091")]:
        print(f"\n=== field F_p, p = {plabel} ===")
        rows = []
        for kname, K in COMPLEXES:
            t = K.n
            branches = []
            worst = best = None
            for seed in SEEDS:
                M = sheaf_mix_matrix(K, p, seed)
                r = analyze(f"sheaf[{kname}] seed={seed.decode()}", M, p)
                branches.append(r["branch"])
                if worst is None or r["branch"] < worst["branch"]:
                    worst = r
                if best is None or r["branch"] > best["branch"]:
                    best = r
            summary = dict(best)
            summary["name"] = f"sheaf[{kname}] (5 seeds)"
            summary["branch"] = f"{min(branches)}-{max(branches)}" if min(branches) != max(branches) else branches[0]
            rows.append(summary)
            rows.append(analyze(f"  cauchy_mds t={t}", cauchy_mds(t, p), p))
            if t == 4:
                rows.append(analyze("  poseidon2_M4", poseidon2_m4(p), p))
        report(rows)
    print("\nNotes:")
    print(" * zeros = zero entries of M; any zero entry breaks a 1x1 minor -> not MDS.")
    print(" * nnz = F_p multiplications per M application (Poseidon2 applies M4 in")
    print("   8 additions + doublings, i.e. ~0 generic mults - its structure is the cost story).")
    print(" * zeros(M^2) = 0 means full diffusion after composing 2 mixing layers.")


if __name__ == "__main__":
    main()
