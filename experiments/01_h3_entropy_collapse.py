"""
experiments/01_h3_entropy_collapse.py — measure the H3 entropy collapse and
confirm the Phase-0 fix. Deterministic (fixed seeds).

H3: the old key sampling drew  int(rng.integers(0, 2**62)) % (p**d)  for β and L.
At PQ-128 (p = 2^61-1, d = 6, |F_q| ~ 2^366) the draw never exceeds 2^62, so the
field element (via positional base-p encoding) is (a0, a1, 0, 0, 0, 0) with
a1 ∈ {0,1,2,3}: β and L are confined to a ~2^62 near-scalar subset. Effective
key entropy per element collapses from ~366 bits to ~62 bits — and under Grover
that halves to ~31 bits, by itself invalidating the 147-bit quantum claim.

This script quantifies:
  (A) OLD sampler: distribution of nonzero coordinates and empirical support size.
  (B) NEW sampler (crypto.sampling.random_fq_element): full-field coverage.

Run: python experiments/01_h3_entropy_collapse.py
"""
import os
import sys
import math

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from crypto.field_pd import make_field
from crypto.sampling import random_fq_element

SEED = 20260705
P = 2**61 - 1
D = 6
N = 2000


def old_sampler_int(rng, p, d):
    """Reproduces the buggy draw: int(rng.integers(0, 2**62)) % (p**d)."""
    return int(rng.integers(0, 2**62)) % (p ** d)


def coord_stats(int_samples, F):
    """For a list of integer codes, return per-coordinate nonzero fraction."""
    d = F.d
    nz = [0] * d
    a1_values = set()
    for n in int_samples:
        coords = F.from_int(n)
        for i in range(d):
            if coords[i] != 0:
                nz[i] += 1
        a1_values.add(coords[1])
    return [c / len(int_samples) for c in nz], a1_values


def main():
    F = make_field(P, D)
    print(f"# H3 entropy-collapse measurement (seed={SEED}, p=2^61-1, d={D}, N={N})")
    print(f"# field size |F_q| = p^d ~ 2^{math.log2(P**D):.1f}\n")

    # (A) OLD sampler
    rng = np.random.default_rng(SEED)
    old_ints = [old_sampler_int(rng, P, D) for _ in range(N)]
    old_nz, old_a1 = coord_stats(old_ints, F)
    max_int = max(old_ints)
    print("(A) OLD sampler  int(rng.integers(0,2**62)) % p^d")
    print(f"    max integer drawn        : 2^{math.log2(max_int):.1f} (field allows 2^{math.log2(P**D):.1f})")
    print(f"    per-coord nonzero frac   : {[round(x,3) for x in old_nz]}")
    print(f"    distinct a1 (coord 1)    : {sorted(old_a1)}")
    print(f"    => coords 2..{D-1} are ALWAYS zero: {all(old_nz[i]==0 for i in range(2,D))}")
    print(f"    effective entropy/elem   : ~{math.log2(max_int):.0f} bits (Grover: ~{math.log2(max_int)/2:.0f} bits)\n")

    # (B) NEW sampler
    rng = np.random.default_rng(SEED)
    new_ints = [F.to_int(random_fq_element(F, rng, exclude_ints=(0, 1))) for _ in range(N)]
    new_nz, _ = coord_stats(new_ints, F)
    expected = (P - 1) / P
    print("(B) NEW sampler  random_fq_element (rejection over [0, p^d))")
    print(f"    per-coord nonzero frac   : {[round(x,3) for x in new_nz]}")
    print(f"    expected (p-1)/p         : {expected:.3f}")
    print(f"    all coords vary          : {all(new_nz[i]>0.9 for i in range(D))}")
    print(f"    effective entropy/elem   : ~{math.log2(P**D):.0f} bits (Grover: ~{math.log2(P**D)/2:.0f} bits)\n")

    ok = all(old_nz[i] == 0 for i in range(2, D)) and all(new_nz[i] > 0.9 for i in range(D))
    print(f"RESULT: H3 reproduced on OLD sampler and fixed on NEW sampler: {ok}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
