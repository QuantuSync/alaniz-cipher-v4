"""
tests/test_sampling.py — unbiased sampling helpers (Phase-0 H3 fix).

Verifies:
  - uniform_int_below stays in range and is (approximately) uniform;
  - random_fq_element uses the FULL field F_{p^d} (the H3 regression: β and L
    must NOT collapse to the near-scalar subset (a0, a1, 0, ..., 0));
  - random_fq_element honours exclusions ({0}, {0,1});
  - random_invertible_matrix_fp yields invertible matrices with in-range entries;
  - prg_vec is deterministic, domain-separated, and in range.
"""
import os
import sys

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from crypto.field_pd import make_field
from crypto.linalg_fp import matrix_det_fp
from crypto.sampling import (uniform_int_below, random_fq_element,
                             random_invertible_matrix_fp, prg_vec)


def test_uniform_int_below_in_range():
    rng = np.random.default_rng(123)
    N = 1000
    vals = [uniform_int_below(rng, N) for _ in range(5000)]
    assert all(0 <= v < N for v in vals)
    assert min(vals) < N * 0.1 and max(vals) > N * 0.9  # covers the range


def test_uniform_int_below_no_modulo_bias():
    """Residues of a non-power-of-two modulus should be ~uniform."""
    rng = np.random.default_rng(7)
    N = 7  # not a power of 2 → the buggy `% ` approach would bias
    counts = [0] * N
    trials = 70000
    for _ in range(trials):
        counts[uniform_int_below(rng, N)] += 1
    expected = trials / N
    # Each bucket within 5% of expected (loose, deterministic seed).
    for c in counts:
        assert abs(c - expected) < 0.05 * expected, counts


def test_random_fq_element_uses_full_field():
    """H3 regression: every coordinate position must genuinely vary.

    Old buggy sampling produced (a0, a1, 0, 0, 0, 0) with a1 in {0,1,2,3};
    coordinates 2..d-1 were ALWAYS zero. This test fails on that code.
    """
    F = make_field(257, 6)
    rng = np.random.default_rng(2024)
    samples = [random_fq_element(F, rng, exclude_ints=(0, 1)) for _ in range(300)]
    for i in range(F.d):
        col = [s[i] for s in samples]
        assert len(set(col)) > 1, f"coordinate {i} never varies (H3 collapse)"
        nonzero_frac = sum(1 for x in col if x != 0) / len(col)
        # For a uniform field element each coordinate is nonzero w.p. (p-1)/p.
        assert nonzero_frac > 0.9, f"coordinate {i} nonzero frac {nonzero_frac}"


def test_random_fq_element_excludes():
    F = make_field(97, 3)
    rng = np.random.default_rng(5)
    zero = F.zero()
    one = F.one()
    for _ in range(500):
        x = random_fq_element(F, rng, exclude_ints=(0, 1))
        assert x != zero and x != one


def test_random_invertible_matrix_fp():
    rng = np.random.default_rng(11)
    p, d = 257, 6
    for _ in range(20):
        M = random_invertible_matrix_fp(p, d, rng)
        assert len(M) == d and all(len(row) == d for row in M)
        assert all(0 <= x < p for row in M for x in row)
        assert matrix_det_fp(M, p) != 0


def test_prg_vec_deterministic_and_in_range():
    nonce = b"\x01" * 16
    a = prg_vec(nonce, "v", 3, 6, 257)
    b = prg_vec(nonce, "v", 3, 6, 257)
    assert a == b
    assert len(a) == 6 and all(0 <= x < 257 for x in a)


def test_prg_vec_domain_separation():
    nonce = b"\x02" * 16
    base = prg_vec(nonce, "v", 0, 6, 257)
    assert prg_vec(nonce, "v", 1, 6, 257) != base          # idx separated
    assert prg_vec(nonce, "w", 0, 6, 257) != base          # label separated
    assert prg_vec(b"\x03" * 16, "v", 0, 6, 257) != base   # nonce separated
