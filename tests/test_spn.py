"""
tests/test_spn.py — Phase 2 (AO SPN): field/S-box (2a) and mixing layer (2b).

Verifies:
  - Goldilocks factorization of p-1 and minimal bijective exponent d = 7;
  - x^7 is an exhaustive bijection on the tiny proxy prime (structure-identical
    to Goldilocks: 3,5 | p-1, 7 !| p-1) and roundtrips on Goldilocks;
  - proxy primes mimic the Goldilocks exponent structure and fit msolve (<2^31);
  - matrix_rank_fp on rectangular matrices;
  - Cauchy reference is MDS (branch t+1) and is_mds <-> branch == t+1;
  - sheaf mixing matrix: symmetric, zero pattern = non-adjacency, K4 dense;
  - pinned Phase-2b gate results (fixed seed, Goldilocks): branch numbers
    5 / 5 / 6 for tetrahedron / double_tet / octahedron (bounds 5 / 6 / 7).
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from core.complex2d import Complex2D
from crypto.linalg_fp import matrix_rank_fp
from crypto.spn_field import (
    GOLDILOCKS_P, GOLDILOCKS_P_MINUS_1_FACTORIZATION, PROXY_PRIMES,
    PROXY_PRIME_TINY, PROXY_PRIME_30, find_goldilocks_like_prime,
    is_goldilocks_like, is_prime, min_bijective_exponent, sbox, sbox_exponents,
    sbox_inv,
)
from crypto.spn_mix import (
    branch_number, cauchy_mds, is_mds, poseidon2_m4, sheaf_mix_matrix,
    zero_entries,
)
from crypto.spn_permutation import SPNParams, permute, permute_inverse
from crypto.spn_cico import build_cico_system, to_msolve


# ─────────────────────────── 2a: field & S-box ───────────────────────────

def test_goldilocks_factorization():
    prod = 1
    for q, k in GOLDILOCKS_P_MINUS_1_FACTORIZATION:
        assert is_prime(q)
        prod *= q ** k
    assert prod == GOLDILOCKS_P - 1
    assert is_prime(GOLDILOCKS_P)


def test_goldilocks_min_exponent_is_7():
    assert min_bijective_exponent(GOLDILOCKS_P) == 7
    d, d_inv = sbox_exponents(GOLDILOCKS_P)
    assert d == 7
    assert (d * d_inv) % (GOLDILOCKS_P - 1) == 1


def test_sbox_bijective_exhaustive_tiny_proxy():
    p = PROXY_PRIME_TINY  # 31: p-1 = 2·3·5, same exponent structure
    d, d_inv = sbox_exponents(p)
    assert d == 7
    images = {sbox(x, p, d) for x in range(p)}
    assert images == set(range(p))  # bijection
    for x in range(p):
        assert sbox_inv(sbox(x, p, d), p, d_inv) == x


def test_sbox_roundtrip_goldilocks():
    p = GOLDILOCKS_P
    d, d_inv = sbox_exponents(p)
    for x in (0, 1, 2, p - 1, 0xDEADBEEF, 3141592653589793238 % p):
        assert sbox_inv(sbox(x, p, d), p, d_inv) == x


def test_proxy_primes_mimic_goldilocks():
    for q in PROXY_PRIMES:
        assert is_goldilocks_like(q)
        assert min_bijective_exponent(q) == 7
        assert q < 2**31  # msolve characteristic limit
    # 16-bit tier is the largest Goldilocks-like prime BELOW 2^16 (msolve
    # segfaults on 65551 and other primes just above 2^16 -- see spn_field).
    assert PROXY_PRIMES[1] < 2**16
    assert find_goldilocks_like_prime(2**30) == PROXY_PRIMES[2]


def test_rejects_non_bijective_exponent():
    import pytest
    with pytest.raises(ValueError):
        sbox_exponents(GOLDILOCKS_P, d=3)  # 3 | p-1


# ─────────────────────────── 2b: mixing layer ───────────────────────────

def test_matrix_rank_fp_rectangular():
    p = 101
    assert matrix_rank_fp([], p) == 0
    assert matrix_rank_fp([[0, 0], [0, 0]], p) == 0
    assert matrix_rank_fp([[1, 2, 3]], p) == 1
    assert matrix_rank_fp([[1, 2], [2, 4], [0, 1]], p) == 2
    assert matrix_rank_fp([[1, 2], [2, 4 % p]], p) == 1


def test_cauchy_is_mds_and_crosscheck():
    p = 101
    for t in (3, 4, 5, 6):
        C = cauchy_mds(t, p)
        assert is_mds(C, p)
        assert branch_number(C, p) == t + 1


def test_poseidon2_m4_is_mds_over_goldilocks():
    M = poseidon2_m4(GOLDILOCKS_P)
    assert is_mds(M, GOLDILOCKS_P)
    assert branch_number(M, GOLDILOCKS_P) == 5


def test_sheaf_matrix_structure():
    p = GOLDILOCKS_P
    for K in (Complex2D.tetrahedron(), Complex2D.double_tetrahedron(),
              Complex2D.octahedron()):
        M = sheaf_mix_matrix(K, p, b"structure-seed")
        assert all(M[i][j] == M[j][i] for i in range(K.n) for j in range(K.n))
        non_adjacent = {(u, v) for u in range(K.n) for v in range(K.n)
                        if u != v and tuple(sorted((u, v))) not in K.edge_idx}
        assert set(zero_entries(M)) <= non_adjacent
        # complete 1-skeleton (K4) -> dense; missing edges -> those exact zeros
        if K.n == 4:
            assert zero_entries(M) == []


def test_gate2b_pinned_branch_numbers_goldilocks():
    """Phase-2b gate results, pinned as regression (seed spn-mix-seed-0)."""
    p = GOLDILOCKS_P
    seed = b"spn-mix-seed-0"
    expected = {
        "tetrahedron": (Complex2D.tetrahedron(), 5, True),    # MDS bound 5
        "double_tet": (Complex2D.double_tetrahedron(), 5, False),  # bound 6
        "octahedron": (Complex2D.octahedron(), 6, False),     # bound 7
    }
    for name, (K, want_branch, want_mds) in expected.items():
        M = sheaf_mix_matrix(K, p, seed)
        assert branch_number(M, p) == want_branch, name
        assert is_mds(M, p) == want_mds, name


# ─────────────────────────── 3a: SPN permutation ───────────────────────────

def test_spn_permutation_is_bijective_small_exhaustive():
    """x^7 SPN over a tiny Goldilocks-like prime is a bijection; exhaustive on a
    reduced 1-vertex-free slice is too large, so check the round map is invertible
    on random points and that permute/permute_inverse roundtrip."""
    p = PROXY_PRIMES[0]  # 31
    for R in (1, 2, 3):
        prm = SPNParams(Complex2D.tetrahedron(), p, R)
        seen = set()
        # sample a chunk of the domain; every image must be distinct (injective)
        for a in range(0, p, 3):
            x = [a, (a * 7) % p, (a * 13) % p, (a * 29) % p]
            y = tuple(permute(prm, x))
            assert y not in seen
            seen.add(y)
            assert permute_inverse(prm, list(y)) == x


def test_spn_permutation_roundtrip_goldilocks():
    p = GOLDILOCKS_P
    for t_complex in (Complex2D.tetrahedron(), Complex2D.octahedron()):
        for R in (1, 4, 8):
            prm = SPNParams(t_complex, p, R)
            x = [i * 123456789 % p for i in range(t_complex.n)]
            assert permute_inverse(prm, permute(prm, x)) == x


# ─────────────────────────── 3b: CICO model ───────────────────────────

def test_cico_system_is_consistent_at_witness():
    """The generated CICO system must vanish at the witness it is built from
    (guards the msolve pipeline: an inconsistent build would read as a spurious
    'no solution')."""
    p = PROXY_PRIME_30
    for K in (Complex2D.tetrahedron(), Complex2D.octahedron()):
        for R in (1, 2, 3):
            for c in (1, K.n - 1):
                prm = SPNParams(K, p, R)
                variables, polys, meta = build_cico_system(prm, c=c)
                assert meta["n_vars"] == meta["n_eqs"] == K.n * R
                val = {}
                for r, st in enumerate(meta["states"]):
                    for i, x in enumerate(st):
                        val[f"x{r}_{i}"] = x % p
                for poly in polys:
                    expr = poly
                    for name, x in sorted(val.items(), key=lambda kv: -len(kv[0])):
                        expr = expr.replace(name, str(x))
                    assert eval(expr.replace("^", "**")) % p == 0


def test_msolve_serialization_has_no_carriage_returns():
    """msolve mis-parses CRLF; to_msolve output must be LF-only (regression)."""
    p = PROXY_PRIME_30
    prm = SPNParams(Complex2D.tetrahedron(), p, 2)
    variables, polys, _ = build_cico_system(prm, c=1)
    text = to_msolve(variables, polys, p)
    assert "\r" not in text
    lines = text.strip().split("\n")
    assert lines[0] == ",".join(variables)   # variable line
    assert lines[1] == str(p)                 # characteristic line
