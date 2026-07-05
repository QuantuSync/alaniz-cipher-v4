"""
crypto/spn_field.py — field and S-box for the AO SPN permutation (Phase 2a).

Design decisions (rationale in docs/SPN_SPEC.md §1-2):

  * Target field: **Goldilocks** p = 2^64 - 2^32 + 1. Standard AO field
    (Plonky2/3), fast native 64-bit arithmetic, and Poseidon2 has a reference
    instantiation over it — the direct competitor for the mixing-layer study.
  * S-box: x -> x^d with d the MINIMAL exponent such that gcd(d, p-1) = 1
    (bijective power map of lowest degree). For Goldilocks
    p - 1 = 2^32 · 3 · 5 · 17 · 257 · 65537, so 3 and 5 divide p-1 and the
    minimum is **d = 7** (matches Plonky2's x^7). Governing lesson from the
    A6-CICO break: degree grows by ROUND COMPOSITION, never by an expensive
    one-shot S-box.
  * msolve (the Groebner engine, WSL) only supports characteristic < 2^31, so
    the attack experiments run over **proxy primes** that replicate the
    Goldilocks exponent structure: 3 | p'-1, 5 | p'-1, 7 ∤ p'-1, which forces
    the same minimal d = 7. PROXY_PRIMES pins one tiny prime (exhaustive
    tests), one 16-bit and one 30-bit prime (msolve scale).
"""
from __future__ import annotations

from math import gcd

GOLDILOCKS_P = 2**64 - 2**32 + 1

# p - 1 = 2^32 · 3 · 5 · 17 · 257 · 65537 (asserted in tests/test_spn.py)
GOLDILOCKS_P_MINUS_1_FACTORIZATION = ((2, 32), (3, 1), (5, 1), (17, 1), (257, 1), (65537, 1))

# Goldilocks-like proxy primes for msolve (char < 2^31): 3·5 | p-1, 7 ∤ p-1,
# hence min bijective exponent = 7, same as Goldilocks. Values verified by
# tests/test_spn.py::test_proxy_primes_mimic_goldilocks.
PROXY_PRIME_TINY = 31            # p-1 = 2·3·5; exhaustive bijectivity tests
PROXY_PRIME_16 = 65551           # smallest such prime >= 2^16
PROXY_PRIME_30 = 1073742091      # smallest such prime >= 2^30
PROXY_PRIMES = (PROXY_PRIME_TINY, PROXY_PRIME_16, PROXY_PRIME_30)


def is_prime(n: int) -> bool:
    """Deterministic Miller-Rabin for n < 3.3·10^24 (fixed witness set)."""
    if n < 2:
        return False
    for q in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % q == 0:
            return n == q
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def min_bijective_exponent(p: int) -> int:
    """Smallest d >= 2 with gcd(d, p-1) = 1, i.e. x^d is a bijection of F_p."""
    d = 2
    while gcd(d, p - 1) != 1:
        d += 1
    return d


def sbox_exponents(p: int, d: int | None = None) -> tuple:
    """Return (d, d_inv) with x -> x^d bijective on F_p and (x^d)^{d_inv} = x.

    d defaults to the minimal bijective exponent. Raises if gcd(d, p-1) != 1.
    """
    if d is None:
        d = min_bijective_exponent(p)
    if gcd(d, p - 1) != 1:
        raise ValueError(f"x^{d} is not a bijection of F_{p}: gcd(d, p-1) != 1")
    return d, pow(d, -1, p - 1)


def sbox(x: int, p: int, d: int) -> int:
    """S-box x -> x^d over F_p."""
    return pow(x, d, p)


def sbox_inv(y: int, p: int, d_inv: int) -> int:
    """Inverse S-box y -> y^{d_inv} over F_p."""
    return pow(y, d_inv, p)


def is_goldilocks_like(p: int) -> bool:
    """True iff p is prime, 3 | p-1, 5 | p-1 and 7 ∤ p-1 (min exponent = 7)."""
    return (
        is_prime(p)
        and (p - 1) % 3 == 0
        and (p - 1) % 5 == 0
        and (p - 1) % 7 != 0
    )


def find_goldilocks_like_prime(start: int) -> int:
    """Smallest Goldilocks-like proxy prime >= start (see module docstring)."""
    # p ≡ 1 (mod 15) is necessary; scan that residue class.
    p = start + ((1 - start) % 15)
    while not is_goldilocks_like(p):
        p += 15
    return p
