"""
crypto/field_pd.py — Minimal F_{p^d} arithmetic for huge primes.

galois library hangs constructing GF(p^d) for p ≥ 2^21 due to lookup tables.
This module provides a minimal pure-Python implementation suitable for
PQ-128 size parameters (p ≈ 2^61, d=6), at the cost of slower per-operation
times relative to galois's JIT-compiled paths.

Element representation: tuple (a_0, a_1, ..., a_{d-1}) of Python ints,
representing a_0 + a_1·X + ... + a_{d-1}·X^{d-1} ∈ F_p[X] / (irr(X)).
"""
from __future__ import annotations
from dataclasses import dataclass


@dataclass(frozen=True)
class FpdField:
    p: int
    d: int
    irr_coeffs: tuple   # (c_0, c_1, ..., c_d) representing X^d + ... ;
                        # last entry must be 1 (monic)

    def add(self, a: tuple, b: tuple) -> tuple:
        return tuple((a[i] + b[i]) % self.p for i in range(self.d))

    def sub(self, a: tuple, b: tuple) -> tuple:
        return tuple((a[i] - b[i]) % self.p for i in range(self.d))

    def neg(self, a: tuple) -> tuple:
        return tuple((-a[i]) % self.p for i in range(self.d))

    def mul(self, a: tuple, b: tuple) -> tuple:
        # Schoolbook polynomial multiplication, then reduce.
        # Optimisations:
        #   (1) defer mod-p to once-per-output (instead of per inner step);
        #   (2) skip zero coefficients in irr (sparse irrs like X^d + a·X + b
        #       gain dramatically).
        d = self.d
        p = self.p
        irr = self.irr_coeffs

        # Step 1: convolution with deferred mod
        prod = [0] * (2 * d - 1)
        for i in range(d):
            ai = a[i]
            if ai == 0: continue
            for j in range(d):
                bj = b[j]
                if bj == 0: continue
                prod[i + j] += ai * bj
        # Apply mod once (each accumulator is bounded by d·(p-1)² so Python
        # big ints handle this fine).
        for i in range(2 * d - 1):
            prod[i] %= p

        # Step 2: reduce mod irr, skipping zero coefficients of irr
        # Pre-compute list of non-zero positions in irr[0..d-1]
        nz_irr = [(i, irr[i]) for i in range(d) if irr[i] != 0]
        for k in range(2 * d - 2, d - 1, -1):
            coef = prod[k]
            if coef == 0:
                continue
            prod[k] = 0
            base = k - d
            for i, irr_i in nz_irr:
                prod[base + i] = (prod[base + i] - coef * irr_i) % p
        return tuple(prod[:d])

    def pow(self, a: tuple, exp: int) -> tuple:
        # Square-and-multiply
        result = self.one()
        base = a
        e = exp
        while e > 0:
            if e & 1:
                result = self.mul(result, base)
            base = self.mul(base, base)
            e >>= 1
        return result

    def inv(self, a: tuple) -> tuple:
        # By Fermat: a^(-1) = a^(p^d - 2)
        return self.pow(a, self.p ** self.d - 2)

    def zero(self) -> tuple:
        return tuple([0] * self.d)

    def one(self) -> tuple:
        return tuple([1] + [0] * (self.d - 1))

    def from_int(self, n: int) -> tuple:
        """Map integer n in [0, p^d) to element via positional encoding:
            n = a_0 + a_1 p + ... + a_{d-1} p^{d-1}"""
        n = n % (self.p ** self.d)
        out = []
        for _ in range(self.d):
            out.append(n % self.p)
            n //= self.p
        return tuple(out)

    def from_scalar(self, n: int) -> tuple:
        """Embed integer n as F_p scalar in F_q: returns (n mod p, 0, ..., 0).
        Different from from_int (which uses positional encoding for arbitrary
        F_q elements). Use this for true scalar quantities like binomial
        coefficients or small integer exponent multipliers."""
        return (n % self.p,) + (0,) * (self.d - 1)

    def to_int(self, a: tuple) -> int:
        n = 0
        for i in range(self.d - 1, -1, -1):
            n = n * self.p + a[i]
        return n

    def is_zero(self, a: tuple) -> bool:
        return all(x == 0 for x in a)

    def equals(self, a: tuple, b: tuple) -> bool:
        return a == b


# ─────────────────────────── Common irreducible polynomials ───────────────────────────

def find_irreducible(p: int, d: int):
    """
    Find an irreducible polynomial of degree d over F_p, return its
    coefficients in ASCENDING order [c_0, c_1, ..., c_d] with c_d = 1.

    Reference path is galois-free: we always use the pure-Python Rabin
    test (`crypto.irreducible.find_irreducible_rabin`). That routine itself
    tries `galois.irreducible_poly` only as an optional accelerator for
    d ≤ 3 and falls back to Rabin when galois is absent, so this function
    never *requires* galois.

    Any irreducible polynomial of degree d defines the same field F_{p^d}
    up to isomorphism; the specific choice only needs to be consistent
    within a run (it is: the field is built once per setup).
    """
    from crypto.irreducible import find_irreducible_rabin
    return find_irreducible_rabin(p, d)


def make_field(p: int, d: int) -> FpdField:
    asc = find_irreducible(p, d)
    return FpdField(p=p, d=d, irr_coeffs=tuple(asc))
