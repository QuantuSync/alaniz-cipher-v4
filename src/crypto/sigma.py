"""
crypto/sigma.py — Vector-valued nonlinear map σ in F_{p^d}.

Reuses the v3 design: σ(y) = y + ι⁻¹(π_e(L · ι(y) + 1))
where π_e(x) = x^e is a monomial power permutation in F_{p^d}.

For v4 we keep this primitive unchanged. The novelty is in the surrounding
sheaf structure, not in σ.
"""
from __future__ import annotations
import numpy as np
import galois
from math import gcd


def find_secure_exponent(p: int, d: int) -> int:
    """Smallest e ≥ 3 with gcd(e, p^d − 1) = 1 (so π_e is a bijection)."""
    order = p ** d - 1
    for e in [3, 5, 7, 11, 13, 17, 19, 23]:
        if gcd(e, order) == 1:
            return e
    e = 3
    while gcd(e, order) != 1:
        e += 2
    return e


class SigmaV4:
    """
    σ : F_p^d → F_p^d, defined as
       σ(y) = y + ι⁻¹(π_e(L · ι(y) + 1))
    where ι : F_p^d → F_{p^d} is the canonical vector ↔ field-element bijection,
    π_e(x) = x^e, and L ∈ F_{p^d}^* is part of the public parameters.
    """

    def __init__(self, p: int, d: int, exponent: int | None = None,
                 L_gf=None, rng=None):
        self.p = p
        self.d = d
        self.GF_ext = galois.GF(p ** d, repr="poly")
        self.GF_p = galois.GF(p)
        self.exponent = exponent or find_secure_exponent(p, d)

        if L_gf is None:
            rng = rng or np.random.default_rng(0xABCD)
            order_minus_1 = p ** d - 1
            while True:
                # Use Python ints to avoid int64 overflow at d=6, p ≥ 2^11
                val = int(rng.integers(0, 2**62)) % order_minus_1 + 1
                cand = self.GF_ext(val)
                if int(cand) != 0:
                    L_gf = cand
                    break
        self.L_gf = L_gf
        self.one = self.GF_ext(1)

    # ---------------- vec ↔ field bijection ----------------

    def vec_to_gf(self, v: np.ndarray):
        """Map (a_0, ..., a_{d-1}) ∈ F_p^d to a_0 + a_1 X + ... + a_{d-1} X^{d-1} ∈ F_{p^d}."""
        v = np.asarray(v, dtype=np.int64) % self.p
        # galois interprets integer as polynomial-coefficient encoding
        idx = 0
        for i in range(self.d - 1, -1, -1):
            idx = idx * self.p + int(v[i])
        return self.GF_ext(idx)

    def gf_to_vec(self, g) -> np.ndarray:
        n = int(g)
        out = np.zeros(self.d, dtype=np.int64)
        for i in range(self.d):
            out[i] = n % self.p
            n //= self.p
        return out

    # ---------------- forward σ ----------------

    def __call__(self, y: np.ndarray) -> np.ndarray:
        y_gf = self.vec_to_gf(y)
        inner = self.L_gf * y_gf + self.one
        powered = inner ** self.exponent
        tail = self.gf_to_vec(powered)
        return np.array([(int(y[i]) + int(tail[i])) % self.p
                         for i in range(self.d)], dtype=np.int64)

    def __repr__(self):
        return f"σ_v4(p={self.p}, d={self.d}, e={self.exponent}, L={int(self.L_gf)})"
