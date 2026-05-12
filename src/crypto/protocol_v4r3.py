"""
crypto/protocol_v4r3.py — v4r3 with F_{p^d} field-multiplication coupling.

Replaces v4r2's Hadamard product ⊙ with field multiplication via ι:
    (s_u ⊙_F s_v) := ι⁻¹(ι(s_u) · ι(s_v)) in F_{p^d}

Why this is potentially better than Hadamard:
  - Hadamard couples coordinate-by-coordinate, which means each output
    coordinate of (s_u ⊙ s_v) depends only on the corresponding input
    coordinates. The d output coordinates are algebraically decoupled.
  - Field multiplication in F_{p^d} mixes ALL coordinates: each output
    coordinate of ι⁻¹(ι(s_u) · ι(s_v)) depends on ALL input coordinates of
    s_u and s_v. The bilinear form is the full d×d×d tensor, not the diagonal.
  - This matches the algebraic structure of σ (which already operates in F_{p^d}).

Same encryption pattern, same overall protocol shape, but with the coupling
via ι.
"""
from __future__ import annotations
import os
import numpy as np
import hashlib
import galois
from dataclasses import dataclass
from typing import Optional
from math import comb

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from core.complex2d import Complex2D
from core.sheaf2d import Sheaf2D
from crypto.sigma import SigmaV4


def prg_vec(nonce: bytes, label: str, idx: int, d: int, p: int):
    """Derive a F_p^d vector pseudorandomly from (nonce, label, idx).

    Uses SHAKE-256 as PRG. Standard construction.
    """
    h = hashlib.shake_256()
    h.update(nonce)
    h.update(label.encode())
    h.update(idx.to_bytes(4, "big"))
    bytes_per = max(1, ((p - 1).bit_length() + 7) // 8) + 4
    out = h.digest(bytes_per * d)
    vals = []
    for i in range(d):
        chunk = out[i * bytes_per:(i + 1) * bytes_per]
        vals.append(int.from_bytes(chunk, "big") % p)
    return np.array(vals, dtype=np.int64)


@dataclass
class KeyV4r3:
    A: dict
    beta: dict
    B: dict
    C: dict
    s_reject: bytes


@dataclass
class PublicParamsV4r3:
    K: Complex2D
    sheaf: Sheaf2D
    sigma: SigmaV4

    @classmethod
    def generate(cls, K, d, p, rng=None, exponent=None):
        sheaf = Sheaf2D.cocycle_compatible(K, d, p, rng=rng)
        sigma = SigmaV4(p, d, rng=rng, exponent=exponent)
        return cls(K=K, sheaf=sheaf, sigma=sigma)


class ProtocolV4r3:
    def __init__(self, params):
        self.params = params
        self.K = params.K
        self.sheaf = params.sheaf
        self.sigma = params.sigma
        self.d = params.sheaf.d
        self.p = params.sheaf.p
        self.GF_p = params.sheaf.GF
        self.GF_ext = self.sigma.GF_ext

        self.H0_basis = self.sheaf.H0_basis()
        self.k_msg = self.H0_basis.shape[1]

        self.edges_at = {v: [] for v in range(self.K.n)}
        for e_idx, (u, v) in enumerate(self.K.edges):
            self.edges_at[u].append((e_idx, u, v))
            self.edges_at[v].append((e_idx, u, v))
        self.triangles_at = {v: [] for v in range(self.K.n)}
        for t_idx, t in enumerate(self.K.triangles):
            for v in t:
                self.triangles_at[v].append((t_idx, t))

    def keygen(self, rng=None):
        rng = rng or np.random.default_rng(0xBEEF)
        d, p = self.d, self.p
        A = {v: self._random_gl(rng) for v in range(self.K.n)}
        beta = {}
        order_minus_2 = p ** d - 2
        for v in range(self.K.n):
            while True:
                # Python int to avoid int64 overflow for d ≥ 6 with large p
                cand_int = int(rng.integers(0, 2**62)) % order_minus_2 + 2
                cand = self.GF_ext(cand_int)
                if int(cand) != 0 and int(cand) != 1:
                    beta[v] = cand
                    break
        B = {e_idx: self._random_gl(rng) for e_idx in range(self.K.m)}
        C = {t_idx: self._random_gl(rng) for t_idx in range(self.K.l)}
        s_reject = rng.bytes(32)
        return KeyV4r3(A=A, beta=beta, B=B, C=C, s_reject=s_reject)

    def _random_gl(self, rng):
        d, p = self.d, self.p
        while True:
            M = self.GF_p(rng.integers(0, p, size=(d, d)).astype(np.int64))
            try:
                np.linalg.inv(M)
                return M
            except Exception:
                continue

    def _section_value(self, s_flat, v):
        return s_flat[v * self.d:(v + 1) * self.d]

    def _field_mul(self, a, b):
        """ι⁻¹(ι(a) · ι(b)) — field multiplication via the canonical bijection."""
        a_gf = self.sigma.vec_to_gf(np.array(a, dtype=np.int64))
        b_gf = self.sigma.vec_to_gf(np.array(b, dtype=np.int64))
        prod = a_gf * b_gf
        return self.GF_p(np.array(self.sigma.gf_to_vec(prod), dtype=np.int64))

    def _sigma_v3(self, arg, beta_v):
        arg_np = np.array(arg, dtype=np.int64)
        u = self.sigma.vec_to_gf(arg_np)
        L = self.sigma.L_gf
        powered = (L * u + self.GF_ext(1)) ** self.sigma.exponent
        w = beta_v * u + (beta_v - self.GF_ext(1)) * powered
        return self.GF_p(np.array(self.sigma.gf_to_vec(w), dtype=np.int64))

    def _arg_at_vertex(self, s_flat, key, v):
        s_v = self._section_value(s_flat, v)
        arg = key.A[v] @ s_v
        for e_idx, u, w in self.edges_at[v]:
            other = u if w == v else w
            s_other = self._section_value(s_flat, other)
            arg = arg + key.B[e_idx] @ self._field_mul(s_other, s_v)
        for t_idx, t in self.triangles_at[v]:
            others = [x for x in t if x != v]
            s_a = self._section_value(s_flat, others[0])
            s_b = self._section_value(s_flat, others[1])
            triple = self._field_mul(self._field_mul(s_a, s_v), s_b)
            arg = arg + key.C[t_idx] @ triple
        return arg

    def encrypt(self, s_flat, key, nonce: bytes | None = None):
        if nonce is None:
            nonce = os.urandom(16)
        if not self.sheaf.is_global_section(s_flat):
            raise ValueError("Plaintext must be in H⁰")
        c = self.GF_p.Zeros(self.K.n * self.d)
        for v in range(self.K.n):
            r_v = self.GF_p(prg_vec(nonce, "v", v, self.d, self.p))
            arg = self._arg_at_vertex(s_flat, key, v) + r_v
            z_v = self._sigma_v3(arg, key.beta[v])
            c[v * self.d:(v + 1) * self.d] = z_v - r_v
        return nonce, c

    def decrypt_brute(self, nonce, c, key) -> Optional[np.ndarray]:
        from itertools import product as iproduct
        p, k = self.p, self.k_msg
        for coeffs in iproduct(range(p), repeat=k):
            cand_alpha = self.GF_p(np.array(coeffs, dtype=np.int64))
            s = self.H0_basis @ cand_alpha
            try:
                _, c_check = self.encrypt(s, key, nonce=nonce)
            except Exception:
                continue
            if np.all(c_check == c):
                return s
        return None
