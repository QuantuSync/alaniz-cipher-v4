"""
crypto/protocol_v4r3_pq128.py — v4r3 keygen + encrypt at PQ-128 parameters.

Bypasses the galois dependency for F_{p^d} (which can't construct fields
with p > ~2^21 in reasonable time) by using the hand-rolled FpdField in
crypto/field_pd.py.

This module ONLY supports keygen and encrypt — decryption is not implemented
because the algebraic decryptor uses sympy.GF, which has poor performance
at d=6 on our hardware. Full decryption at PQ-128 scale would require
msolve/magma or a hand-rolled F4 implementation.
"""
from __future__ import annotations
import os
import hashlib
import time
import numpy as np
from dataclasses import dataclass

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from core.complex2d import Complex2D
from crypto.field_pd import FpdField, make_field


# ─────────────────────────── F_p arithmetic helpers ───────────────────────────

def random_invertible_matrix(p: int, d: int, rng: np.random.Generator) -> list:
    """Generate a random d×d invertible matrix over F_p. Uses Gauss check."""
    while True:
        M = [[int(rng.integers(0, 2**62)) % p for _ in range(d)] for _ in range(d)]
        # Compute determinant via Gaussian elimination mod p
        if matrix_det_fp(M, p) != 0:
            return M


def matrix_det_fp(M: list, p: int) -> int:
    """Determinant of d×d matrix over F_p."""
    d = len(M)
    A = [row[:] for row in M]
    sign = 1
    for col in range(d):
        # Find pivot
        pv = -1
        for r in range(col, d):
            if A[r][col] % p != 0:
                pv = r; break
        if pv == -1:
            return 0
        if pv != col:
            A[col], A[pv] = A[pv], A[col]
            sign = -sign
        inv = pow(A[col][col], p - 2, p)
        for r in range(col + 1, d):
            factor = (A[r][col] * inv) % p
            for c in range(col, d):
                A[r][c] = (A[r][c] - factor * A[col][c]) % p
    det = sign
    for i in range(d):
        det = (det * A[i][i]) % p
    return det % p


def matvec_mul_fp(M: list, v: list, p: int) -> list:
    """Matrix-vector product M·v over F_p."""
    d = len(M)
    out = []
    for i in range(d):
        s = 0
        for j in range(d):
            s = (s + M[i][j] * v[j]) % p
        out.append(s)
    return out


def vec_add_fp(a: list, b: list, p: int) -> list:
    return [(a[i] + b[i]) % p for i in range(len(a))]


def vec_sub_fp(a: list, b: list, p: int) -> list:
    return [(a[i] - b[i]) % p for i in range(len(a))]


# ─────────────────────────── PRG for nonces ───────────────────────────

def prg_vec(nonce: bytes, label: str, idx: int, d: int, p: int) -> list:
    """F_p^d vector pseudorandom from (nonce, label, idx)."""
    h = hashlib.shake_256()
    h.update(nonce)
    h.update(label.encode())
    h.update(idx.to_bytes(4, "big"))
    bits_per = (p - 1).bit_length() + 16
    bytes_per = (bits_per + 7) // 8
    out_bytes = h.digest(bytes_per * d)
    vals = []
    for i in range(d):
        chunk = out_bytes[i * bytes_per:(i + 1) * bytes_per]
        vals.append(int.from_bytes(chunk, "big") % p)
    return vals


# ─────────────────────────── Sigma_v3 in field form ───────────────────────────

def sigma_v3(F: FpdField, arg_vec: list, beta: tuple, L: tuple, e: int) -> list:
    """σ_v3(arg) = ι⁻¹(β · ι(arg) + (β-1) · (L · ι(arg) + 1)^e)."""
    arg_gf = tuple(arg_vec)        # already polynomial-coefficient form
    L_arg = F.mul(L, arg_gf)
    one = F.one()
    L_arg_plus_1 = F.add(L_arg, one)
    powered = F.pow(L_arg_plus_1, e)
    beta_minus_1 = F.sub(beta, one)
    term1 = F.mul(beta, arg_gf)
    term2 = F.mul(beta_minus_1, powered)
    out = F.add(term1, term2)
    return list(out)


# ─────────────────────────── Public params + key ───────────────────────────

@dataclass
class KeyPQ128:
    A: dict
    beta: dict          # vertex -> tuple (F_{p^d} element)
    B: dict
    C: dict


@dataclass
class ParamsPQ128:
    K: Complex2D
    F: FpdField
    L: tuple                    # F_{p^d} element
    exponent: int
    d: int
    p: int
    H0_basis: list              # list of column vectors
    rho_ve: dict
    rho_et: dict


def find_secure_exponent(p: int, d: int) -> int:
    """Smallest e ≥ 3 with gcd(e, p^d − 1) = 1."""
    from math import gcd
    order = p ** d - 1
    for e in [3, 5, 7, 11, 13, 17, 19, 23, 29, 31]:
        if gcd(e, order) == 1:
            return e
    e = 3
    while gcd(e, order) != 1:
        e += 2
    return e


def gen_h0_basis(K: Complex2D, d: int, p: int, rng) -> tuple:
    """Generate cocycle-compatible sheaf and H0 basis of dim d.

    Strategy from sheaf2d.cocycle_compatible: choose ρ_{w,e} = M_e · T_w with
    M_e and T_w independent invertible. Sections are s_v = T_v^{-1} · α for
    α ∈ F_p^d arbitrary.
    """
    # Generate T_v invertible per vertex
    T = {v: random_invertible_matrix(p, d, rng) for v in range(K.n)}
    # rho_ve = M_e · T_w
    rho_ve = {}
    for e_idx, (u, v) in enumerate(K.edges):
        M_e = random_invertible_matrix(p, d, rng)
        rho_ve[(u, e_idx)] = matrix_mul_fp(M_e, T[u], p)
        rho_ve[(v, e_idx)] = matrix_mul_fp(M_e, T[v], p)
    rho_et = {}
    for t_idx, t in enumerate(K.triangles):
        u, v, w = t
        for e in [(u, v), (u, w), (v, w)]:
            e_idx = K.edge_idx[e]
            rho_et[(e_idx, t_idx)] = random_invertible_matrix(p, d, rng)

    # H0 basis: for each canonical α basis vector, the section is s_v = T_v^{-1} · α.
    H0_basis = []
    for alpha_idx in range(d):
        alpha = [1 if i == alpha_idx else 0 for i in range(d)]
        section = []
        for v in range(K.n):
            T_v_inv = matrix_inverse_fp(T[v], p)
            s_v = matvec_mul_fp(T_v_inv, alpha, p)
            section.extend(s_v)
        H0_basis.append(section)
    # Return as columns: H0_basis[col][row]
    return H0_basis, rho_ve, rho_et


def matrix_mul_fp(A: list, B: list, p: int) -> list:
    """Matrix product A·B over F_p."""
    d = len(A)
    C = [[0] * d for _ in range(d)]
    for i in range(d):
        for k in range(d):
            if A[i][k] == 0: continue
            for j in range(d):
                C[i][j] = (C[i][j] + A[i][k] * B[k][j]) % p
    return C


def matrix_inverse_fp(M: list, p: int) -> list:
    """Inverse of d×d matrix over F_p via Gauss-Jordan. None if singular."""
    d = len(M)
    A = [row[:] + [1 if i == j else 0 for j in range(d)] for i, row in enumerate(M)]
    for col in range(d):
        pv = -1
        for r in range(col, d):
            if A[r][col] % p != 0:
                pv = r; break
        if pv == -1:
            raise ValueError("Singular matrix")
        if pv != col:
            A[col], A[pv] = A[pv], A[col]
        inv = pow(A[col][col], p - 2, p)
        for c in range(2 * d):
            A[col][c] = (A[col][c] * inv) % p
        for r in range(d):
            if r != col and A[r][col] % p != 0:
                factor = A[r][col] % p
                for c in range(2 * d):
                    A[r][c] = (A[r][c] - factor * A[col][c]) % p
    return [row[d:] for row in A]


# ─────────────────────────── Setup & keygen ───────────────────────────

def setup_pq128(K: Complex2D, d: int, p: int, rng=None) -> ParamsPQ128:
    rng = rng or np.random.default_rng(0xCAFE)
    F = make_field(p, d)
    H0_basis, rho_ve, rho_et = gen_h0_basis(K, d, p, rng)
    e = find_secure_exponent(p, d)
    # L: random non-zero element of F_{p^d}
    while True:
        L_int = int(rng.integers(0, 2**62)) % (p ** d)
        L = F.from_int(L_int)
        if not F.is_zero(L):
            break
    return ParamsPQ128(K=K, F=F, L=L, exponent=e, d=d, p=p,
                       H0_basis=H0_basis, rho_ve=rho_ve, rho_et=rho_et)


def keygen_pq128(params: ParamsPQ128, rng=None) -> KeyPQ128:
    rng = rng or np.random.default_rng(0xBEEF)
    p, d = params.p, params.d
    F = params.F
    A = {v: random_invertible_matrix(p, d, rng) for v in range(params.K.n)}
    beta = {}
    one = F.one()
    for v in range(params.K.n):
        while True:
            b_int = int(rng.integers(0, 2**62)) % (p ** d)
            b = F.from_int(b_int)
            if not F.is_zero(b) and not F.equals(b, one):
                beta[v] = b; break
    B = {e_idx: random_invertible_matrix(p, d, rng) for e_idx in range(params.K.m)}
    C = {t_idx: random_invertible_matrix(p, d, rng) for t_idx in range(params.K.l)}
    return KeyPQ128(A=A, beta=beta, B=B, C=C)


# ─────────────────────────── Encryption ───────────────────────────

def encrypt_pq128(params: ParamsPQ128, key: KeyPQ128,
                   alpha: list, nonce: bytes = None) -> tuple:
    """alpha: F_p^d coefficient vector (k_msg = d). Returns (nonce, ciphertext)."""
    if nonce is None:
        nonce = os.urandom(16)
    p, d = params.p, params.d
    K = params.K
    F = params.F

    # Build section: s = H0_basis · α where H0_basis is list of columns
    section = [0] * (K.n * d)
    for col_idx, col in enumerate(params.H0_basis):
        for row in range(K.n * d):
            section[row] = (section[row] + alpha[col_idx] * col[row]) % p

    # Build incidence maps
    edges_at = {v: [] for v in range(K.n)}
    for e_idx, (u, v) in enumerate(K.edges):
        edges_at[u].append((e_idx, u, v))
        edges_at[v].append((e_idx, u, v))
    triangles_at = {v: [] for v in range(K.n)}
    for t_idx, t in enumerate(K.triangles):
        for v in t:
            triangles_at[v].append((t_idx, t))

    # Encrypt per vertex
    c_vec = [0] * (K.n * d)
    for v in range(K.n):
        s_v = section[v * d:(v + 1) * d]
        # arg_v = A_v · s_v + Σ_e B_e · F.mul(s_other, s_v) + Σ_t C_t · F.mul3(s_a, s_v, s_b)
        arg = matvec_mul_fp(key.A[v], s_v, p)
        for e_idx, u, w in edges_at[v]:
            other = u if w == v else w
            s_other = section[other * d:(other + 1) * d]
            prod = F.mul(tuple(s_other), tuple(s_v))
            contrib = matvec_mul_fp(key.B[e_idx], list(prod), p)
            arg = vec_add_fp(arg, contrib, p)
        for t_idx, t in triangles_at[v]:
            others = [x for x in t if x != v]
            s_a = section[others[0] * d:(others[0] + 1) * d]
            s_b = section[others[1] * d:(others[1] + 1) * d]
            triple = F.mul(F.mul(tuple(s_a), tuple(s_v)), tuple(s_b))
            contrib = matvec_mul_fp(key.C[t_idx], list(triple), p)
            arg = vec_add_fp(arg, contrib, p)
        # Add nonce
        r_v = prg_vec(nonce, "v", v, d, p)
        arg = vec_add_fp(arg, r_v, p)
        # Apply σ_v3
        z = sigma_v3(F, arg, key.beta[v], params.L, params.exponent)
        # c_v = z - r_v
        c_v = vec_sub_fp(z, r_v, p)
        for i in range(d):
            c_vec[v * d + i] = c_v[i]
    return nonce, c_vec
