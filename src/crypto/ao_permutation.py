"""
crypto/ao_permutation.py — Alaniz as an arithmetization-oriented (AO) round
function on the full state F_p^{n·d}. See docs/AO_SPEC.md.

In the AO model the round parameters (A, B, C, β, L, round constants) are PUBLIC;
security is the hardness of CICO on the public map. This module gives the forward
map so attacks can build the CICO system directly (no oracle/secret needed).

Round  R = S ∘ (M + rc):
  - M (mixing, degree 3): arg_v(x) = A_v·x_v + Σ B_e·(x_u·x_v) + Σ C_t·(x_a·x_v·x_b)
  - rc: per-vertex round constants rc_v = PRG(nonce, "v", v)
  - S (S-box, degree e): σ_v(τ) = β_v·τ + (β_v−1)·(L·τ+1)^e   [as-implemented]
        or the pure-power permutation variant π_e(τ) = (L·τ+1)^e  [bijective]
"""
from __future__ import annotations

from crypto.linalg_fp import matvec_mul_fp, vec_add_fp
from crypto.sampling import prg_vec


def _incidence(K):
    edges_at = {v: [] for v in range(K.n)}
    for e_idx, (a, b) in enumerate(K.edges):
        edges_at[a].append((e_idx, a, b))
        edges_at[b].append((e_idx, a, b))
    triangles_at = {v: [] for v in range(K.n)}
    for t_idx, t in enumerate(K.triangles):
        for u in t:
            triangles_at[u].append((t_idx, t))
    return edges_at, triangles_at


def mixing_layer(params, key, x):
    """M: degree-3 sheaf coupling on the full state x ∈ F_p^{n·d}.
    Returns list of arg_v vectors (F_p^d each), concatenated as F_p^{n·d}."""
    p, d, K, F = params.p, params.d, params.K, params.F
    edges_at, triangles_at = _incidence(K)
    out = [0] * (K.n * d)
    for v in range(K.n):
        x_v = x[v * d:(v + 1) * d]
        arg = matvec_mul_fp(key.A[v], x_v, p)
        for e_idx, u, w in edges_at[v]:
            other = u if w == v else w
            x_other = x[other * d:(other + 1) * d]
            prod = F.mul(tuple(x_other), tuple(x_v))
            arg = vec_add_fp(arg, matvec_mul_fp(key.B[e_idx], list(prod), p), p)
        for t_idx, t in triangles_at[v]:
            others = [z for z in t if z != v]
            x_a = x[others[0] * d:(others[0] + 1) * d]
            x_b = x[others[1] * d:(others[1] + 1) * d]
            triple = F.mul(F.mul(tuple(x_a), tuple(x_v)), tuple(x_b))
            arg = vec_add_fp(arg, matvec_mul_fp(key.C[t_idx], list(triple), p), p)
        out[v * d:(v + 1) * d] = arg
    return out


def round_constants(params, nonce):
    """rc ∈ F_p^{n·d}: per-vertex PRG masks (AO round constants)."""
    p, d, K = params.p, params.d, params.K
    rc = [0] * (K.n * d)
    for v in range(K.n):
        rc[v * d:(v + 1) * d] = prg_vec(nonce, "v", v, d, p)
    return rc


def _sigma_impl(F, tau, beta, L, e):
    """σ_v(τ) = β·τ + (β−1)·(L·τ+1)^e  (as-implemented; NOT a permutation)."""
    one = F.one()
    powered = F.pow(F.add(F.mul(L, tau), one), e)
    return F.add(F.mul(beta, tau), F.mul(F.sub(beta, one), powered))


def _sigma_power(F, tau, L, e):
    """π_e(τ) = (L·τ+1)^e  (bijective AO S-box variant)."""
    one = F.one()
    return F.pow(F.add(F.mul(L, tau), one), e)


def sbox_layer(params, key, y, variant="impl"):
    """S: apply σ_v per vertex to state y ∈ F_p^{n·d}."""
    d, K, F = params.d, params.K, params.F
    L, e = params.L, params.exponent
    out = [0] * (K.n * d)
    for v in range(K.n):
        tau = tuple(y[v * d:(v + 1) * d])
        if variant == "impl":
            z = _sigma_impl(F, tau, key.beta[v], L, e)
        elif variant == "power":
            z = _sigma_power(F, tau, L, e)
        else:
            raise ValueError(f"unknown S-box variant {variant!r}")
        out[v * d:(v + 1) * d] = list(z)
    return out


def ao_forward(params, key, x, nonce, variant="impl"):
    """One AO round R(x) = S(M(x) + rc) on the full state x ∈ F_p^{n·d}."""
    p = params.p
    arg = mixing_layer(params, key, x)
    rc = round_constants(params, nonce)
    y = vec_add_fp(arg, rc, p)
    return sbox_layer(params, key, y, variant=variant)


def section_from_alpha(params, alpha):
    """s = H₀·α ∈ F_p^{n·d} (input restricted to global sections)."""
    p, d, K = params.p, params.d, params.K
    s = [0] * (K.n * d)
    for col_idx, col in enumerate(params.H0_basis):
        a = alpha[col_idx]
        if a == 0:
            continue
        for row in range(K.n * d):
            s[row] = (s[row] + a * col[row]) % p
    return s
