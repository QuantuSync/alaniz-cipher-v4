"""
attacks/A5_key_recovery.py — algebraic key-recovery probes (Phase-0 spike).

Two probes, both on the H3-corrected reference scheme, small scale, fixed seed.

A5a — β is LINEAR given (A, B, C) + one known-plaintext ciphertext.
    Model: known-plaintext attacker who additionally knows the coupling key
    (A, B, C). Per vertex v with plaintext α and public nonce:
        w_v := c_v + r_v = σ_v(τ_v),  τ_v = ι(arg_v(α) + r_v)
        σ_v(τ) = β_v·τ + (β_v − 1)·(L·τ + 1)^e
    Everything except β_v is known, and σ_v is AFFINE in β_v:
        w = β_v·(τ + P) − P,   P := (L·τ + 1)^e
        ⇒ β_v = (w + P) · (τ + P)^{-1}   (one field inversion).
    Result: β_v recovered exactly, O(1) per vertex.
    ⇒ The trapdoor secrecy CANNOT rest on β; it rests entirely on (A, B, C).

A5b — full key-recovery system size (β AND A,B,C unknown).
    Reports the unknown/equation counts and system degree, which is the actual
    NL-SMIP-KR hardness surface handed to Fase 1 (MinRank / structural on A,B,C).

Run: python attacks/A5_key_recovery.py
"""
import os
import sys

import numpy as np

try:
    sys.stdout.reconfigure(encoding="utf-8")  # Windows console is cp1252 by default
except Exception:
    pass

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from core.complex2d import Complex2D
from crypto.protocol_v4r3_pq128 import (setup_pq128, keygen_pq128, encrypt_pq128,
                                        prg_vec)
from crypto.linalg_fp import matvec_mul_fp, vec_add_fp

SEED = 20260705


def arg_at_vertex(params, key, section, v):
    """Recompute arg_v(α) in F_p^d from the (known) coupling key A,B,C.

    Mirrors encrypt_pq128's per-vertex argument, BEFORE the nonce mask and σ.
    """
    p, d = params.p, params.d
    K, F = params.K, params.F
    edges_at = {u: [] for u in range(K.n)}
    for e_idx, (a, b) in enumerate(K.edges):
        edges_at[a].append((e_idx, a, b))
        edges_at[b].append((e_idx, a, b))
    triangles_at = {u: [] for u in range(K.n)}
    for t_idx, t in enumerate(K.triangles):
        for u in t:
            triangles_at[u].append((t_idx, t))

    s_v = section[v * d:(v + 1) * d]
    arg = matvec_mul_fp(key.A[v], s_v, p)
    for e_idx, u, w in edges_at[v]:
        other = u if w == v else w
        s_other = section[other * d:(other + 1) * d]
        prod = F.mul(tuple(s_other), tuple(s_v))
        arg = vec_add_fp(arg, matvec_mul_fp(key.B[e_idx], list(prod), p), p)
    for t_idx, t in triangles_at[v]:
        others = [x for x in t if x != v]
        s_a = section[others[0] * d:(others[0] + 1) * d]
        s_b = section[others[1] * d:(others[1] + 1) * d]
        triple = F.mul(F.mul(tuple(s_a), tuple(s_v)), tuple(s_b))
        arg = vec_add_fp(arg, matvec_mul_fp(key.C[t_idx], list(triple), p), p)
    return arg


def build_section(params, alpha):
    p, d, K = params.p, params.d, params.K
    section = [0] * (K.n * d)
    for col_idx, col in enumerate(params.H0_basis):
        for row in range(K.n * d):
            section[row] = (section[row] + alpha[col_idx] * col[row]) % p
    return section


def a5a_recover_beta(params, key, alpha, nonce):
    """Recover every β_v via the affine-in-β field division. Returns success."""
    p, d, K, F = params.p, params.d, params.K, params.F
    e, L = params.exponent, params.L
    one = F.one()
    section = build_section(params, alpha)
    _, ct = encrypt_pq128(params, key, alpha, nonce=nonce)

    ok = True
    recovered = {}
    for v in range(K.n):
        r_v = prg_vec(nonce, "v", v, d, p)
        c_v = ct[v * d:(v + 1) * d]
        w = tuple((c_v[i] + r_v[i]) % p for i in range(d))              # σ_v(τ)
        arg = arg_at_vertex(params, key, section, v)
        tau = tuple((arg[i] + r_v[i]) % p for i in range(d))           # ι(arg+r)
        P = F.pow(F.add(F.mul(L, tau), one), e)                        # (Lτ+1)^e
        num = F.add(w, P)                                              # w + P
        den = F.add(tau, P)                                           # τ + P
        beta_rec = F.mul(num, F.inv(den))
        recovered[v] = beta_rec
        if beta_rec != key.beta[v]:
            ok = False
    return ok, recovered


def a5b_system_size(params):
    """Report the size/degree of the FULL key-recovery system."""
    d, K, e = params.d, params.K, params.exponent
    n, m, l = K.n, K.m, K.l
    unknowns_A = n * d * d
    unknowns_B = m * d * d
    unknowns_C = l * d * d
    unknowns_beta = n * d          # β_v as F_p^d coords
    unknowns_alpha = d             # message per ciphertext (unknown in ct-only)
    total_key = unknowns_A + unknowns_B + unknowns_C + unknowns_beta
    eqs_per_ct = n * d
    return {
        "unknowns_A": unknowns_A, "unknowns_B": unknowns_B,
        "unknowns_C": unknowns_C, "unknowns_beta": unknowns_beta,
        "unknowns_alpha_per_ct": unknowns_alpha,
        "total_key_unknowns": total_key,
        "eqs_per_ciphertext": eqs_per_ct,
        "system_degree_in_key": e + 1,  # β·(Lτ+1)^e, τ affine in A,B,C
    }


def main():
    K = Complex2D.tetrahedron()
    print(f"# A5 key-recovery probes (seed={SEED}, tetra)\n")
    print("A5a — recover β given (A,B,C) known + known plaintext:")
    print(f"{'d':>3} {'p':>5} {'e':>3} {'beta_recovered_exactly':>24} {'cost':>18}")
    for (d, p) in [(2, 5), (3, 11), (4, 5)]:
        rng = np.random.default_rng(SEED)
        params = setup_pq128(K, d, p, rng=rng)
        key = keygen_pq128(params, rng=rng)
        alpha = [int(rng.integers(0, p)) for _ in range(d)]
        nonce = b"\x00" * 16  # fixed, public
        ok, _ = a5a_recover_beta(params, key, alpha, nonce)
        print(f"{d:>3} {p:>5} {params.exponent:>3} {str(ok):>24} {'1 field inv/vertex':>18}")

    print("\nA5b — full key-recovery system (β AND A,B,C unknown), tetra:")
    for (d, p) in [(2, 5), (3, 11), (4, 5)]:
        rng = np.random.default_rng(SEED)
        params = setup_pq128(K, d, p, rng=rng)
        info = a5b_system_size(params)
        print(f"  d={d} p={p} e={params.exponent}: "
              f"{info['total_key_unknowns']} key unknowns "
              f"(A={info['unknowns_A']}, B={info['unknowns_B']}, "
              f"C={info['unknowns_C']}, β={info['unknowns_beta']}), "
              f"{info['eqs_per_ciphertext']} eqs/ct, degree {info['system_degree_in_key']}")

    print("\nInterpretation:")
    print("  - β is NOT an independent hardness source: it is linearly (field-")
    print("    division) determined once (A,B,C) and one known plaintext are given.")
    print("  - NL-SMIP-KR hardness therefore reduces to recovering (A,B,C).")
    print("    That is the structural/MinRank target for Fase 1 (A4).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
