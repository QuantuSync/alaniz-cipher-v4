"""
attacks/A6_cico_solving_degree.py — real solving degree of CICO for the Alaniz
AO round (public permutation). Fixed seed.

KEY MODELING POINT (see docs/AO_SPEC.md): in the AO model the permutation is
PUBLIC (β, L, A, B, C are public round parameters). Alaniz has a SINGLE round
R = S ∘ (M + rc). For CICO with a constrained output block, the attacker inverts
the (public) S-box σ_v on that block by root-finding — cheap — and is left with
the degree-3 MIXING system in the free variables. The high S-box degree e does
NOT compound to 3e because there is only one S-box layer and the constrained
outputs are known.

Consequence: the naive "attacker faces a degree-3e system" bound (source of the
suspended 74/…/147 numbers) does NOT hold in the AO model. The real CICO solving
degree is that of a CUBIC system. This script measures both and reports the gap.

The legitimate decryptor's own algorithm (σ⁻¹ per vertex + cubic F4) is EXACTLY
this CICO attack. We reuse it.

Run: python attacks/A6_cico_solving_degree.py
"""
import os
import sys
import time
from math import comb

import numpy as np

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from core.complex2d import Complex2D
from crypto.protocol_v4r3_pq128 import setup_pq128, keygen_pq128, encrypt_pq128
from crypto.decrypt_v4r3_pq128 import (field_struct_tensor, triple_struct_tensor,
                                       get_R_at, build_cubic_system_structure,
                                       specialise_to_combo,
                                       sigma_inverse_all_candidates)
from crypto.ao_permutation import mixing_layer, section_from_alpha
from crypto.f4_solver import (build_macaulay_matrix, solve_polysystem_linearization)

SEED = 20260705


def naive_3e_hilbert(m_eqs, degree, n_vars, bound=600):
    """D_reg of a semi-regular system of m_eqs polys of `degree` in n_vars —
    the naive 'attacker faces degree-3e' bound."""
    num = [0] * (bound + 1)
    for k in range(m_eqs + 1):
        dg = k * degree
        if dg > bound:
            break
        num[dg] += ((-1) ** k) * comb(m_eqs, k)
    inv = [comb(n_vars - 1 + j, j) for j in range(bound + 1)]
    coef = [0] * (bound + 1)
    for i in range(bound + 1):
        if num[i]:
            for j in range(bound + 1 - i):
                coef[i + j] += num[i] * inv[j]
    for D in range(bound + 1):
        if coef[D] <= 0:
            return D
    return -1


def flint_macaulay_rank(equations, d, p, D):
    """Rank of the Macaulay matrix at degree D via python-flint (fast)."""
    import flint
    rows, monos, _ = build_macaulay_matrix(equations, d, p, D)
    n_cols = len(monos)
    data = [0] * (len(rows) * n_cols)
    for i, r in enumerate(rows):
        base = i * n_cols
        for c, v in r.items():
            data[base + c] = int(v) % p
    M = flint.nmod_mat(len(rows), n_cols, data, p)
    return M.rank(), len(rows), n_cols


def measure(d, p):
    K = Complex2D.tetrahedron()
    rng = np.random.default_rng(SEED)
    params = setup_pq128(K, d, p, rng=rng)
    key = keygen_pq128(params, rng=rng)
    e = params.exponent
    alpha = [int(rng.integers(0, p)) for _ in range(d)]
    nonce = b"\x00" * 16
    _, ct = encrypt_pq128(params, key, alpha, nonce=nonce)

    # ---- CICO attack = decryptor's algorithm: invert public σ, build cubic system
    # The attacker inverts the PUBLIC σ_v on the constrained outputs (root-finding;
    # σ is non-injective so this yields ~2.1 candidates/vertex → a small combo
    # enumeration, exactly as the decryptor does). We report the combo count and,
    # to measure the residual mixing degree cleanly, build the exact cubic system
    # from the TRUE argument arg_v(α)=M(H0·α)_v (which the correct combo yields).
    t0 = time.time()
    T_struct = field_struct_tensor(params.F)
    T_triple = triple_struct_tensor(params.F)
    R = get_R_at(params)
    structure = build_cubic_system_structure(params, key, T_struct, T_triple, R)
    n_combos = 1
    for v in range(K.n):
        cands = sigma_inverse_all_candidates(params, key, ct, nonce, v)
        n_combos *= max(1, len(cands))
    # true argument (the preimage the correct σ⁻¹ combo recovers)
    arg_full = mixing_layer(params, key, section_from_alpha(params, alpha))
    arg_rec = {v: [arg_full[v * d + i] for i in range(d)] for v in range(K.n)}
    eqs = specialise_to_combo(structure, arg_rec, d, p, K.n)
    build_t = time.time() - t0

    # ---- real CICO solving degree = smallest D solving the CUBIC system
    emp_D = None
    solve_t0 = time.time()
    for D in range(2, 12):
        sol = solve_polysystem_linearization(eqs, d=d, p=p, D_reg=D)
        if sol is not None and list(sol) == alpha:
            emp_D = D
            break
    solve_t = time.time() - solve_t0

    # rank profile at the solving degree (flint), for the record
    rank_info = None
    if emp_D is not None:
        try:
            rk, nr, nc = flint_macaulay_rank(eqs, d, p, emp_D)
            rank_info = f"{nr}x{nc} rank={rk} ker={nc-rk}"
        except Exception as ex:
            rank_info = f"(flint rank n/a: {ex})"

    naive = naive_3e_hilbert(K.n * d, 3 * e, d)
    return {
        "d": d, "p": p, "e": e, "3e": 3 * e, "m_eqs": K.n * d,
        "naive_3e_Dreg": naive,
        "cico_solving_degree": emp_D,
        "recovered": emp_D is not None,
        "sigma_inv_combos": n_combos,
        "rank@D": rank_info,
        "build_s": round(build_t, 2), "solve_s": round(solve_t, 2),
    }


def main():
    print(f"# A6-CICO: real solving degree of one-round CICO (seed={SEED}, tetra)\n")
    print("Model: permutation PUBLIC. Attack = invert public σ on fixed outputs +")
    print("solve the residual CUBIC mixing system. High degree e does NOT compound.\n")
    print(f"{'d':>3} {'p':>5} {'e':>3} {'3e':>4} "
          f"{'naive-3e Dreg':>14} {'CICO solving deg':>17} {'rec':>4} {'time_s':>7}")
    for (d, p) in [(2, 17), (3, 11), (4, 257), (6, 257)]:
        try:
            r = measure(d, p)
            print(f"{r['d']:>3} {r['p']:>5} {r['e']:>3} {r['3e']:>4} "
                  f"{r['naive_3e_Dreg']:>14} {str(r['cico_solving_degree']):>17} "
                  f"{str(r['recovered']):>4} {r['build_s']+r['solve_s']:>7.1f}")
        except Exception as ex:
            print(f"{d:>3} {p:>5}  ERROR: {type(ex).__name__}: {ex}")
    print("\nReading: 'naive-3e Dreg' is the degree the SUSPENDED bit-claims assumed")
    print("the attacker pays. 'CICO solving deg' is what the attacker ACTUALLY pays")
    print("in the public one-round AO model. The gap = the security bound evaporates.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
