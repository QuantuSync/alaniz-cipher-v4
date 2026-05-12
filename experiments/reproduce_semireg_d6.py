"""
Experiment 20 — Why does D_reg=4 fail for v4r3 cubic system?

Hypothesis: v4r3 cubics have structural syzygies that delay the first-fall
degree from 4 (semi-regular prediction) to 5 (empirical).

Test:
  A. At small p with multiple seeds, count D=4 successes vs D=5 successes.
  B. For one seed, build the Macaulay matrix at D=4 and check its rank
     vs the expected semi-regular rank. The gap = number of syzygies.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'src'))
import time
import numpy as np
from itertools import combinations_with_replacement as cwr
from math import comb

from core.complex2d import Complex2D
from crypto.protocol_v4r3_pq128 import (setup_pq128, keygen_pq128,
                                          encrypt_pq128)
from crypto.decrypt_v4r3_pq128 import (decrypt_pq128,
                                          field_struct_tensor,
                                          triple_struct_tensor,
                                          get_R_at,
                                          build_cubic_system_structure,
                                          specialise_to_combo,
                                          sigma_inverse_all_candidates)
from crypto.f4_solver import build_macaulay_matrix, rref_sparse_fp


def count_macaulay_rank(eqs, d, p, D):
    """Compute the rank of the Macaulay matrix at degree D over F_p."""
    rows, monos, mono_idx = build_macaulay_matrix(eqs, d, p, D)
    n_cols = len(monos)
    n_rows = len(rows)
    rref_rows, pivot_for_col = rref_sparse_fp(rows, n_cols, p)
    rank = len(pivot_for_col)
    return rank, n_rows, n_cols


def expected_rank_semireg(m, d, p, D, deg=3):
    """Expected rank of Macaulay matrix at D for m semi-regular polys of
    degree deg in d variables. For semi-regular, the cokernel dimension
    equals the d-th coefficient of (1-t^deg)^m / (1-t)^d truncated at
    first non-positive value.

    Macaulay matrix: rows = m · C(d + D - deg, D - deg), cols = C(d+D, D).
    Generic rank = min(rows, cols - cokernel_dim_at_D).
    """
    n_cols = comb(d + D, D)
    n_rows = m * comb(d + D - deg, D - deg)

    # Compute Hilbert series numerator (1 - t^deg)^m and denominator (1-t)^d
    # Find coefficient of t^D in expansion
    # (1-t^deg)^m: Σ_k C(m, k) (-1)^k t^(deg·k)
    # (1-t)^(-d) = Σ_j C(d-1+j, j) t^j
    # Product coefficient of t^D: Σ_{k: deg·k <= D} C(m, k)(-1)^k · C(d-1 + D - deg·k, D - deg·k)
    coef_D = 0
    k = 0
    while deg * k <= D:
        term = ((-1)**k) * comb(m, k) * comb(d - 1 + D - deg*k, D - deg*k)
        coef_D += term
        k += 1
    # Truncate negative
    cokernel_truncated = max(coef_D, 0)
    expected_rank = n_cols - cokernel_truncated
    return expected_rank, n_rows, n_cols, coef_D


def run_diagnosis(p, d, n_seeds=5):
    K = Complex2D.tetrahedron()
    print(f"\n══ Diagnosis at d={d}, p={p}, tetrahedron (n={K.n}, m={K.n*d} cubics) ══")
    m = K.n * d   # 24 for tetra

    # Theoretical analysis
    for D in [3, 4, 5]:
        exp_rank, n_rows, n_cols, hilb_coef = expected_rank_semireg(m, d, p, D)
        print(f"  D={D}: matrix {n_rows}×{n_cols}, "
              f"Hilbert coef = {hilb_coef}, expected rank (semi-reg) = {exp_rank}")

    print(f"\n  Empirical test: build v4r3 system + measure rank")
    from itertools import product
    results = []
    for seed in range(n_seeds):
        rng = np.random.default_rng(seed)
        params = setup_pq128(K, d, p, rng=rng)
        key = keygen_pq128(params, rng=rng)
        alpha_orig = [int(rng.integers(0, 2**62)) % p for _ in range(d)]
        nonce, ct = encrypt_pq128(params, key, alpha_orig)

        # Get one valid combo
        F = params.F
        cands_per_v = []
        for v in range(K.n):
            cands = sigma_inverse_all_candidates(params, key, ct, nonce, v)
            cands_per_v.append(cands)

        T_struct = field_struct_tensor(F)
        T_triple = triple_struct_tensor(F)
        R = get_R_at(params)
        structure = build_cubic_system_structure(params, key, T_struct, T_triple, R)

        # Find a combo that includes the actual α
        good_combo = None
        for combo in product(*cands_per_v):
            arg_recovered = {v: combo[v] for v in range(K.n)}
            eqs_test = specialise_to_combo(structure, arg_recovered, d, p, K.n)
            all_zero = True
            for eq in eqs_test:
                v = 0
                for mono, coef in eq.items():
                    val = 1
                    for ii, ee in enumerate(mono):
                        for _ in range(ee):
                            val = (val * alpha_orig[ii]) % p
                    v = (v + coef * val) % p
                if v != 0:
                    all_zero = False; break
            if all_zero:
                good_combo = combo
                break

        if good_combo is None:
            print(f"  seed={seed}: no consistent combo found, skipping")
            continue

        arg_recovered = {v: good_combo[v] for v in range(K.n)}
        eqs = specialise_to_combo(structure, arg_recovered, d, p, K.n)

        # Now measure rank at D=3, 4, 5
        ranks = {}
        for D in [3, 4, 5]:
            t0 = time.time()
            rank, n_rows, n_cols = count_macaulay_rank(eqs, d, p, D)
            ranks[D] = (rank, n_rows, n_cols, time.time()-t0)

        print(f"  seed={seed}: ranks per D:")
        for D in [3, 4, 5]:
            r, nr, nc, t = ranks[D]
            free_cols = nc - r
            exp_rank, _, _, hilb = expected_rank_semireg(m, d, p, D)
            extra = exp_rank - r  # positive = v4r3 has FEWER pivots than semi-regular
            extra_syz = max(0, -hilb if hilb > 0 else 0)
            extra_unique = max(0, extra)
            print(f"    D={D}: rank={r}/{nc} (free_cols={free_cols}), "
                  f"semi-reg expected rank={exp_rank}, "
                  f"deficiency vs semi-reg = {extra} ({t:.1f}s)")
        results.append({"seed": seed, "ranks": ranks})

    return results


def main():
    print("=" * 72)
    print(" Experiment 20: Diagnosing D_reg for v4r3 cubic system")
    print("=" * 72)

    print("\nKey question: kernel of Macaulay matrix at D=4 must be 1-dim")
    print("for unique solution extraction. If kernel is ≥ 2-dim, F4 fails.")
    print("Free columns after RREF = kernel dimension = (cols - rank).")

    # Run at small p where it's fast
    run_diagnosis(p=257, d=6, n_seeds=3)


if __name__ == "__main__":
    main()
