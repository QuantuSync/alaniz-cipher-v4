"""
Experiment 26 — Direct F4 attack on the v4r3 PUBLIC system.

Simulates an attacker with NO secret key, NO σ⁻¹. Given only:
  - The public key (H0_basis, σ, A_v, B_e, C_t are NOT given — those are secret;
    the attacker sees only the PUBLIC parameters K, d, p, exponent e, L, and
    can OBSERVE encrypt outputs)
  - A target ciphertext c*

The attack: fit the public polynomial system σ_v(arg_v(α)) - c*_v = 0 in α,
then solve via Macaulay-matrix linearization.

Steps:
  1. Generate (params, key) at small (d, e, p).
  2. Pick a random message α*, encrypt to get c*.
  3. Fit the polynomial system by INTERPOLATION (since we have oracle access
     via encrypt — the attacker can encrypt arbitrary α and observe).
     NOTE: this is a STRONGER attacker model than just having one ciphertext.
     If F4 succeeds with oracle access, then real attacker (no oracle) is
     no harder than this. If F4 fails even WITH oracle, the scheme is secure
     against direct F4.
  4. Run Macaulay-matrix RREF at increasing D until kernel_dim = 1.
  5. Extract solution and compare to α*.

Measures: empirical D_reg, time, success rate.
"""
import sys, os, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'src'))
from math import comb
import numpy as np
from itertools import product

from core.complex2d import Complex2D
from crypto.protocol_v4r3 import ProtocolV4r3, PublicParamsV4r3
from crypto.f4_solver import (build_macaulay_matrix, rref_sparse_fp,
                                extract_solution, all_monomials)


def fit_public_poly(proto, key, ct_target, nonce, max_deg, verbose=False):
    """Interpolate F_v,k(α) = encrypt(α, key, nonce)[v,k] - ct_target[v,k]
    as a polynomial in α of total degree ≤ max_deg.

    Uses encrypt as ORACLE. Returns list of polys, one per output coordinate.
    """
    p = proto.p
    d_field = proto.d
    K = proto.K
    n_var = proto.k_msg
    monos, mono_idx = all_monomials(n_var, max_deg)
    n_mono = len(monos)

    # Generate samples: enough to over-determine the fit
    rng = np.random.default_rng(0xDEAD)
    target_n = n_mono + 10
    samples = []
    seen = set()
    max_unique = p ** n_var
    if target_n > max_unique:
        samples = list(product(range(p), repeat=n_var))
        target_n = len(samples)
    else:
        while len(samples) < target_n:
            v = tuple(int(rng.integers(0, p)) for _ in range(n_var))
            if v not in seen:
                seen.add(v); samples.append(v)
    n_samples = len(samples)

    if verbose:
        print(f"    fit: {n_samples} samples, {n_mono} monomials", flush=True)

    n_outputs = K.n * d_field
    Y = np.zeros((n_samples, n_outputs), dtype=np.int64)
    F = np.zeros((n_samples, n_mono), dtype=np.int64)

    for i, alpha in enumerate(samples):
        s = proto.H0_basis @ proto.GF_p(np.array(alpha, dtype=np.int64))
        _, c_alpha = proto.encrypt(s, key, nonce=nonce)
        c_alpha_arr = np.array(c_alpha, dtype=np.int64) % p
        ct_arr = np.array(ct_target, dtype=np.int64) % p
        Y[i] = (c_alpha_arr - ct_arr) % p
        for j, mon in enumerate(monos):
            val = 1
            for ii, ee in enumerate(mon):
                for _ in range(ee):
                    val = (val * alpha[ii]) % p
            F[i, j] = val

    # Solve F · w = Y over F_p via row reduction
    polys = []
    for k_out in range(n_outputs):
        b = Y[:, k_out].copy() % p
        aug = np.hstack([F.copy() % p, b.reshape(-1, 1)]) % p
        n_rows = aug.shape[0]
        n_cols = n_mono
        pivots = []
        row = 0
        for col in range(n_cols):
            pv = -1
            for r in range(row, n_rows):
                if aug[r, col] % p != 0:
                    pv = r; break
            if pv == -1: continue
            if pv != row:
                aug[[row, pv]] = aug[[pv, row]]
            inv = pow(int(aug[row, col]), p - 2, p)
            aug[row] = (aug[row] * inv) % p
            for r in range(n_rows):
                if r != row and aug[r, col] % p != 0:
                    aug[r] = (aug[r] - aug[r, col] * aug[row]) % p
            pivots.append((row, col))
            row += 1
        rank = row
        for r in range(rank, n_rows):
            if np.any(aug[r, :n_cols] % p != 0): continue
            if aug[r, n_cols] % p != 0:
                if verbose:
                    print(f"    fit failed: output {k_out} inconsistent at degree {max_deg}", flush=True)
                return None
        if rank < n_cols:
            if verbose:
                print(f"    fit underdetermined: rank {rank} < {n_cols}", flush=True)
            return None
        coefs = np.zeros(n_mono, dtype=np.int64)
        for r, c in pivots:
            coefs[c] = aug[r, n_cols] % p
        poly = {mon: int(coefs[j]) for j, mon in enumerate(monos) if int(coefs[j]) != 0}
        polys.append(poly)
    return polys


def eval_poly(poly, alpha, p):
    result = 0
    for mon, c in poly.items():
        val = 1
        for i, e in enumerate(mon):
            for _ in range(e):
                val = (val * alpha[i]) % p
        result = (result + c * val) % p
    return result


def attack_one_instance(d, p_min, e_target, seed, verbose=False, force_exponent=None,
                          complex_kind="tetra"):
    """Generate one v4r3 instance and try direct F4 attack on public system.

    complex_kind: "tetra", "double_tet", or "octa".
    """
    if complex_kind == "tetra":
        K = Complex2D.tetrahedron()
    elif complex_kind == "double_tet":
        K = Complex2D.double_tetrahedron()
    elif complex_kind == "octa":
        K = Complex2D.octahedron()
    else:
        raise ValueError(complex_kind)
    deg = 3 * e_target
    primes = [11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113]
    p = next(pr for pr in primes if pr >= max(p_min, deg + 1))

    rng = np.random.default_rng(seed)
    print(f"\n══ {complex_kind} d={d}, e_target={e_target}, p={p}, seed={seed} ══", flush=True)
    print(f"   {complex_kind}: m={K.n*d} cubics in d={d} vars, deg(public poly)=3e", flush=True)

    params = PublicParamsV4r3.generate(K, d, p, rng=rng, exponent=force_exponent)
    proto = ProtocolV4r3(params)
    e_actual = proto.sigma.exponent
    print(f"   e_actual = {e_actual}, public poly degree = {3*e_actual}", flush=True)
    deg_actual = 3 * e_actual
    m = K.n * d

    # Hilbert prediction
    Dreg_hilbert = None
    for D in range(200):
        coef = 0
        kk = 0
        while deg_actual * kk <= D:
            if kk > m: break
            sign = -1 if kk & 1 else 1
            coef += sign * comb(m, kk) * comb(d - 1 + D - deg_actual*kk, d - 1)
            kk += 1
        if coef <= 0:
            Dreg_hilbert = D; break
    print(f"   Hilbert D_reg prediction: {Dreg_hilbert}", flush=True)

    # Encrypt random α
    key = proto.keygen(rng=rng)
    coeffs = rng.integers(0, p, size=proto.k_msg).astype(np.int64)
    s = proto.H0_basis @ proto.GF_p(coeffs)
    nonce, ct = proto.encrypt(s, key)
    alpha_orig = [int(x) for x in coeffs]
    print(f"   α target: {alpha_orig}", flush=True)

    # Fit the public polynomial system
    print(f"   Fitting public poly system (degree ≤ {deg_actual})...", flush=True)
    t0 = time.time()
    polys = fit_public_poly(proto, key, ct, nonce, deg_actual, verbose=verbose)
    fit_time = time.time() - t0
    if polys is None:
        print(f"   FIT FAILED", flush=True)
        return {"success": False, "reason": "fit_failed", "fit_time": fit_time}
    print(f"   Fit OK in {fit_time:.1f}s", flush=True)

    # Sanity check: polys must vanish at α_orig
    n_vanish = sum(1 for poly in polys if eval_poly(poly, alpha_orig, p) == 0)
    print(f"   Polys vanishing at α_orig: {n_vanish}/{len(polys)}", flush=True)
    if n_vanish != len(polys):
        print(f"   ERROR: fit incorrect", flush=True)
        return {"success": False, "reason": "fit_incorrect"}

    # Macaulay scan
    print(f"   Macaulay rank scan from D=deg upward:", flush=True)
    print(f"   {'D':>3s} {'rows':>7s} {'cols':>7s} {'rank':>7s} {'kernel':>7s} {'time':>7s}", flush=True)
    empirical_Dreg = None
    rref_total = 0.0
    ranks_by_D = {}
    for D in range(deg_actual, deg_actual + 30):
        t0 = time.time()
        rows, monos, mono_idx = build_macaulay_matrix(polys, d, p, D)
        n_rows = len(rows); n_cols = len(monos)
        if n_rows > 40000 or n_cols > 30000:
            print(f"   {D:>3d} {n_rows:>7d} {n_cols:>7d} (skipped, too large)", flush=True)
            break
        rref_rows, pivot_for_col = rref_sparse_fp(rows, n_cols, p)
        rank = len(pivot_for_col)
        kernel = n_cols - rank
        elapsed = time.time() - t0
        rref_total += elapsed
        flag = " ← unique" if kernel == 1 else ""
        print(f"   {D:>3d} {n_rows:>7d} {n_cols:>7d} {rank:>7d} {kernel:>7d} {elapsed:>6.1f}s{flag}", flush=True)
        ranks_by_D[D] = {"rows": n_rows, "cols": n_cols, "rank": rank, "kernel": kernel}
        if kernel == 1:
            sol = extract_solution(rref_rows, pivot_for_col, d, mono_idx, monos, p)
            match = list(sol) == alpha_orig
            print(f"      Solver: {sol}, match={match}", flush=True)
            empirical_Dreg = D
            break
        if kernel == 0:
            empirical_Dreg = -1
            print(f"      Over-constrained, no solution", flush=True)
            break

    return {
        "success": empirical_Dreg is not None and empirical_Dreg > 0,
        "empirical_Dreg": empirical_Dreg,
        "hilbert_Dreg": Dreg_hilbert,
        "gap": (empirical_Dreg - Dreg_hilbert) if empirical_Dreg and Dreg_hilbert else None,
        "fit_time": fit_time,
        "rref_total": rref_total,
        "ranks_by_D": ranks_by_D,
        "p": p, "d": d, "e": e_actual,
    }


def next_prime(n):
    n += 1
    while True:
        is_p = True
        if n < 2: is_p = False
        for d in range(2, int(n**0.5)+1):
            if n % d == 0: is_p = False; break
        if is_p: return n
        n += 1


def main():
    print("=" * 78)
    print(" Experiment 26: direct F4 attack on v4r3 PUBLIC system at small scale")
    print(" Goal: validate Hilbert D_reg model empirically before extrapolation")
    print("=" * 78)

    cases = [
        # (d, p_min, e_target, seed)
        (3, 11, 3, 0),
        (3, 11, 3, 1),
        (3, 11, 3, 2),
        (4, 11, 3, 0),
        (4, 11, 3, 1),
    ]

    results = []
    for d, p_min, e_t, seed in cases:
        r = attack_one_instance(d, p_min, e_t, seed)
        results.append(r)

    print("\n" + "=" * 78)
    print(" Summary")
    print("-" * 78)
    print(f"  {'d':>3s} {'e':>3s} {'p':>4s} {'Hilbert':>8s} {'empirical':>10s} {'gap':>5s} "
          f"{'fit':>7s} {'F4':>7s}")
    for r in results:
        if not r.get("success"):
            print(f"  FAILED: {r.get('reason', 'unknown')}", flush=True)
            continue
        gap = r["gap"]
        gap_str = str(gap) if gap is not None else "—"
        print(f"  {r['d']:>3d} {r['e']:>3d} {r['p']:>4d} {r['hilbert_Dreg']:>8d} "
              f"{r['empirical_Dreg']:>10d} {gap_str:>5s} "
              f"{r['fit_time']:>6.1f}s {r['rref_total']:>6.1f}s")
    print("=" * 78)


if __name__ == "__main__":
    main()
