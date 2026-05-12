"""
Experiment 23 — Empirical D_reg validation at d=2, 3 with p > 3e.

Conditions: p > 3e so Fermat doesn't reduce polynomial degree.
            p^d > C(d + 3e, 3e) so we have enough unique samples.

If the v4r3 PUBLIC polynomial system is actually semi-regular, the empirical
D_reg measured here should match the Hilbert prediction. This validates
extrapolation to PQ-128 parameters.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'src'))
import time
import numpy as np
from math import comb
from itertools import product

from core.complex2d import Complex2D
from crypto.protocol_v4r3 import ProtocolV4r3, PublicParamsV4r3
from crypto.f4_solver import (build_macaulay_matrix, rref_sparse_fp,
                                extract_solution, all_monomials)


def hilbert_first_neg(m: int, d: int, deg: int, max_D: int = 500):
    for D in range(max_D + 1):
        coef = 0
        k = 0
        while deg * k <= D:
            if k > m: break
            sign = -1 if (k & 1) else 1
            coef += sign * comb(m, k) * comb(d - 1 + D - deg*k, d - 1)
            k += 1
        if coef <= 0:
            return D
    return None


def fit_public_poly(proto, key, ciphertext, nonce, max_deg, max_samples=None):
    """Interpolate (encrypt(α) - ciphertext)[k] as polynomial in α."""
    p = proto.p
    d_field = proto.d
    K = proto.K
    n_var = proto.k_msg
    monos, mono_idx = all_monomials(n_var, max_deg)
    n_mono = len(monos)
    target_n = n_mono + 5
    if max_samples is not None:
        target_n = min(target_n, max_samples)

    # Choose samples
    rng = np.random.default_rng(0xDEAD)
    samples = []
    seen = set()
    if target_n > p**n_var:
        samples = list(product(range(p), repeat=n_var))
        target_n = len(samples)
    else:
        while len(samples) < target_n:
            v = tuple(int(rng.integers(0, p)) for _ in range(n_var))
            if v not in seen:
                seen.add(v); samples.append(v)
    n_samples = len(samples)

    n_outputs = K.n * d_field
    Y = np.zeros((n_samples, n_outputs), dtype=np.int64)
    F = np.zeros((n_samples, n_mono), dtype=np.int64)
    for i, alpha in enumerate(samples):
        s = proto.H0_basis @ proto.GF_p(np.array(alpha, dtype=np.int64))
        _, c_alpha = proto.encrypt(s, key, nonce=nonce)
        c_alpha_arr = np.array(c_alpha, dtype=np.int64) % p
        ct_arr = np.array(ciphertext, dtype=np.int64) % p
        Y[i] = (c_alpha_arr - ct_arr) % p
        for j, m in enumerate(monos):
            val = 1
            for ii, ee in enumerate(m):
                for _ in range(ee):
                    val = (val * alpha[ii]) % p
            F[i, j] = val

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
                return None, None, "fit underdetermined"
        if rank < n_cols:
            # Fit underdetermined; need more samples or higher D
            return None, None, f"fit rank {rank} < n_cols {n_cols}"
        coefs = np.zeros(n_mono, dtype=np.int64)
        for r, c in pivots:
            coefs[c] = aug[r, n_cols] % p
        poly = {m: int(coefs[j]) % p for j, m in enumerate(monos) if int(coefs[j]) % p != 0}
        polys.append(poly)
    return polys, monos, "OK"


def measure_dreg(K, d, p, label):
    rng = np.random.default_rng(42)
    params = PublicParamsV4r3.generate(K, d, p, rng=rng)
    proto = ProtocolV4r3(params)
    e = proto.sigma.exponent
    deg = 3 * e
    m = K.n * d
    n_mono = comb(d + deg, deg)
    print(f"\n══ {label}, d={d}, p={p}, e={e}, deg=3e={deg} ══")
    print(f"   n_mono = C(d+3e, 3e) = {n_mono}")
    print(f"   p^d = {p**d}, suffices = {p**d >= n_mono + 5}")
    if p <= deg:
        print(f"   ⚠ p ≤ 3e: Fermat reduction will lower effective degree")
    if p**d < n_mono + 5:
        print(f"   ⚠ p^d < n_mono: insufficient unique samples")

    # Hilbert prediction
    D_reg_pred = hilbert_first_neg(m, d, deg)
    print(f"   Hilbert (semi-reg) D_reg prediction: {D_reg_pred}")

    # Fit public system
    key = proto.keygen(rng=rng)
    coeffs = rng.integers(0, p, size=proto.k_msg).astype(np.int64)
    s = proto.H0_basis @ proto.GF_p(coeffs)
    nonce, ct = proto.encrypt(s, key)
    alpha_orig = list(int(x) for x in coeffs)

    print(f"   α target: {alpha_orig}")
    print(f"   Fitting...", flush=True)
    t0 = time.time()
    polys, monos, status = fit_public_poly(proto, key, ct, nonce, deg)
    fit_time = time.time() - t0
    print(f"   Fit status: {status} in {fit_time:.1f}s")
    if polys is None:
        return None, D_reg_pred

    # Verify
    n_zero = sum(1 for poly in polys
                  if sum(c * (eval_mono(m, alpha_orig, p)) for m, c in poly.items()) % p == 0)
    print(f"   {n_zero}/{len(polys)} polynomials vanish at α_orig")

    # Find empirical D_reg by Macaulay rank scan
    print(f"   Macaulay rank scan:", flush=True)
    print(f"   {'D':>3s} {'rows':>7s} {'cols':>7s} {'rank':>7s} {'kernel':>7s} {'time':>7s}")
    empirical_D_reg = None
    for D in range(deg, deg + 10):
        t0 = time.time()
        rows, mns, _ = build_macaulay_matrix(polys, d, p, D)
        n_rows = len(rows)
        n_cols = len(mns)
        rref_rows, pivot_for_col = rref_sparse_fp(rows, n_cols, p)
        rank = len(pivot_for_col)
        kernel = n_cols - rank
        elapsed = time.time() - t0
        flag = " ← unique soln" if kernel == 1 else ""
        print(f"   {D:>3d} {n_rows:>7d} {n_cols:>7d} {rank:>7d} {kernel:>7d} {elapsed:>6.1f}s{flag}")
        if kernel == 1 and empirical_D_reg is None:
            sol = extract_solution(rref_rows, pivot_for_col, d, _, mns, p)
            match = list(sol) == alpha_orig
            print(f"      Solver returned: {sol}, match={match}")
            empirical_D_reg = D
            break
        if kernel == 0:
            empirical_D_reg = -1  # over-constrained
            break
    return empirical_D_reg, D_reg_pred


def eval_mono(m, alpha, p):
    val = 1
    for i, e in enumerate(m):
        for _ in range(e):
            val = (val * alpha[i]) % p
    return val


def main():
    print("=" * 76)
    print(" Experiment 23: empirical D_reg validation for v4r3 public system")
    print("=" * 76)

    K = Complex2D.tetrahedron()

    # d=2, p=17 (e will be 5 by find_secure_exponent for p^d-1 = 288)
    e1, p1 = measure_dreg(K, 2, 17, "tetra-d2-p17")

    # d=2, p=23 (e selection might differ; deg should still fit)
    e2, p2 = measure_dreg(K, 2, 23, "tetra-d2-p23")

    # d=3, p=11 — but check fit feasibility first
    # For d=3 with default e: p^d-1 = 11^3-1 = 1330 = 2·5·7·19. e=3 has gcd(3, 1330)=1. So e=3.
    # n_mono = C(3+9, 9) = 220. p^3 = 1331. OK.
    e3, p3 = measure_dreg(K, 3, 11, "tetra-d3-p11")

    print("\n" + "=" * 76)
    print(" Validation summary:")
    print("-" * 76)
    print(f"  {'case':<25s} {'pred D_reg':>12s} {'empirical':>10s} {'match?':>10s}")
    for label, ep, pp in [("tetra-d2-p17", e1, p1),
                          ("tetra-d2-p23", e2, p2),
                          ("tetra-d3-p11", e3, p3)]:
        match = "✓" if (ep is not None and ep == pp) else ("close" if ep and abs(ep - pp) <= 2 else "?")
        print(f"  {label:<25s} {pp:>12} {str(ep):>10s} {match:>10s}")
    print("=" * 76)


if __name__ == "__main__":
    main()
