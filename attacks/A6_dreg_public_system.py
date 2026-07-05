"""
attacks/A6_dreg_public_system.py — empirical D_reg of the message-recovery
system, measured on the H3-corrected reference scheme. Fixed seed, fixed nonce.

Scope note (honesty, see docs/HARDNESS.md §H2):
  The degree-3e system in α is available to a CHOSEN-PLAINTEXT attacker who
  fixes the nonce and interpolates the map α → c from oracle queries (this needs
  NO secret key — it is pure input/output fitting). With FRESH nonces the map
  changes per query and cannot be interpolated (that defense is A2). Here we
  measure the WORST CASE (fixed/reused nonce), which upper-bounds attacker power
  and is exactly the quantity the suspended bit-claims (74/…) were based on.

Method:
  1. Fix nonce. Pick α*, encrypt → c*.
  2. Interpolate each output coord F_{v,k}(α) as a degree-≤3e polynomial in α
     via encrypt-oracle sampling + modular linear solve.
  3. Form the system {F_{v,k}(α) − c*_{v,k} = 0} and run Macaulay-matrix
     linearization at increasing D; empirical D_reg = smallest D recovering α*.
  4. Compare to the semi-regular Hilbert-series prediction.

Run: python attacks/A6_dreg_public_system.py
"""
import os
import sys
import time

import numpy as np

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from core.complex2d import Complex2D
from crypto.protocol_v4r3_pq128 import setup_pq128, keygen_pq128, encrypt_pq128
from crypto.f4_solver import all_monomials, solve_polysystem_linearization

SEED = 20260705
NONCE = b"\x00" * 16  # fixed / reused: worst case for the defender


def hilbert_dreg(m_eqs: int, degree: int, n_vars: int, bound: int = 400) -> int:
    """Semi-regular D_reg: first D with non-positive coeff in
    (1 - t^degree)^m_eqs / (1 - t)^n_vars."""
    # numerator (1 - t^degree)^m_eqs via binomial, truncated
    num = [0] * (bound + 1)
    from math import comb
    for k in range(m_eqs + 1):
        deg = k * degree
        if deg > bound:
            break
        num[deg] += ((-1) ** k) * comb(m_eqs, k)
    # divide by (1-t)^n_vars  ==  multiply by (1-t)^{-n_vars} = Σ C(n_vars-1+j, j) t^j
    inv = [comb(n_vars - 1 + j, j) for j in range(bound + 1)]
    coef = [0] * (bound + 1)
    for i in range(bound + 1):
        if num[i] == 0:
            continue
        for j in range(bound + 1 - i):
            coef[i + j] += num[i] * inv[j]
    for D in range(bound + 1):
        if coef[D] <= 0:
            return D
    return -1


def solve_square_multi_rhs(V, Y, p):
    """Solve V·X = Y over F_p where V is square (n×n) and Y is (n×k) columns.

    Single Gauss-Jordan on the augmented [V | Y]; back-reads all k solution
    columns at once. Returns X as list of k coefficient vectors (length n each),
    or None if V is singular.
    """
    n = len(V)
    k = len(Y[0])
    A = [list(V[i]) + list(Y[i]) for i in range(n)]  # n × (n+k)
    width = n + k
    for c in range(n):
        pr = -1
        for i in range(c, n):
            if A[i][c] % p != 0:
                pr = i
                break
        if pr == -1:
            return None  # singular
        A[c], A[pr] = A[pr], A[c]
        inv = pow(A[c][c], p - 2, p)
        row_c = A[c]
        A[c] = [(x * inv) % p for x in row_c]
        row_c = A[c]
        for i in range(n):
            if i != c:
                f = A[i][c] % p
                if f:
                    Ai = A[i]
                    A[i] = [(Ai[j] - f * row_c[j]) % p for j in range(width)]
    # columns n..n+k-1 hold the solutions
    return [[A[r][n + j] for r in range(n)] for j in range(k)]


def interpolate_system(params, key, alpha_star, degree):
    """Interpolate each output coord as a degree-≤`degree` poly in α.

    One shared square sample matrix V (n_mono × n_mono) is inverted ONCE via a
    single multi-RHS Gauss-Jordan over all n·d output coordinates, instead of
    re-solving per coordinate. Returns (equations, c_star)."""
    p, d, K = params.p, params.d, params.K
    n_out = K.n * d
    monos, mono_idx = all_monomials(d, degree)
    n_mono = len(monos)

    # Interpolating a degree-`degree` polynomial needs at least n_mono DISTINCT
    # sample points, but F_p^d has only p^d of them. Guard against the field
    # being too small (otherwise fresh_alpha would spin forever).
    if p ** d < n_mono:
        raise RuntimeError(
            f"field too small: p^d={p**d} < n_mono={n_mono} "
            f"(need larger p for d={d}, degree={degree})")

    rng = np.random.default_rng(SEED + 999)
    seen = set()

    def fresh_alpha():
        while True:
            if len(seen) >= p ** d:
                raise RuntimeError("exhausted all p^d distinct points")
            a = tuple(int(rng.integers(0, p)) for _ in range(d))
            if a not in seen:
                seen.add(a)
                return a

    # Build a square, invertible sample matrix V (retry singular rows).
    V, Y = [], []
    while len(V) < n_mono:
        a = fresh_alpha()
        _, c = encrypt_pq128(params, key, list(a), nonce=NONCE)
        V.append([pow_mono(a, m, p) for m in monos])
        Y.append(list(c))
    sols = solve_square_multi_rhs(V, Y, p)
    tries = 0
    while sols is None and tries < 50:
        tries += 1
        # replace a random-ish row with a fresh sample and retry
        a = fresh_alpha()
        _, c = encrypt_pq128(params, key, list(a), nonce=NONCE)
        V[tries % n_mono] = [pow_mono(a, m, p) for m in monos]
        Y[tries % n_mono] = list(c)
        sols = solve_square_multi_rhs(V, Y, p)
    if sols is None:
        raise RuntimeError("interpolation matrix singular after retries")

    _, c_star = encrypt_pq128(params, key, list(alpha_star), nonce=NONCE)

    equations = []
    const = tuple([0] * d)
    for i in range(n_out):
        coef = sols[i]
        poly = {monos[j]: coef[j] % p for j in range(n_mono) if coef[j] % p != 0}
        poly[const] = (poly.get(const, 0) - c_star[i]) % p
        poly = {m: cc for m, cc in poly.items() if cc % p != 0}
        equations.append(poly)
    return equations, c_star


def pow_mono(a, mono, p):
    r = 1
    for i, e in enumerate(mono):
        if e:
            r = (r * pow(a[i], e, p)) % p
    return r


def measure_one(d, p, substrate="tetra"):
    K = Complex2D.tetrahedron() if substrate == "tetra" else Complex2D.octahedron()
    rng = np.random.default_rng(SEED)
    params = setup_pq128(K, d, p, rng=rng)
    key = keygen_pq128(params, rng=rng)
    e = params.exponent
    degree = 3 * e
    m_eqs = K.n * d
    hpred = hilbert_dreg(m_eqs, degree, d)

    alpha_star = [int(rng.integers(0, p)) for _ in range(d)]
    t0 = time.time()
    equations, c_star = interpolate_system(params, key, alpha_star, degree)
    interp_t = time.time() - t0

    # search empirical D_reg
    emp = None
    tsolve0 = time.time()
    D_cap = hpred + 8 if hpred > 0 else degree + 8
    for D in range(1, D_cap + 1):
        try:
            sol = solve_polysystem_linearization(equations, d=d, p=p, D_reg=D)
        except Exception:
            sol = None
        if sol is not None and list(sol) == alpha_star:
            emp = D
            break
    solve_t = time.time() - tsolve0
    gap = (emp - hpred) if (emp is not None and hpred > 0) else None
    return {
        "d": d, "p": p, "e": e, "3e": degree, "m_eqs": m_eqs,
        "hilbert_Dreg": hpred, "empirical_Dreg": emp, "gap": gap,
        "interp_s": round(interp_t, 1), "solve_s": round(solve_t, 1),
    }


def main():
    print(f"# A6 empirical D_reg of the message-recovery system "
          f"(seed={SEED}, fixed nonce)\n")
    print(f"{'d':>3} {'p':>5} {'e':>3} {'3e':>4} {'m_eqs':>6} "
          f"{'Hilbert':>8} {'empirical':>10} {'gap':>5} {'interp_s':>9} {'solve_s':>8}")
    # p must satisfy p^d >= n_mono = C(d+3e, d) AND p > 3e (DESIGN constraint).
    configs = [(2, 17), (3, 11)]
    results = []
    for (d, p) in configs:
        r = measure_one(d, p)
        results.append(r)
        print(f"{r['d']:>3} {r['p']:>5} {r['e']:>3} {r['3e']:>4} {r['m_eqs']:>6} "
              f"{r['hilbert_Dreg']:>8} {str(r['empirical_Dreg']):>10} "
              f"{str(r['gap']):>5} {r['interp_s']:>9} {r['solve_s']:>8}")
    # d >= 4: interpolating a degree-3e system needs C(d+3e,d) distinct points
    # and a dense C(d+3e,d)-square solve over F_p — e.g. d=4 ⇒ 3876×3876. That
    # is infeasible in pure Python and is left PENDING for SageMath/Magma
    # (rules: heavy linear algebra is out of scope for the Python reference).
    print("#   4     -   -    -      -        -   PENDING(Sage)     -   "
          "(3876x3876 solve)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
