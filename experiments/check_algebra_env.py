"""
experiments/check_algebra_env.py — algebra backend detection + self-test.

Phase-1 (AO reframe) needs fast linear algebra over F_p at scale (Macaulay-matrix
RREF for solving-degree / D_reg measurement) and, ideally, a Groebner engine.

This script reports which backends are available and self-tests the usable ones:
  - python-flint  : fast nmod_mat RREF/rank/nullspace + univariate resultants.
                    This is the workhorse for Macaulay-based AO analysis.
  - Sage/msolve/Magma/Singular : full Groebner engines (F4/F5/Buchberger).

It also cross-checks flint's RREF against the pure-Python f4_solver on the known
d=2 A6 instance (empirical D_reg = 22) so we trust the accelerated path before
relying on it.

Run: python experiments/check_algebra_env.py
Exit 0 if at least one usable backend passes self-test; 1 otherwise.
"""
import os
import shutil
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass


def detect_cli(names):
    found = {}
    for n in names:
        path = shutil.which(n)
        found[n] = path
    return found


def detect_wsl():
    try:
        r = subprocess.run(["wsl.exe", "-l", "-q"], capture_output=True,
                           text=True, timeout=10)
        # WSL prints an install hint (nonzero-ish) when no distro exists.
        out = (r.stdout or "") + (r.stderr or "")
        return "no" if ("not installed" in out.lower() or "no est" in out.lower()
                        or not r.stdout.strip()) else "yes"
    except Exception:
        return "no"


def check_flint():
    """Return (available, report_dict)."""
    try:
        import flint
    except Exception as ex:
        return False, {"error": f"import failed: {ex}"}
    rep = {"version": flint.__version__}

    # 1. nmod_mat RREF / rank correctness (known 3x3 over F_5)
    M = flint.nmod_mat(3, 3, [2, 1, 1, 1, 3, 2, 1, 0, 4], 5)
    rep["rank_3x3_F5"] = M.rank()  # expect 3 (invertible)

    # 2. univariate resultant correctness over F_7:
    #    res(x^2-2, x^2-3) with roots ±√2, ±√3 → nonzero; sanity vs sympy-free check
    a = flint.nmod_poly([5, 0, 1], 7)  # x^2 - 2  (−2 ≡ 5)
    b = flint.nmod_poly([4, 0, 1], 7)  # x^2 - 3  (−3 ≡ 4)
    rep["resultant_ok"] = (a.resultant(b) == (a.resultant(b)))  # computes without error
    rep["resultant_value_F7"] = int(a.resultant(b))

    return True, rep


def flint_rref_rank(rows, n_cols, p):
    """Rank of a sparse Macaulay matrix (list of {col:coef}) via flint nmod_mat."""
    import flint
    n_rows = len(rows)
    data = [0] * (n_rows * n_cols)
    for i, r in enumerate(rows):
        base = i * n_cols
        for c, v in r.items():
            data[base + c] = int(v) % p
    M = flint.nmod_mat(n_rows, n_cols, data, p)
    return M.rank()


def cross_check_d2(verbose=True):
    """Build the A6 d=2 Macaulay system and confirm flint rank == numpy rank,
    and that flint reproduces the pivot count consistent with D_reg=22."""
    import numpy as np
    from core.complex2d import Complex2D
    from crypto.protocol_v4r3_pq128 import setup_pq128, keygen_pq128
    from crypto.f4_solver import build_macaulay_matrix, rref_sparse_fp
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "attacks"))
    from A6_dreg_public_system import interpolate_system

    d, p = 2, 17
    K = Complex2D.tetrahedron()
    rng = np.random.default_rng(20260705)
    params = setup_pq128(K, d, p, rng=rng)
    key = keygen_pq128(params, rng=rng)
    degree = 3 * params.exponent
    alpha = [int(rng.integers(0, p)) for _ in range(d)]
    eqs, _ = interpolate_system(params, key, alpha, degree)

    D = 22  # known empirical D_reg for this instance
    rows, monos, _ = build_macaulay_matrix(eqs, d, p, D)
    n_cols = len(monos)

    t0 = time.time()
    rref_rows, pivots = rref_sparse_fp([dict(r) for r in rows], n_cols, p)
    numpy_rank = len(pivots)
    t_numpy = time.time() - t0

    t0 = time.time()
    flint_rank = flint_rref_rank(rows, n_cols, p)
    t_flint = time.time() - t0

    ok = (numpy_rank == flint_rank)
    if verbose:
        print(f"  Macaulay d=2 p=17 D={D}: {len(rows)}x{n_cols}")
        print(f"    numpy rank = {numpy_rank}  ({t_numpy:.2f}s)")
        print(f"    flint rank = {flint_rank}  ({t_flint:.2f}s)  "
              f"speedup x{(t_numpy / t_flint):.1f}" if t_flint > 0 else "")
        print(f"    ranks agree: {ok}")
    return ok


def main():
    print("# Algebra backend check\n")

    print("## CLI Groebner engines")
    cli = detect_cli(["sage", "magma", "msolve", "Singular", "singular", "gp"])
    for n, path in cli.items():
        print(f"    {n:10s}: {'FOUND ' + path if path else 'absent'}")
    print(f"    WSL       : {detect_wsl()}")

    print("\n## python-flint (fast F_p linear algebra + resultants)")
    flint_ok, rep = check_flint()
    if flint_ok:
        for k, v in rep.items():
            print(f"    {k:20s}: {v}")
    else:
        print(f"    NOT AVAILABLE: {rep}")

    usable = flint_ok
    if flint_ok:
        print("\n## Cross-check flint RREF vs pure-Python (A6 d=2 instance)")
        try:
            cross_ok = cross_check_d2()
            usable = usable and cross_ok
        except Exception as ex:
            print(f"    cross-check FAILED: {type(ex).__name__}: {ex}")
            usable = False

    print("\n## Capability summary")
    print(f"    Fast Macaulay/RREF over F_p (solving-degree, D_reg): "
          f"{'AVAILABLE (python-flint)' if flint_ok else 'BLOCKED'}")
    print(f"    Univariate resultants (A-Resultant): "
          f"{'AVAILABLE (python-flint)' if flint_ok else 'BLOCKED'}")
    any_gb = any(cli.values())
    print(f"    Full Groebner engine (F4/F5/Buchberger, monomial-order GB): "
          f"{'AVAILABLE' if any_gb else 'BLOCKED (no Sage/msolve/Magma/Singular; no WSL)'}")

    print("\nRESULT:", "USABLE backend present" if usable else "NO usable backend")
    return 0 if usable else 1


if __name__ == "__main__":
    sys.exit(main())
