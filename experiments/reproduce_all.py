"""
experiments/reproduce_all.py — one-command reproduction (portable, galois-free).

Runs the fast, deterministic baseline that establishes the repo is reproducible and
functional at small scale:
  1. The full pytest suite.
  2. A fixed-seed end-to-end roundtrip at (tetra, d=6, p=257).

Heavier reproductions (d=12 F4 RREF, empirical D_reg at d>=4) require SageMath/
Magma and are listed as PENDING, not run here. See docs/STATUS.md.

Usage:
    python experiments/reproduce_all.py
Deterministic: fixed seed 42.
"""
import os
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(REPO_ROOT, "src")
sys.path.insert(0, SRC)

SEED = 42


def run_pytest() -> bool:
    print("=" * 70)
    print("[1/2] pytest -q")
    print("=" * 70)
    r = subprocess.run([sys.executable, "-m", "pytest", "-q"], cwd=REPO_ROOT)
    return r.returncode == 0


def run_e2e_roundtrip() -> bool:
    print("=" * 70)
    print(f"[2/2] e2e roundtrip: tetra, d=6, p=257, seed={SEED}")
    print("=" * 70)
    import numpy as np
    from core.complex2d import Complex2D
    from crypto.protocol_v4r3_pq128 import setup_pq128, keygen_pq128, encrypt_pq128
    from crypto.decrypt_v4r3_pq128 import decrypt_pq128

    K = Complex2D.tetrahedron()
    rng = np.random.default_rng(SEED)
    params = setup_pq128(K, 6, 257, rng=rng)
    key = keygen_pq128(params, rng=rng)
    alpha = [int(rng.integers(0, 100)) for _ in range(6)]
    nonce, ct = encrypt_pq128(params, key, alpha)
    alpha_rec, _ = decrypt_pq128(params, key, ct, nonce, try_D_values=(5,))
    ok = list(alpha_rec) == alpha
    print(f"  alpha     = {alpha}")
    print(f"  recovered = {list(alpha_rec) if alpha_rec is not None else None}")
    print(f"  roundtrip = {'PASS' if ok else 'FAIL'}")
    return ok


def main() -> int:
    results = {}
    results["pytest"] = run_pytest()
    results["e2e_d6_p257"] = run_e2e_roundtrip()

    print("=" * 70)
    print("SUMMARY (reproducible, seed=%d)" % SEED)
    print("=" * 70)
    for name, ok in results.items():
        print(f"  {name:20s} {'PASS' if ok else 'FAIL'}")
    print("\nPENDING (require SageMath/Magma, see docs/STATUS.md):")
    print("  - d=12 F4 RREF end-to-end")
    print("  - empirical D_reg at d in {4,6,8} on the attacker's system")

    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
