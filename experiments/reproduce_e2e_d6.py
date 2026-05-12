"""
Experiment 19 — Robust PQ-128 end-to-end verification across seeds.

Purpose: confirm the full pipeline works reliably, not just for one seed.
Reports exact measured timings.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'src'))
import time
import numpy as np
from core.complex2d import Complex2D
from crypto.protocol_v4r3_pq128 import (setup_pq128, keygen_pq128,
                                          encrypt_pq128)
from crypto.decrypt_v4r3_pq128 import decrypt_pq128


def run_one(K, p, d, seed, label, try_D=(5,)):
    rng = np.random.default_rng(seed)
    params = setup_pq128(K, d, p, rng=rng)
    key = keygen_pq128(params, rng=rng)
    alpha_orig = [int(rng.integers(0, 2**62)) % p for _ in range(d)]
    nonce, ct = encrypt_pq128(params, key, alpha_orig)

    t0 = time.time()
    alpha_rec, timings = decrypt_pq128(params, key, ct, nonce,
                                          verbose=False, try_D_values=try_D)
    decrypt_time = time.time() - t0

    if alpha_rec is None:
        return {"seed": seed, "verify": False, "decrypt_time": decrypt_time,
                "timings": timings}
    match = list(alpha_rec) == alpha_orig
    return {"seed": seed, "verify": match, "decrypt_time": decrypt_time,
            "timings": timings, "alpha_orig": alpha_orig[:2],
            "alpha_rec": list(alpha_rec)[:2]}


def main():
    print("=" * 72)
    print(" Experiment 19: PQ-128 end-to-end verification across seeds")
    print("=" * 72)

    K = Complex2D.tetrahedron()
    p = 2**61 - 1
    d = 6

    print(f"\nParameters: tetrahedron (n=4, m=6, l=4), d=6, p=2^61-1 = {p}")
    print(f"            σ exponent e=17, F4 linearization at D=5")

    seeds = [42, 7, 99, 2024, 1]
    results = []
    for seed in seeds:
        print(f"\n  seed={seed}: running...", end=" ", flush=True)
        r = run_one(K, p, d, seed, f"seed={seed}")
        results.append(r)
        v = r["verify"]
        t = r["decrypt_time"]
        flag = "✓" if v else "✗"
        print(f"{flag} verify={v}, decrypt={t:.1f}s")

    # Summary
    print("\n" + "=" * 72)
    print(" Summary")
    print("-" * 72)
    n_verified = sum(1 for r in results if r["verify"])
    print(f"  Seeds verified: {n_verified}/{len(results)}")
    if n_verified > 0:
        decrypt_times = [r["decrypt_time"] for r in results if r["verify"]]
        sigma_times = [r["timings"].get("sigma_inverse_total", 0) for r in results if r["verify"]]
        f4_times = [r["timings"].get("f4_total", 0) for r in results if r["verify"]]
        struct_times = [r["timings"].get("struct_setup", 0) for r in results if r["verify"]]
        combos = [r["timings"].get("combos_tried", 0) for r in results if r["verify"]]

        print(f"\n  Decrypt times across verified seeds:")
        for r in results:
            if not r["verify"]: continue
            print(f"    seed={r['seed']:>5d}: {r['decrypt_time']:>6.2f}s "
                  f"(σ⁻¹={r['timings'].get('sigma_inverse_total', 0):.1f}s, "
                  f"F4={r['timings'].get('f4_total', 0):.1f}s, "
                  f"combos={r['timings'].get('combos_tried', 0)})")

        print(f"\n  Average breakdown:")
        print(f"    σ⁻¹ (4 vertices):     {np.mean(sigma_times):.2f}s "
              f"(min {min(sigma_times):.2f}, max {max(sigma_times):.2f})")
        print(f"    cubic structure:      {np.mean(struct_times):.2f}s")
        print(f"    F4 D=5:               {np.mean(f4_times):.2f}s "
              f"(min {min(f4_times):.2f}, max {max(f4_times):.2f})")
        print(f"    combos tried avg:     {np.mean(combos):.1f}")
        print(f"    TOTAL avg:            {np.mean(decrypt_times):.2f}s")

    print("=" * 72)


if __name__ == "__main__":
    main()
