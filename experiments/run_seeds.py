"""Run a single seed and append its result to results file."""
import sys, os, json, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'src'))
import numpy as np
from core.complex2d import Complex2D
from crypto.protocol_v4r3_pq128 import setup_pq128, keygen_pq128, encrypt_pq128
from crypto.decrypt_v4r3_pq128 import decrypt_pq128


def run_seed(seed, results_path):
    K = Complex2D.tetrahedron()
    p = 2**61 - 1
    d = 6

    print(f"\n[seed={seed}] starting at {time.strftime('%H:%M:%S')}", flush=True)
    rng = np.random.default_rng(seed)
    params = setup_pq128(K, d, p, rng=rng)
    key = keygen_pq128(params, rng=rng)
    alpha_orig = [int(rng.integers(0, 2**62)) % p for _ in range(d)]
    nonce, ct = encrypt_pq128(params, key, alpha_orig)

    t0 = time.time()
    alpha_rec, timings = decrypt_pq128(params, key, ct, nonce,
                                          verbose=False, try_D_values=(5,))
    decrypt_time = time.time() - t0

    verify = (alpha_rec is not None and list(alpha_rec) == alpha_orig)
    print(f"[seed={seed}] verify={verify}, decrypt={decrypt_time:.1f}s, "
          f"σ⁻¹={timings.get('sigma_inverse_total', 0):.1f}s, "
          f"F4={timings.get('f4_total', 0):.1f}s, "
          f"combos={timings.get('combos_tried', 0)}", flush=True)

    record = {
        "seed": seed,
        "verify": verify,
        "decrypt_time": decrypt_time,
        "sigma_inverse_total": timings.get("sigma_inverse_total", 0),
        "struct_setup": timings.get("struct_setup", 0),
        "f4_total": timings.get("f4_total", 0),
        "combos_tried": timings.get("combos_tried", 0),
        "f4_D_used": timings.get("f4_D_used", None),
        "alpha_orig_first": alpha_orig[:2],
        "alpha_rec_first": list(alpha_rec)[:2] if alpha_rec else None,
    }
    # Append to file
    with open(results_path, "a") as f:
        f.write(json.dumps(record) + "\n")
    return record


if __name__ == "__main__":
    seeds = [int(s) for s in sys.argv[1:-1]]
    results_path = sys.argv[-1]
    for s in seeds:
        run_seed(s, results_path)
