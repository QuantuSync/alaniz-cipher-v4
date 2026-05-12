"""Exp 28b — Side-channel σ⁻¹ analysis with incremental state file."""
import sys, os, json, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'src'))
import numpy as np
from core.complex2d import Complex2D
from crypto.protocol_v4r3_pq128 import setup_pq128, keygen_pq128, encrypt_pq128
from crypto.decrypt_v4r3_pq128 import sigma_inverse_all_candidates


def main():
    K = Complex2D.tetrahedron()
    p = 2**61 - 1
    d = 6
    state_file = "/tmp/sidechan_state.jsonl"

    # Read existing state if any
    done_q1 = set()
    if os.path.exists(state_file):
        with open(state_file) as f:
            for line in f:
                r = json.loads(line)
                if r.get('q') == 'q1':
                    done_q1.add(r['trial'])
    print(f"Existing Q1 trials: {sorted(done_q1)}", flush=True)

    # ---- Q1: fixed key, vary α ----
    rng_key = np.random.default_rng(42)
    params = setup_pq128(K, d, p, rng=rng_key)
    key = keygen_pq128(params, rng=rng_key)
    print(f"Setup done, e={params.exponent}", flush=True)

    target_n = 30
    for trial in range(target_n):
        if trial in done_q1:
            continue
        print(f"  trial {trial}...", end=" ", flush=True)
        t0 = time.time()
        rng_a = np.random.default_rng(1000 + trial)
        alpha = [int(rng_a.integers(0, 2**62)) % p for _ in range(d)]
        nonce, ct = encrypt_pq128(params, key, alpha)
        counts = []
        for v in range(K.n):
            cands = sigma_inverse_all_candidates(params, key, ct, nonce, v)
            counts.append(len(cands))
        total = 1
        for c in counts: total *= c

        alpha_lsb = alpha[0] & 1
        alpha_hw = sum(bin(x).count('1') for x in alpha)
        alpha_mod3 = sum(alpha) % 3
        alpha_mod5 = sum(alpha) % 5

        record = {
            'q': 'q1', 'trial': trial, 'counts': counts, 'total': total,
            'alpha_lsb': alpha_lsb, 'alpha_hw': alpha_hw,
            'alpha_mod3': alpha_mod3, 'alpha_mod5': alpha_mod5,
            't': time.time() - t0,
        }
        with open(state_file, 'a') as f:
            f.write(json.dumps(record) + '\n')
        print(f"counts={counts}, total={total}, t={record['t']:.1f}s", flush=True)


if __name__ == "__main__":
    main()
