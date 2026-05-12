"""
example.py — minimal end-to-end usage of Alaniz Cipher v4r3.

Run from repo root:
    python example.py
"""
import sys
import os
import time
import numpy as np

# Add src/ to path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from core.complex2d import Complex2D
from crypto.protocol_v4r3_pq128 import setup_pq128, keygen_pq128, encrypt_pq128
from crypto.decrypt_v4r3_pq128 import decrypt_pq128


def main():
    print("=" * 60)
    print(" Alaniz Cipher v4r3 — minimal example")
    print("=" * 60)

    # Choose parameters: tetrahedron, d=6, p=257 (small for quick demo)
    # Note: d=6 with these p gives ~74 bits classical security; use ONLY for demo.
    # For PQ-128, use d=12 with p=2^61-1. See docs/PARAMETERS.md.
    K = Complex2D.tetrahedron()
    d = 6
    p = 257
    
    print(f"\nParameters: tetrahedron, d={d}, p={p} (demo only, NOT PQ-128 secure)")
    
    rng = np.random.default_rng(42)
    
    print("\n[1] Setup (generates field, sheaf basis)...")
    t0 = time.time()
    params = setup_pq128(K, d, p, rng=rng)
    print(f"    done in {time.time()-t0:.2f}s, σ exponent e={params.exponent}")
    
    print("\n[2] Key generation...")
    t0 = time.time()
    key = keygen_pq128(params, rng=rng)
    print(f"    done in {(time.time()-t0)*1000:.1f}ms")
    
    print("\n[3] Encrypt a random message...")
    alpha = [int(rng.integers(0, 100)) for _ in range(d)]
    print(f"    plaintext α = {alpha}")
    t0 = time.time()
    nonce, ciphertext = encrypt_pq128(params, key, alpha)
    print(f"    encrypted in {(time.time()-t0)*1000:.1f}ms")
    print(f"    ciphertext: {list(ciphertext)}")
    
    print("\n[4] Decrypt (this is where most time is spent)...")
    t0 = time.time()
    alpha_recovered, timings = decrypt_pq128(params, key, ciphertext, nonce,
                                                verbose=False, try_D_values=(5,))
    decrypt_time = time.time() - t0
    print(f"    decrypted in {decrypt_time:.1f}s")
    print(f"      σ⁻¹ at 4 vertices: {timings.get('sigma_inverse_total', 0):.2f}s")
    print(f"      F4 RREF + extraction: {timings.get('f4_total', 0):.2f}s")
    print(f"      candidate combos tried: {timings.get('combos_tried', '?')}")
    
    print("\n[5] Verify...")
    if alpha_recovered is None:
        print("    DECRYPTION FAILED")
        return
    match = list(alpha_recovered) == alpha
    print(f"    α_orig: {alpha}")
    print(f"    α_recv: {list(alpha_recovered)}")
    print(f"    MATCH:  {match}")
    print()
    print("=" * 60)
    if match:
        print(" ✓ Roundtrip successful")
    else:
        print(" ✗ Roundtrip FAILED — implementation bug or parameter issue")
    print("=" * 60)


if __name__ == "__main__":
    main()
