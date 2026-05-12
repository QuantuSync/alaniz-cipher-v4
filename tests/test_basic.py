"""
Minimal test suite for Alaniz Cipher v4r3.

Run with: python -m unittest tests/test_basic.py
Or:       pytest tests/test_basic.py
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

import numpy as np
from core.complex2d import Complex2D
from crypto.protocol_v4r3_pq128 import setup_pq128, keygen_pq128, encrypt_pq128
from crypto.decrypt_v4r3_pq128 import decrypt_pq128
from crypto.field_pd import FpdField, make_field
from crypto.irreducible import find_irreducible_rabin, is_irreducible_rabin
from crypto.poly_pd import find_all_roots_in_Fq


class TestComplex2D(unittest.TestCase):
    def test_tetrahedron(self):
        K = Complex2D.tetrahedron()
        self.assertEqual(K.n, 4)
        self.assertEqual(len(K.edges), 6)
        self.assertEqual(len(K.triangles), 4)

    def test_octahedron(self):
        K = Complex2D.octahedron()
        self.assertEqual(K.n, 6)


class TestField(unittest.TestCase):
    def test_make_field_small(self):
        F = make_field(7, 3)
        a = F.from_scalar(2)
        b = F.from_scalar(3)
        c = F.mul(a, b)
        d = F.add(a, b)
        self.assertEqual(F.from_scalar(6), c)
        self.assertEqual(F.from_scalar(5), d)

    def test_make_field_large(self):
        # The case where galois hangs
        F = make_field(2**61 - 1, 6)
        a = F.one()
        b = F.one()
        c = F.add(a, b)
        d = F.mul(a, b)
        self.assertEqual(F.from_scalar(2), c)
        self.assertEqual(F.one(), d)


class TestIrreducible(unittest.TestCase):
    def test_small_prime(self):
        for d in [2, 3, 4]:
            f = find_irreducible_rabin(7, d)
            self.assertEqual(len(f), d + 1)
            self.assertEqual(f[-1], 1)
            self.assertTrue(is_irreducible_rabin(f, 7))

    def test_large_prime(self):
        p = 2**61 - 1
        for d in [4, 6, 8]:
            f = find_irreducible_rabin(p, d)
            self.assertEqual(len(f), d + 1)
            self.assertTrue(is_irreducible_rabin(f, p))


class TestRoundtrip(unittest.TestCase):
    def test_roundtrip_d6_small_p(self):
        """Smallest e2e test: d=6, p=257, recover the message."""
        K = Complex2D.tetrahedron()
        rng = np.random.default_rng(42)
        params = setup_pq128(K, 6, 257, rng=rng)
        key = keygen_pq128(params, rng=rng)
        alpha = [int(rng.integers(0, 100)) for _ in range(6)]
        nonce, ct = encrypt_pq128(params, key, alpha)
        alpha_rec, _ = decrypt_pq128(params, key, ct, nonce, verbose=False, try_D_values=(5,))
        self.assertEqual(list(alpha_rec), alpha)

    def test_roundtrip_d6_pq61(self):
        """Larger e2e test: d=6, p=2^61-1, single seed."""
        K = Complex2D.tetrahedron()
        rng = np.random.default_rng(42)
        params = setup_pq128(K, 6, 2**61 - 1, rng=rng)
        key = keygen_pq128(params, rng=rng)
        alpha = [int(rng.integers(0, 2**60)) for _ in range(6)]
        nonce, ct = encrypt_pq128(params, key, alpha)
        alpha_rec, _ = decrypt_pq128(params, key, ct, nonce, verbose=False, try_D_values=(5,))
        self.assertEqual(list(alpha_rec), alpha)


class TestRootFinding(unittest.TestCase):
    def test_cz_finds_known_root(self):
        """Construct a polynomial with a known root and verify CZ recovers it."""
        F = make_field(11, 2)  # F_121
        # f(x) = (x - 3)(x - 5) = x² - 8x + 15
        # We need to test find_all_roots_in_Fq with multi-root scenarios.
        # In F_121, find roots of x² - 8x + 15 = 0
        # First, encode the polynomial: coefs [15, -8, 1] in F_q
        coefs = [F.from_scalar(15), F.from_scalar(-8 % 11), F.one()]
        roots = find_all_roots_in_Fq(F, coefs)
        # Convert roots back to F_p representation if they're in F_p
        # Expected: 3 and 5 in F_p ⊂ F_121
        root_values = set()
        for r in roots:
            # Check if r is in F_p (only first coordinate non-zero in extension)
            if all(r[i] == 0 for i in range(1, F.d)):
                root_values.add(r[0])
        self.assertEqual(root_values, {3, 5})


if __name__ == "__main__":
    unittest.main()
