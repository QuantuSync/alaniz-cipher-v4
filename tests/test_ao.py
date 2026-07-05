"""
tests/test_ao.py — AO reframe consistency (Phase-1).

Verifies:
  - ao_forward reproduces the current scheme: encrypt(α) = R(H0·α) − r.
  - the pure-power S-box variant π_e is a bijection per vertex.
  - the CICO message-recovery system, solved by linearization, recovers α.
"""
import os
import sys

import numpy as np
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from core.complex2d import Complex2D
from crypto.protocol_v4r3_pq128 import setup_pq128, keygen_pq128, encrypt_pq128
from crypto.ao_permutation import (ao_forward, section_from_alpha,
                                   round_constants, sbox_layer)

flint = pytest.importorskip("flint")  # CICO builder needs python-flint


def test_ao_forward_matches_encrypt():
    """c = R(H0·α) − r, per-vertex."""
    K = Complex2D.tetrahedron()
    for (d, p) in [(2, 17), (3, 11)]:
        rng = np.random.default_rng(7)
        params = setup_pq128(K, d, p, rng=rng)
        key = keygen_pq128(params, rng=rng)
        alpha = [int(rng.integers(0, p)) for _ in range(d)]
        nonce = b"\x11" * 16
        _, c = encrypt_pq128(params, key, alpha, nonce=nonce)

        s = section_from_alpha(params, alpha)
        z = ao_forward(params, key, s, nonce, variant="impl")
        rc = round_constants(params, nonce)
        c_from_ao = [(z[i] - rc[i]) % p for i in range(K.n * d)]
        assert c_from_ao == list(c)


def test_power_sbox_is_bijection():
    """π_e(τ) = (L·τ+1)^e is a bijection on F_{p^d} (per vertex)."""
    K = Complex2D.tetrahedron()
    d, p = 2, 17
    rng = np.random.default_rng(3)
    params = setup_pq128(K, d, p, rng=rng)
    key = keygen_pq128(params, rng=rng)
    F = params.F
    seen = set()
    # enumerate all p^d field elements at vertex 0, check π_e is injective
    for n in range(p ** d):
        tau = F.from_int(n)
        x = list(tau) + [0] * ((K.n - 1) * d)
        z = sbox_layer(params, key, x, variant="power")
        seen.add(tuple(z[:d]))
    assert len(seen) == p ** d  # bijection ⇒ all images distinct


def test_cico_message_recovery_solves():
    """The CICO system built from the public map recovers α by linearization."""
    from crypto.ao_cico import build_cico_message_recovery
    from crypto.f4_solver import solve_polysystem_linearization
    from crypto.ao_permutation import ao_forward, section_from_alpha, round_constants

    K = Complex2D.tetrahedron()
    d, p = 2, 17
    rng = np.random.default_rng(20260705)
    params = setup_pq128(K, d, p, rng=rng)
    key = keygen_pq128(params, rng=rng)
    nonce = b"\x00" * 16
    alpha = [int(rng.integers(0, p)) for _ in range(d)]

    s = section_from_alpha(params, alpha)
    z_star = ao_forward(params, key, s, nonce, variant="impl")

    eqs, _ = build_cico_message_recovery(params, key, z_star, nonce)
    sol = solve_polysystem_linearization(eqs, d=d, p=p, D_reg=22)
    assert sol is not None and list(sol) == alpha
