"""
tests/test_alaniz_ao.py — Block 4: the concrete Alaniz-AO permutation and sponge.
"""
import itertools
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from crypto.alaniz_ao import (
    ALANIZ_P, ALANIZ_ROUNDS, ALANIZ_T, AlanizAO, chain_coupling, sponge_hash,
)
from crypto.spn_mix import branch_number


def test_default_params():
    perm = AlanizAO()
    assert perm.d == 7 and perm.t == ALANIZ_T and perm.rounds == ALANIZ_ROUNDS
    # Cauchy layer is MDS: branch number = t+1
    assert branch_number(perm.M, perm.p) == perm.t + 1


def test_chain_coupling_is_triangular():
    at = chain_coupling(8)
    for v, pairs in at.items():
        for (a, b) in pairs:
            assert a < b < v


def test_permutation_roundtrips_goldilocks():
    perm = AlanizAO()
    for s in range(30):
        x = [(s * 1000003 + i * 7654319) % ALANIZ_P for i in range(perm.t)]
        assert perm.permute_inverse(perm.permute(x)) == x


def test_permutation_bijective_small_prime():
    """Injectivity on a chunk of the domain over a small Goldilocks-like prime."""
    perm = AlanizAO(p=65371, t=4, rounds=3)
    seen = set()
    for a in range(0, 65371, 149):
        x = [a, (a * 7) % 65371, (a * 13) % 65371, (a * 29) % 65371]
        y = tuple(perm.permute(x))
        assert y not in seen
        seen.add(y)
        assert perm.permute_inverse(list(y)) == x


def test_sponge_cico_effective_m_is_capacity():
    """The sponge inversion CICO fixes the kappa capacity input lanes and
    constrains kappa outputs; the free branches (= m) are the kappa rate lanes.
    For t=2*kappa this is a square 0-dim system with m = kappa (structural check,
    no msolve): verifies the effective-m used to set R and the security bound."""
    from core.complex2d import Complex2D
    from crypto import spn_coupling as C

    p = 1073742091
    for K, kappa in ((Complex2D.tetrahedron(), 2), (Complex2D.octahedron(), 3)):
        t = K.n
        assert t == 2 * kappa                      # balanced sponge (rate=capacity)
        terms = [(v, v - 2, v - 1) for v in range(2, t)]   # chain coupling
        prm = C.CoupledParams(K, p, 2, "input", terms=terms)
        _, _, meta = C.build_coupled_cico(prm, c=kappa)
        assert meta["fixed_in"] == list(range(t - kappa, t))   # capacity lanes fixed
        assert len(meta["fixed_out"]) == t - kappa == kappa    # kappa constraints
        assert (t - kappa) == kappa                             # m_effective = kappa


def test_sponge_deterministic_and_sensitive():
    assert sponge_hash([1, 2, 3, 4, 5]) == sponge_hash([1, 2, 3, 4, 5])
    assert sponge_hash([1, 2, 3, 4, 5]) != sponge_hash([1, 2, 3, 4, 6])
    assert len(sponge_hash([9], out_len=4)) == 4
    # absorbing more than one rate block works and stays in-field
    h = sponge_hash(list(range(20)), out_len=4)
    assert all(0 <= v < ALANIZ_P for v in h)
