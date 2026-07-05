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


def test_sponge_deterministic_and_sensitive():
    assert sponge_hash([1, 2, 3, 4, 5]) == sponge_hash([1, 2, 3, 4, 5])
    assert sponge_hash([1, 2, 3, 4, 5]) != sponge_hash([1, 2, 3, 4, 6])
    assert len(sponge_hash([9], out_len=4)) == 4
    # absorbing more than one rate block works and stays in-field
    h = sponge_hash(list(range(20)), out_len=4)
    assert all(0 <= v < ALANIZ_P for v in h)
