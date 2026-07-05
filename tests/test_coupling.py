"""
tests/test_coupling.py — Camino 1: sheaf structure as non-linearity (Step 1).

Verifies the HARD design constraint (bijectivity, lesson A5a) BEFORE any attack:
  - the triangular coupling is a bijection for all three modes (indep/add/input),
    checked EXHAUSTIVELY on the tiny Goldilocks-like proxy p=31 at t=4;
  - permute / permute_inverse roundtrip over Goldilocks and t=6;
  - the coupled CICO system is consistent at its witness (guards the msolve
    pipeline) and square for every mode.
"""
import itertools
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from core.complex2d import Complex2D
from crypto import spn_coupling as C
from crypto.spn_field import GOLDILOCKS_P, PROXY_PRIME_30, PROXY_PRIMES

MODES = ("indep", "add", "input")


def test_triangle_coupling_is_earlier_only():
    """Every coupling pair (a,b) into vertex v must have a<b<v (triangular)."""
    for K in (Complex2D.tetrahedron(), Complex2D.octahedron(),
              Complex2D.double_tetrahedron()):
        at = C.triangle_coupling(K)
        for v, pairs in at.items():
            for (a, b) in pairs:
                assert a < b < v


def test_coupling_bijective_exhaustive_tiny():
    """Exhaustive over the full domain 31^4: each coupling mode is a bijection
    (one round; multi-round bijectivity then follows from composition + the
    roundtrip test). The full-permute exhaustion at R=2 was run manually and
    also passes; kept to R=1 here to bound test time."""
    p = PROXY_PRIMES[0]  # 31
    K = Complex2D.tetrahedron()
    dom = list(itertools.product(range(p), repeat=4))
    for mode in MODES:
        prm = C.CoupledParams(K, p, 1, mode)
        seen = set()
        for x in dom:
            y = tuple(C.permute(prm, list(x)))
            assert y not in seen
            seen.add(y)
        assert len(seen) == p ** 4


def test_coupling_roundtrip_goldilocks():
    p = GOLDILOCKS_P
    for K in (Complex2D.tetrahedron(), Complex2D.octahedron()):
        for mode in MODES:
            for R in (1, 3, 6):
                prm = C.CoupledParams(K, p, R, mode)
                x = [(i * 987654321 + 7) % p for i in range(K.n)]
                assert C.permute_inverse(prm, C.permute(prm, x)) == x


def test_coupled_cico_consistent_and_square():
    p = PROXY_PRIME_30
    for K in (Complex2D.tetrahedron(), Complex2D.octahedron()):
        for mode in MODES:
            for R in (1, 2):
                for c in (1, K.n - 1):
                    prm = C.CoupledParams(K, p, R, mode)
                    variables, polys, meta = C.build_coupled_cico(prm, c=c)
                    assert meta["n_vars"] == meta["n_eqs"] == len(variables) == len(polys)
                    val = {}
                    for r, st in enumerate(meta["x_states"]):
                        for i, x in enumerate(st):
                            val[f"x{r}_{i}"] = x % p
                    if meta["use_a"]:
                        for r, st in enumerate(meta["a_states"]):
                            for i, x in enumerate(st):
                                val[f"a{r}_{i}"] = x % p
                    for poly in polys:
                        expr = poly
                        for name, x in sorted(val.items(), key=lambda kv: -len(kv[0])):
                            expr = expr.replace(name, str(x))
                        assert eval(expr.replace("^", "**")) % p == 0
