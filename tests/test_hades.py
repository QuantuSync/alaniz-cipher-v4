"""
tests/test_hades.py — HADES (full-partial-full) Alaniz-AO variant: bijectivity,
schedule/cost, and CICO consistency (guards the msolve measurements).
"""
import itertools
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from crypto.alaniz_hades import HadesAO, build_hades_cico

P = 1073742091


def test_hades_schedule_and_counts():
    h = HadesAO(8, 4, 4, p=P)
    assert h.rounds == 8
    assert h.sbox_count() == 4 * 8 + 4 * 1        # full rounds t S-boxes, partial 1
    assert h.schedule[0] == list(range(8)) and h.schedule[4] == [7]


def test_hades_bijective_roundtrip():
    for (t, rf, rp) in [(4, 2, 2), (6, 2, 4), (8, 4, 4), (8, 2, 6)]:
        h = HadesAO(t, rf, rp, p=P)
        for s in range(20):
            x = [(s * 1000003 + i * 7654319) % P for i in range(t)]
            assert h.permute_inverse(h.permute(x)) == x


def test_hades_bijective_exhaustive_tiny():
    h = HadesAO(4, 2, 2, p=31)
    seen = set()
    for x in itertools.product(range(31), repeat=4):
        y = tuple(h.permute(list(x)))
        assert y not in seen
        seen.add(y)
    assert len(seen) == 31 ** 4


def test_hades_cico_consistent_and_square():
    for (t, rf, rp, c) in [(4, 2, 0, 2), (4, 2, 1, 3), (6, 2, 2, 3)]:
        h = HadesAO(t, rf, rp, p=P)
        variables, polys, meta = build_hades_cico(h, c)
        assert meta["n_vars"] == meta["n_eqs"] == len(variables) == len(polys)
        val = {}
        for r, st in enumerate(meta["x_states"]):
            for i, x in enumerate(st):
                val[f"x{r}_{i}"] = x % P
        for r, ad in enumerate(meta["a_states"]):
            for j, a in ad.items():
                val[f"a{r}_{j}"] = a % P
        for poly in polys:
            expr = poly
            for name, x in sorted(val.items(), key=lambda kv: -len(kv[0])):
                expr = expr.replace(name, str(x))
            assert eval(expr.replace("^", "**")) % P == 0
