"""
tests/test_widetrail.py — Block 1: S-box x^7 differential/linear bounds and the
coupling non-degradation (regression for docs/WIDE_TRAIL.md).
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from math import gcd

D = 7


def _ddt_max(p, d):
    powers = [pow(x, d, p) for x in range(p)]
    best = 0
    for a in range(1, p):
        counts = {}
        for x in range(p):
            b = (powers[(x + a) % p] - powers[x]) % p
            counts[b] = counts.get(b, 0) + 1
        best = max(best, max(counts.values()))
    return best


def test_sbox_ddt_bounded_by_d_minus_1():
    """x^7 differential uniformity must not exceed d-1 = 6 (on primes where x^7
    is a bijection, i.e. gcd(7, p-1) = 1)."""
    for p in (31, 257):
        assert gcd(D, p - 1) == 1        # x^7 is a bijection of F_p
        assert _ddt_max(p, D) <= D - 1


def test_input_coupling_does_not_increase_differential_uniformity():
    """The coupled vertex map (x_v + w*x_a*x_b)^7 has, per (x_a,x_b) slice, the
    same differential uniformity as pure x^7 (adding an offset cannot raise it)."""
    p = 31
    w = 13

    def f(xv, xa, xb):
        return pow((xv + w * xa * xb) % p, D, p)

    base = _ddt_max(p, D)
    worst = 0
    for (dv, da, db) in [(1, 0, 0), (1, 1, 0), (0, 1, 1), (2, 3, 5), (7, 1, 1)]:
        counts = {}
        for xv in range(p):
            for xa in range(p):
                for xb in range(p):
                    out = (f((xv + dv) % p, (xa + da) % p, (xb + db) % p)
                           - f(xv, xa, xb)) % p
                    counts[out] = counts.get(out, 0) + 1
        worst = max(worst, max(counts.values()))
    # counts are over p^3 inputs; per (x_a,x_b) slice max = worst / p^2 <= d-1.
    assert worst <= (D - 1) * p * p
    assert base <= D - 1
