"""
experiments/11_transfer_proxies.py — Block 5: proxy -> Goldilocks transfer.

msolve cannot run over Goldilocks (characteristic > 2^31), so the +1-bit/round law
is measured on proxy primes. Transfer argument: the CICO system has the SAME
structure for every prime with gcd(7, p-1)=1 (same S-box exponent, same coupling,
same equations); only the characteristic differs. If D_I and the F4 solving degree
are IDENTICAL across proxies spanning ~5 to ~30 bits (31, 65371, 1073742091), that
is direct evidence D_I is characteristic-independent (structural) and therefore
transfers to Goldilocks. The residual (running the actual Goldilocks system) stays
OPEN -- no engine reaches it.

Minimal input-coupling, m=1. msolve -t 8. Run:
    python experiments/11_transfer_proxies.py
"""
import os
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from core.complex2d import Complex2D
from crypto import spn_coupling as C
from crypto.spn_cico import write_msolve
from crypto.spn_field import PROXY_PRIMES, is_goldilocks_like


def _mnt(path):
    d, r = path.replace("\\", "/").split(":", 1)
    return f"/mnt/{d.lower()}{r}"


def _run(ms, groebner, timeout=300):
    args = ["wsl", "msolve", "-t", "8"]
    if groebner:
        args += ["-g", "2", "-v", "2"]
    args += ["-f", _mnt(ms)]
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout).stdout
    except subprocess.TimeoutExpired:
        return None


def ideal_degree(ms):
    out = _run(ms, False)
    if out is None:
        return "timeout"
    m = re.match(r"\[0, \[\d+,\s*\d+,\s*(\d+),", " ".join(out.split()))
    return int(m.group(1)) if m else "?"


def solving_degree(ms):
    out = _run(ms, True)
    if out is None:
        return "timeout"
    degs = [int(m.group(1)) for line in out.splitlines()
            if (m := re.match(r"\s*(\d+)\s+\d+\s+\d+\s+\d+ x \d+", line))]
    return max(degs) if degs else "?"


def main():
    K = Complex2D.tetrahedron()
    tmp = tempfile.mkdtemp(prefix="transfer_")
    primes = PROXY_PRIMES  # (31, 65371, 1073742091)
    print("=== Transfer check: D_I / F4 solving degree across proxy primes ===")
    print("    minimal input-coupling, m=1; law D_I = 7^R * 2^(R-1)\n")
    print(f"{'prime':>12}{'~bits':>7} | " + " | ".join(f"R={R} (D_I,sd)" for R in (2, 3)))
    for p in primes:
        assert is_goldilocks_like(p) or p == 31   # 31: gcd(7,30)=1 (bijective)
        cells = []
        for R in (2, 3):
            prm = C.CoupledParams(K, p, R, "input", density=1)
            v, po, _ = C.build_coupled_cico(prm, c=K.n - 1)
            ms = os.path.join(tmp, f"t_p{p}_R{R}.ms")
            write_msolve(ms, v, po, p)
            cells.append(f"({ideal_degree(ms)},{solving_degree(ms)})")
        print(f"{p:>12}{p.bit_length():>7} | " + " | ".join(f"{c:>12}" for c in cells))

    print("\nnominal law: R=2 -> D_I=98, R=3 -> D_I=1372.")
    print("If (D_I, sd) are identical across all three primes -> D_I is")
    print("characteristic-independent (structural) -> transfers to Goldilocks.")
    print("OPEN: running the actual Goldilocks system (msolve limited to <2^31).")


if __name__ == "__main__":
    main()
