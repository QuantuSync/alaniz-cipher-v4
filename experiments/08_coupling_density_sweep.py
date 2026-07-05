"""
experiments/08_coupling_density_sweep.py — Camino 1, Step A: does a MINIMAL
(sparse) input-coupling preserve the +1-bit/round law, or does the acceleration
fade as coupling density drops?

For each density k (k=1 minimal .. full triangle set), measure in msolve the CICO
ideal degree D_I at m=1, R in {2,3}, t in {4,6}, plus the F4 solving degree for
the minimal case (non-trap re-check). Baseline (indep) = 7^R; the dense-coupling
law is D_I = 7^R * 2^(R-1). The gate question: is the 2^(R-1) factor already
present at k=1?

msolve run with -t 8 (16 cores available). Reproducible: fixed seeds, proxy
prime 1073742091. Run:  python experiments/08_coupling_density_sweep.py
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
from crypto.spn_field import PROXY_PRIME_30

THREADS = "8"


def _mnt(path):
    d, r = path.replace("\\", "/").split(":", 1)
    return f"/mnt/{d.lower()}{r}"


def run(ms, groebner=False, timeout=300):
    args = ["wsl", "msolve", "-t", THREADS]
    if groebner:
        args += ["-g", "2", "-v", "2"]
    args += ["-f", _mnt(ms)]
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout).stdout
    except subprocess.TimeoutExpired:
        return None


def ideal_degree(ms, timeout=300):
    out = run(ms, timeout=timeout)
    if out is None:
        return "timeout"
    m = re.match(r"\[0, \[\d+,\s*\d+,\s*(\d+),", " ".join(out.split()))
    return int(m.group(1)) if m else "?"


def solving_degree(ms, timeout=300):
    out = run(ms, groebner=True, timeout=timeout)
    if out is None:
        return "timeout"
    degs = [int(m.group(1)) for line in out.splitlines()
            if (m := re.match(r"\s*(\d+)\s+\d+\s+\d+\s+\d+ x \d+", line))]
    return max(degs) if degs else "?"


def measure_di(K, R, m, density, p, tmp):
    prm = C.CoupledParams(K, p, R, "input", density=density)
    v, po, _ = C.build_coupled_cico(prm, c=K.n - m)
    ms = os.path.join(tmp, f"d{density}_t{K.n}_R{R}_m{m}.ms")
    write_msolve(ms, v, po, p)
    return ideal_degree(ms), prm.n_coupling_terms()


def main():
    p = PROXY_PRIME_30
    tmp = tempfile.mkdtemp(prefix="density_")
    print(f"prime {p}; threads {THREADS}; tmp {tmp}\n", flush=True)

    for label, K, densities in [
        ("t=4 tetrahedron", Complex2D.tetrahedron(), [1, 2, 3, 4]),
        ("t=6 octahedron", Complex2D.octahedron(), [1, 2, 4, 6, 8]),
    ]:
        print(f"=== {label}: D_I(input) vs density, m=1 ===", flush=True)
        print(f"  baseline indep: 7^2=49, 7^3=343 ; dense law: 7^R*2^(R-1) "
              f"(R=2->98, R=3->1372)", flush=True)
        print(f"{'density k':>10}{'#terms':>8}{'D_I(R=2)':>10}{'D_I(R=3)':>10}"
              f"{'2^(R-1)? R=2':>13}{'R=3':>7}", flush=True)
        for k in densities:
            d2, nt = measure_di(K, 2, 1, k, p, tmp)
            d3, _ = measure_di(K, 3, 1, k, p, tmp)
            f2 = f"{d2/49:.2f}x" if isinstance(d2, int) else d2
            f3 = f"{d3/343:.2f}x" if isinstance(d3, int) else d3
            print(f"{k:>10}{nt:>8}{str(d2):>10}{str(d3):>10}{f2:>13}{f3:>7}", flush=True)
        # non-trap re-check: F4 solving degree at minimal vs full, R=2
        prm_min = C.CoupledParams(K, p, 2, "input", density=1)
        v, po, _ = C.build_coupled_cico(prm_min, c=K.n - 1)
        msm = os.path.join(tmp, f"sd_min_t{K.n}.ms")
        write_msolve(msm, v, po, p)
        prm_full = C.CoupledParams(K, p, 2, "input", density=None)
        v2, po2, _ = C.build_coupled_cico(prm_full, c=K.n - 1)
        msf = os.path.join(tmp, f"sd_full_t{K.n}.ms")
        write_msolve(msf, v2, po2, p)
        print(f"  F4 solving degree R=2 m=1: minimal={solving_degree(msm)} "
              f"full={solving_degree(msf)} (indep baseline=7)\n", flush=True)


if __name__ == "__main__":
    main()
