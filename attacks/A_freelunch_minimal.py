"""
attacks/A_freelunch_minimal.py — FreeLunch (eprint 2024/347) on the MINIMAL
input-coupling construction (Camino 1 closure, C1-freelunch).

FreeLunch does NOT reduce the number of CICO solutions; it makes the DRL Groebner
basis "free" (skips the F4 step) so the attack cost drops to the FGLM change-of-
order, whose cost is governed by the IDEAL DEGREE D_I. D_I is invariant under the
monomial order AND the modeling (verified earlier: x-only and a-variable models
give the same D_I). Hence our security metric has always been the FreeLunch cost
(D_I itself), not an inflated D_reg -- there is no nominal-vs-effective gap to
exploit. This attack confirms it on the MINIMAL construction (1 coupling term per
round, the one we defend), which was never tested before (only the dense one was).

What "collapse" would look like: the F4 solving degree stays flat (~input degree)
AND D_I falls back to the baseline 7^(R*m) -- i.e. the extra 2^(R-1) solutions are
not really there. What "resists" looks like: D_I follows the nominal curve
7^(R*m)*m*2^(R-1) (higher than baseline) and the F4 solving degree grows with R.

Measures, for the minimal-input construction vs the indep baseline (m=1):
  * D_I (msolve rational parametrization degree = FreeLunch/FGLM cost driver),
  * the DRL F4 solving degree (max step degree, msolve -v 2 -g 2),
  * msolve wall time (empirical cost signal).

msolve -t 16. Fixed seeds, proxy prime 1073742091. Run:
    python attacks/A_freelunch_minimal.py
"""
import os
import re
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from core.complex2d import Complex2D
from crypto import spn_coupling as C
from crypto.spn_cico import write_msolve
from crypto.spn_field import PROXY_PRIME_30

THREADS = "16"


def _mnt(path):
    d, r = path.replace("\\", "/").split(":", 1)
    return f"/mnt/{d.lower()}{r}"


def _run(ms, groebner, timeout):
    args = ["wsl", "msolve", "-t", THREADS]
    if groebner:
        args += ["-g", "2", "-v", "2"]
    args += ["-f", _mnt(ms)]
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout).stdout
    except subprocess.TimeoutExpired:
        return None


def ideal_degree(ms, timeout):
    t0 = time.time()
    out = _run(ms, False, timeout)
    if out is None:
        return "timeout", timeout
    m = re.match(r"\[0, \[\d+,\s*\d+,\s*(\d+),", " ".join(out.split()))
    return (int(m.group(1)) if m else "?"), round(time.time() - t0)


def solving_degree(ms, timeout):
    out = _run(ms, True, timeout)
    if out is None:
        return "timeout"
    degs = [int(m.group(1)) for line in out.splitlines()
            if (m := re.match(r"\s*(\d+)\s+\d+\s+\d+\s+\d+ x \d+", line))]
    return max(degs) if degs else "?"


def measure(K, R, m, mode, density, p, tmp, timeout):
    kw = {} if mode == "indep" else {"density": density}
    prm = C.CoupledParams(K, p, R, mode, **kw)
    v, po, _ = C.build_coupled_cico(prm, c=K.n - m)
    ms = os.path.join(tmp, f"{mode}_d{density}_t{K.n}_R{R}.ms")
    write_msolve(ms, v, po, p)
    di, secs = ideal_degree(ms, timeout)
    sd = solving_degree(ms, timeout)
    return di, sd, secs


def main():
    p = PROXY_PRIME_30
    tmp = tempfile.mkdtemp(prefix="freelunch_")
    print(f"prime {p}; threads {THREADS}\n", flush=True)
    for label, K, Rs in [
        ("t=4 tetrahedron", Complex2D.tetrahedron(), [2, 3, 4]),
        ("t=6 octahedron", Complex2D.octahedron(), [2, 3]),
    ]:
        print(f"=== {label}, m=1: FreeLunch cost driver D_I + F4 solving degree ===",
              flush=True)
        print(f"  nominal law input: D_I = 7^R * 2^(R-1) ; baseline indep: 7^R",
              flush=True)
        print(f"{'R':>2} | {'indep D_I':>10}{'sd':>4}{'sec':>5}"
              f" | {'min-input D_I':>13}{'sd':>4}{'sec':>5}"
              f" | {'nominal':>9}{'follows?':>9}", flush=True)
        for R in Rs:
            bd, bsd, bsec = measure(K, R, 1, "indep", None, p, tmp, 600)
            md, msd, msec = measure(K, R, 1, "input", 1, p, tmp, 600)
            nominal = 7**R * 2**(R - 1)
            follows = "yes" if md == nominal else ("timeout" if md == "timeout" else "NO")
            print(f"{R:>2} | {str(bd):>10}{str(bsd):>4}{bsec:>5}"
                  f" | {str(md):>13}{str(msd):>4}{msec:>5}"
                  f" | {nominal:>9}{follows:>9}", flush=True)
        print(flush=True)

    print("Verdict logic:", flush=True)
    print(" * min-input D_I follows the nominal 7^R*2^(R-1) (> baseline 7^R) AND its", flush=True)
    print("   F4 solving degree grows with R (> baseline)  -> +1 bit/round RESISTS", flush=True)
    print("   FreeLunch (its cost = FGLM(D_I) is genuinely higher).", flush=True)
    print(" * If min-input D_I fell to 7^R or sd stayed flat -> nominal-degree collapse.", flush=True)


if __name__ == "__main__":
    main()
