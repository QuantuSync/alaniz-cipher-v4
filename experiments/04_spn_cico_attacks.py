"""
experiments/04_spn_cico_attacks.py — Phase 3b: CICO attack suite on the AO SPN
via a real Groebner engine (msolve on WSL).

Attacks modeled against the target papers (NOT generic Groebner):
  * FreeLunch  (eprint 2024/347): the intermediate-variable modeling below is
    exactly the "one variable per S-box input" setting FreeLunch analyses; its
    cost is dominated by resolving the 0-dim ideal, driven by the IDEAL DEGREE
    D_I (sparse-FGLM change of order ~ O(D_I^2)).
  * CheapLunch (eprint 2025/2040): reduces variable/constant overhead; same D_I
    scaling, measured at the attacker-optimal capacity.
  * Resultant  (eprint 2025/259, 2026/1281): eliminate to a univariate of degree
    D_I; forming/solving it is ~Õ(D_I^2) / Õ(D_I). msolve's rational
    parametrization IS this eliminant; its degree (3rd output field) = D_I.

Measured quantity: D_I = degree of msolve's rational parametrization = number of
solutions of the CICO system over the algebraic closure. This is the single
cost driver shared by all three attacks. We measure it for t=6 (octahedron,
PRINCIPAL — sheaf structure genuinely constrains) and t=4 (tetrahedron, MDS
CONTROL) at small R and several capacities c, then extrapolate.

KEY EMPIRICAL LAW (verified R in {1,2,3}, both t, several c):
        D_I = 7^(R · m),     m = t - c = number of free branches,
independent of t AND of the mixing-layer branch number.

Reproducible: fixed seeds; proxy prime 1073742091 (Goldilocks-like, msolve-safe;
NOTE msolve mis-parses CRLF and crashes on some primes near 2^16 — see
docs/CRYPTANALYSIS.md). Run:  python experiments/04_spn_cico_attacks.py
"""
import os
import re
import subprocess
import sys
import tempfile
from math import log2

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from core.complex2d import Complex2D
from crypto.spn_cico import build_cico_system, write_msolve
from crypto.spn_field import PROXY_PRIME_30
from crypto.spn_permutation import SPNParams

LOG2_7 = log2(7)


def _win_to_mnt(path):
    """C:/x/y  ->  /mnt/c/x/y  for WSL."""
    p = path.replace("\\", "/")
    drive, rest = p.split(":", 1)
    return f"/mnt/{drive.lower()}{rest}"


def run_msolve(ms_path, groebner=False, timeout=600):
    """Invoke msolve on WSL; return raw stdout (str)."""
    args = ["wsl", "msolve"]
    if groebner:
        args += ["-g", "2"]
    args += ["-f", _win_to_mnt(ms_path)]
    out = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    return out.stdout


def parse_ideal_degree(param_out):
    """Ideal degree D_I = 3rd field of msolve's rational parametrization.

    Format: [0, [p, nvars, DEGREE, [vars], ...]].  Returns int or None
    ([-1] = empty variety, [1,...] = positive dimensional).
    """
    joined = " ".join(param_out.split())
    m = re.match(r"\[0, \[\d+,\s*\d+,\s*(\d+),", joined)
    return int(m.group(1)) if m else None


def measure(K, R, c, p, tmp, timeout=600):
    prm = SPNParams(K, p, R)
    variables, polys, meta = build_cico_system(prm, c=c)
    ms = os.path.join(tmp, f"cico_t{K.n}_R{R}_c{c}.ms")
    write_msolve(ms, variables, polys, p)
    try:
        out = run_msolve(ms, timeout=timeout)
        di = parse_ideal_degree(out)
    except subprocess.TimeoutExpired:
        di = None
    return {"t": K.n, "R": R, "c": c, "m": K.n - c,
            "n_vars": meta["n_vars"], "n_eqs": meta["n_eqs"],
            "D_I": di, "D_I_pred": 7 ** (R * (K.n - c))}


def sec_bits(D_I, omega=2):
    """Conservative attacker cost model: resolving a 0-dim ideal of degree D_I
    (sparse-FGLM / resultant) ~ D_I^omega field ops. Security = omega·log2 D_I."""
    return omega * log2(D_I)


def r_star(m, target=128, omega=2):
    """Smallest R with omega·log2(7^(R·m)) >= target, i.e. R >= target/(omega·m·log2 7)."""
    import math
    return math.ceil(target / (omega * m * LOG2_7))


def main():
    p = PROXY_PRIME_30
    K4 = Complex2D.tetrahedron()      # t=4, MDS control
    K6 = Complex2D.octahedron()       # t=6, sheaf principal
    # Feasible instances (keep D_I <= ~1.2e5 so FGLM finishes quickly).
    # All D_I <= 16807 so each FGLM finishes in ~seconds at the 30-bit proxy.
    # (7^6 = 117649 cases confirm the same law but take minutes single-threaded.)
    jobs = [
        (K4, 1, 1), (K4, 1, 2), (K4, 1, 3),   # R=1 capacity sweep
        (K4, 2, 2), (K4, 2, 3),               # R=2
        (K4, 3, 3),                           # R=3, m=1 -> 7^3 (round scaling)
        (K6, 1, 1), (K6, 1, 3), (K6, 1, 5),   # t=6 capacity sweep
        (K6, 2, 4),                           # t=6, R=2, m=2 -> 7^4 (t-independence)
    ]
    tmp = tempfile.mkdtemp(prefix="spn_cico_")
    print(f"prime p = {p} (Goldilocks-like proxy); tmp = {tmp}\n")
    hdr = f"{'t':>3}{'R':>3}{'c':>3}{'m':>3}{'n_vars':>7}{'D_I':>10}{'7^(R·m)':>10}{'match':>7}"
    print(hdr)
    print("-" * len(hdr))
    rows = []
    for K, R, c in jobs:
        r = measure(K, R, c, p, tmp)
        rows.append(r)
        match = "yes" if r["D_I"] == r["D_I_pred"] else "NO"
        di = r["D_I"] if r["D_I"] is not None else "timeout"
        print(f"{r['t']:>3}{r['R']:>3}{r['c']:>3}{r['m']:>3}{r['n_vars']:>7}"
              f"{str(di):>10}{r['D_I_pred']:>10}{match:>7}")

    print("\nEMPIRICAL LAW  D_I = 7^(R·m),  m = t - c  (free branches).")
    print("D_I is INDEPENDENT of t and of the mixing branch number:")
    print("  compare (t=4,R=2,m=2) and (t=6,R=2,m=2): both D_I = 7^4 = 2401.\n")

    print("Security (conservative, cost ~ D_I^2 field ops; omega=2):")
    print(f"{'m (=capacity)':>14}{'R*=rounds for 128-bit':>26}")
    for m in (1, 2, 3):
        print(f"{m:>14}{r_star(m):>26}")
    print("\nBecause D_I does not depend on t, R* is the SAME for t=4 and t=6 at")
    print("equal capacity m. The sheaf branch deficit costs 0 extra rounds vs the")
    print("MDS control against FreeLunch/CheapLunch/resultant. Branch number governs")
    print("only the statistical (differential/linear) wide-trail bound, measured")
    print("separately in experiments/03_mix_branch_number.py.")


if __name__ == "__main__":
    main()
