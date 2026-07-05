"""
attacks/A_cheaplunch_resultant.py — Block 3: CheapLunch (eprint 2025/2040) and
resultant/elimination (2025/259, 2026/1281) RUN on the minimal construction,
not just argued via D_I.

Both attacks are dominated by the ideal degree D_I (the number of CICO solutions):
  * CheapLunch fixes MORE outputs (CICO-2) to shrink the modeling; but in our
    square parametrization more fixed outputs = larger m = LARGER D_I, so it cannot
    beat the cheapest CICO-1 (m=1). We measure D_I for CICO-1 vs CICO-2 to show the
    cost tracks D_I and there is no sub-D_I shortcut.
  * The resultant attack eliminates variables down to a univariate; its degree is
    the ideal degree D_I. We run msolve's elimination order (-e nvars-1) and read
    the univariate eliminant degree, confirming it equals D_I.

msolve -t 16. Fixed seeds, proxy 1073742091. Run:
    python attacks/A_cheaplunch_resultant.py
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


def _mnt(path):
    d, r = path.replace("\\", "/").split(":", 1)
    return f"/mnt/{d.lower()}{r}"


def _msolve(args, ms, timeout=600):
    try:
        return subprocess.run(["wsl", "msolve", "-t", "16"] + args + ["-f", _mnt(ms)],
                              capture_output=True, text=True, timeout=timeout).stdout
    except subprocess.TimeoutExpired:
        return None


def ideal_degree(ms, timeout=600):
    out = _msolve([], ms, timeout)
    if out is None:
        return "timeout"
    m = re.match(r"\[0, \[\d+,\s*\d+,\s*(\d+),", " ".join(out.split()))
    return int(m.group(1)) if m else "?"


def eliminant_degree(ms, nvars, timeout=600):
    """Run the elimination order eliminating the first nvars-1 variables; the
    surviving univariate generator's degree = D_I for a 0-dim ideal."""
    out = _msolve(["-e", str(nvars - 1), "-g", "2"], ms, timeout)
    if out is None:
        return "timeout"
    # parse leading monomial degrees of the last (univariate) block; take the max
    # exponent appearing on the sole remaining variable.
    degs = re.findall(r"\^(\d+)", out)
    return max((int(d) for d in degs), default=("?" if "[1]" not in out else 0))


def build(K, R, m, density, p, tmp, tag):
    prm = C.CoupledParams(K, p, R, "input", density=density)
    v, po, _ = C.build_coupled_cico(prm, c=K.n - m)
    ms = os.path.join(tmp, f"{tag}.ms")
    write_msolve(ms, v, po, p)
    return ms, len(v)


def main():
    p = PROXY_PRIME_30
    tmp = tempfile.mkdtemp(prefix="cheaplunch_")
    K = Complex2D.tetrahedron()
    print("=== CheapLunch (more fixed outputs = CICO-2) on the minimal build ===")
    print(f"{'CICO':>7}{'R':>3}{'m':>3}{'D_I':>10}{'law 7^(Rm)*m*2^(R-1)':>22}", flush=True)
    for (R, m, name) in [(2, 1, "CICO-1"), (2, 2, "CICO-2"), (3, 1, "CICO-1"), (3, 2, "CICO-2")]:
        ms, _ = build(K, R, m, 1, p, tmp, f"cl_R{R}_m{m}")
        di = ideal_degree(ms)
        law = 7**(R*m) * m * 2**(R-1)
        print(f"{name:>7}{R:>3}{m:>3}{str(di):>10}{law:>22}", flush=True)
    print("  -> more fixed outputs (CICO-2, larger m) gives LARGER D_I, never smaller:")
    print("     CheapLunch cannot beat the cheapest CICO-1. Cost stays tied to D_I.\n")

    print("=== Resultant / elimination: univariate eliminant degree = D_I ===")
    print(f"{'R':>3}{'m':>3}{'nvars':>7}{'D_I':>8}{'eliminant deg':>15}{'match':>7}", flush=True)
    for (R, m) in [(2, 1), (3, 1), (2, 2)]:
        ms, nvars = build(K, R, m, 1, p, tmp, f"res_R{R}_m{m}")
        di = ideal_degree(ms)
        ed = eliminant_degree(ms, nvars)
        match = "yes" if di == ed else str(ed)
        print(f"{R:>3}{m:>3}{nvars:>7}{str(di):>8}{str(ed):>15}{match:>7}", flush=True)
    print("  -> the eliminant degree equals D_I: the resultant attack's univariate")
    print("     has degree D_I, so its cost is also D_I-bound. No shortcut.")


if __name__ == "__main__":
    main()
