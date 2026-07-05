"""
experiments/06_coupling_grade_gate.py — Camino 1, Step-2 MINI-GATE.

Question: does the simplicial (sheaf) coupling of S-boxes make the CICO ideal
degree grow FASTER per round than independent S-boxes? Measures D_I side by side
for three constructions sharing the SAME neutral Cauchy-MDS linear layer:

  indep  baseline A : y_v = x_v^7                     (round degree 7)
  add    B-add      : y_v = x_v^7 + Σ c·x_u·x_u'      (round degree 7)
  input  B-in       : y_v = (x_v + Σ c·x_u·x_u')^7    (round degree 14)

Baseline law (verified in experiment 04): D_I = 7^(R·m), m = t - c free branches.
Gate verdict: D_I(coupled) > D_I(baseline) at equal (R, m)?  If not, the coupling
buys no algebraic security (clean negative). If yes, Step 3 must then check with
FreeLunch/CheapLunch whether the extra degree is real security or a nominal-degree
trap (Griffin/Arion fell that way).

Reproducible: fixed seeds, proxy prime 1073742091. Run:
    python experiments/06_coupling_grade_gate.py
"""
import os
import re
import subprocess
import sys
import tempfile
from math import log2

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from core.complex2d import Complex2D
from crypto import spn_coupling as C
from crypto.spn_cico import write_msolve
from crypto.spn_field import PROXY_PRIME_30


def _win_to_mnt(path):
    p = path.replace("\\", "/")
    drive, rest = p.split(":", 1)
    return f"/mnt/{drive.lower()}{rest}"


def ideal_degree(ms_path, timeout=240):
    try:
        out = subprocess.run(["wsl", "msolve", "-f", _win_to_mnt(ms_path)],
                             capture_output=True, text=True, timeout=timeout).stdout
    except subprocess.TimeoutExpired:
        return "timeout"
    m = re.match(r"\[0, \[\d+,\s*\d+,\s*(\d+),", " ".join(out.split()))
    return int(m.group(1)) if m else "posdim/empty"


def measure(K, R, c, mode, p, tmp):
    prm = C.CoupledParams(K, p, R, mode)
    variables, polys, _ = C.build_coupled_cico(prm, c=c)
    ms = os.path.join(tmp, f"cpl_{mode}_t{K.n}_R{R}_c{c}.ms")
    write_msolve(ms, variables, polys, p)
    return ideal_degree(ms)


def main():
    p = PROXY_PRIME_30
    tmp = tempfile.mkdtemp(prefix="coupling_gate_")
    print(f"prime {p}; tmp {tmp}\n")
    complexes = [("t=4 tetrahedron (control)", Complex2D.tetrahedron()),
                 ("t=6 octahedron (principal)", Complex2D.octahedron())]
    # minimal CICO m=1 (c=t-1), push R; plus one m=2 row.
    for label, K in complexes:
        print(f"=== {label} ===", flush=True)
        print(f"{'R':>2}{'m':>3}{'baseline 7^(R*m)':>18}"
              f"{'indep':>9}{'add':>9}{'input':>9}", flush=True)
        # minimal CICO m=1 (c=t-1) across R gives the cleanest growth-rate signal
        # and smallest D_I; add a couple of m=2 rows for the capacity dependence.
        rows = [(R, 1) for R in (1, 2, 3, 4, 5)] + [(1, 2), (2, 2)]
        for R, m in rows:
            c = K.n - m
            base = 7 ** (R * m)
            di = {mode: measure(K, R, c, mode, p, tmp)
                  for mode in ("indep", "add", "input")}
            print(f"{R:>2}{m:>3}{base:>18}"
                  f"{str(di['indep']):>9}{str(di['add']):>9}{str(di['input']):>9}",
                  flush=True)
        print(flush=True)

    print("Reading the gate:")
    print(" * indep should reproduce D_I = 7^(R*m) (baseline law).")
    print(" * add  > baseline?  -> low-degree cross term accelerates (unlikely: x^7 dominates).")
    print(" * input> baseline?  -> input-coupling (round degree 14) accelerates D_I.")
    print("   If input's D_I ~ 14^(R*m) it is a real per-round speedup CANDIDATE;")
    print("   Step 3 then checks FreeLunch/CheapLunch don't collapse it.")


if __name__ == "__main__":
    main()
