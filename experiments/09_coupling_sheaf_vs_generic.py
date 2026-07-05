"""
experiments/09_coupling_sheaf_vs_generic.py — Camino 1, decisive CONTROL.

Is the verified +1-bit/round acceleration a property of the SHEAF incidence, or
generic to ANY triangular input-coupling of an x^7 S-box? The density-independence
result (experiment 08: even 1 term gives the full 2^(R-1) factor) suggests generic.
This control settles it: compare, at identical scales/seeds, four triangular
input-couplings that differ ONLY in incidence (which earlier pair couples into v):

  sheaf : pairs from the complex's 2-simplices (the current construction)
  dense : ALL pairs a<b<v (complete triangular; ignores the complex)
  chain : v -> (v-2, v-1)  (local, non-sheaf)
  star  : v -> (0, 1)      (fixed, non-sheaf)

(The weights are ALREADY arbitrary PRG in every case, so this also covers the
"generic weights" question; a 'sheaf' run with a different seed is included to show
D_I is generic in the weight values.)

The octahedron is the discriminator: it is NOT a complete complex, so sheaf != dense
there (on the tetrahedron K4 every triple is a triangle, so they coincide).

Verdict: same D_I across patterns -> the effect is GENERIC (sheaf was inspiration,
not mechanism). Less for non-sheaf -> something sheaf-specific.

msolve -t 8. Fixed seeds. Run:  python experiments/09_coupling_sheaf_vs_generic.py
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


def _run(ms, groebner, timeout):
    args = ["wsl", "msolve", "-t", THREADS]
    if groebner:
        args += ["-g", "2", "-v", "2"]
    args += ["-f", _mnt(ms)]
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout).stdout
    except subprocess.TimeoutExpired:
        return None


def ideal_degree(ms, timeout=300):
    out = _run(ms, False, timeout)
    if out is None:
        return "timeout"
    m = re.match(r"\[0, \[\d+,\s*\d+,\s*(\d+),", " ".join(out.split()))
    return int(m.group(1)) if m else "?"


def solving_degree(ms, timeout=300):
    out = _run(ms, True, timeout)
    if out is None:
        return "timeout"
    degs = [int(m.group(1)) for line in out.splitlines()
            if (m := re.match(r"\s*(\d+)\s+\d+\s+\d+\s+\d+ x \d+", line))]
    return max(degs) if degs else "?"


def build(K, R, m, terms, seed, p, tmp, tag):
    prm = C.CoupledParams(K, p, R, "input", seed=seed, terms=terms)
    # sanity: triangular coupling must be a bijection
    x = [(i * 7 + 1) % p for i in range(K.n)]
    assert C.permute_inverse(prm, C.permute(prm, x)) == x, f"{tag} not bijective"
    v, po, _ = C.build_coupled_cico(prm, c=K.n - m)
    ms = os.path.join(tmp, f"{tag}.ms")
    write_msolve(ms, v, po, p)
    return ms, len(prm.terms)


def main():
    p = PROXY_PRIME_30
    tmp = tempfile.mkdtemp(prefix="sheaf_ctrl_")
    print(f"prime {p}; threads {THREADS}\n", flush=True)
    K = Complex2D.octahedron()   # NOT complete -> sheaf != dense
    print("=== t=6 octahedron: sheaf vs generic incidences (input coupling, m=1) ===",
          flush=True)
    print(" baseline indep D_I: 7^2=49, 7^3=343 ; +1-bit law: R=2->98, R=3->1372\n",
          flush=True)
    patterns = [
        ("sheaf", C.pattern_terms(K, "sheaf"), b"coupling/v1"),
        ("sheaf-seed2", C.pattern_terms(K, "sheaf"), b"coupling/other-seed"),
        ("dense", C.pattern_terms(K, "dense"), b"coupling/v1"),
        ("chain", C.pattern_terms(K, "chain"), b"coupling/v1"),
        ("star", C.pattern_terms(K, "star"), b"coupling/v1"),
    ]
    print(f"{'pattern':>12}{'#terms':>8}{'D_I(R=2)':>10}{'D_I(R=3)':>10}"
          f"{'F4 deg(R=2)':>12}", flush=True)
    for name, terms, seed in patterns:
        ms2, nt = build(K, 2, 1, terms, seed, p, tmp, name + "_R2")
        ms3, _ = build(K, 3, 1, terms, seed, p, tmp, name + "_R3")
        d2 = ideal_degree(ms2)
        d3 = ideal_degree(ms3)
        f4 = solving_degree(ms2)
        print(f"{name:>12}{nt:>8}{str(d2):>10}{str(d3):>10}{str(f4):>12}", flush=True)

    print("\n=== large point (R=2,m=2): sheaf vs chain (minimal, msolve -t 8) ===",
          flush=True)
    for name in ("sheaf", "chain"):
        terms = C.pattern_terms(K, name)[:1]   # single term
        ms, nt = build(K, 2, 2, terms, b"coupling/v1", p, tmp, f"big_{name}")
        print(f"  {name} (1 term): D_I(R=2,m=2) = {ideal_degree(ms, 600)} "
              f"(law B predicts 9604)", flush=True)


if __name__ == "__main__":
    main()
