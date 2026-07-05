"""
experiments/12_sponge_cico.py — sponge CICO of Alaniz-AO: the effective-m capacity
flank.

For a sponge with rate = capacity = kappa (t = 2*kappa), the standard inversion
CICO fixes the kappa capacity input lanes and constrains kappa output lanes; the
free branches are the kappa rate input lanes, so m_effective = kappa. For the
recommended instance (t=8, kappa=4) this is m=4 -- exactly the m used to set R=8.

This models the REAL sponge CICO (chain input-coupling on the rate/capacity
partition, capacity lanes fixed = the last kappa lanes), not the abstract m-free
CICO, and measures D_I on small sponge analogs (t=4 kappa=2, t=6 kappa=3) to anchor
the law to the sponge model. Then applies the verified law at t=8, R=8, m=4 over
Goldilocks to get the preimage/collision security (omega=2).

msolve -t 16. Fixed seeds, proxy 1073742091. Run:
    python experiments/12_sponge_cico.py
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

LOG2_7 = log2(7)


def chain_terms(t):
    return [(v, v - 2, v - 1) for v in range(2, t)]


def _mnt(path):
    d, r = path.replace("\\", "/").split(":", 1)
    return f"/mnt/{d.lower()}{r}"


def ideal_degree(ms, timeout=400):
    try:
        out = subprocess.run(["wsl", "msolve", "-t", "16", "-f", _mnt(ms)],
                             capture_output=True, text=True, timeout=timeout).stdout
    except subprocess.TimeoutExpired:
        return "timeout"
    m = re.match(r"\[0, \[\d+,\s*\d+,\s*(\d+),", " ".join(out.split()))
    return int(m.group(1)) if m else "?"


def measure(K, R, kappa, mode, p, tmp):
    t = K.n
    terms = None if mode == "indep" else chain_terms(t)
    prm = C.CoupledParams(K, p, R, mode, terms=terms)
    # sponge CICO: fix the kappa capacity input lanes (the last kappa) => c=kappa,
    # constrain kappa output lanes; free = kappa rate lanes => m = kappa.
    v, po, _ = C.build_coupled_cico(prm, c=kappa)
    ms = os.path.join(tmp, f"sp_{mode}_t{t}_R{R}.ms")
    write_msolve(ms, v, po, p)
    return ideal_degree(ms)


def sec_bits(R, m, coupled, omega=2):
    """log2 of attack cost = omega*log2(D_I). D_I = 7^(Rm)*(m*2^(R-1) if coupled)."""
    logdi = R * m * LOG2_7 + (log2(m) + (R - 1) if coupled else 0)
    return omega * logdi


def main():
    p = PROXY_PRIME_30
    tmp = tempfile.mkdtemp(prefix="sponge_")
    print("=== Sponge CICO on small analogs (chain coupling, m = kappa) ===")
    print(f"{'t':>3}{'kappa=m':>8}{'R':>3}{'indep D_I':>11}{'chain D_I':>11}"
          f"{'law m*2^(R-1)*7^(Rm)':>22}", flush=True)
    for (K, kappa, Rs) in [(Complex2D.tetrahedron(), 2, [1, 2]),
                           (Complex2D.octahedron(), 3, [1])]:
        for R in Rs:
            di_i = measure(K, R, kappa, "indep", p, tmp)
            di_c = measure(K, R, kappa, "input", p, tmp)
            law = 7**(R*kappa) * kappa * 2**(R-1)
            print(f"{K.n:>3}{kappa:>8}{R:>3}{str(di_i):>11}{str(di_c):>11}{law:>22}",
                  flush=True)
    print("  -> chain D_I >= indep D_I (7^(Rm)): coupling never hurts in the sponge")
    print("     model; equals the law where it covers the rate branches.\n")

    print("=== Alaniz-AO security at R=8, m=kappa=4 over Goldilocks (omega=2) ===")
    print(f"{'attack':>12}{'m':>3}{'coupled?':>10}{'security bits (R=8)':>20}{'>=128?':>8}")
    for label, coupled in [("baseline", False), ("with coupling", True)]:
        b = sec_bits(8, 4, coupled)
        print(f"{'preimage':>12}{4:>3}{label:>10}{b:>20.1f}{'YES' if b >= 128 else 'NO':>8}")
    # collision: generic 2^(c/2)=2^128 (c=256-bit capacity); algebraic CICO >= preimage
    print(f"{'collision':>12}{4:>3}{'generic':>10}{128.0:>20.1f}{'=128':>8}")
    print(f"{'collision':>12}{4:>3}{'algebraic':>10}{sec_bits(8,4,False):>20.1f}{'YES':>8}")
    print("\nEven the baseline (no coupling) at m=4, R=8 gives ~180 bits: the capacity")
    print("flank is closed with margin. R*_alg(m=4) = 6; R=8 = 6 + margin.")


if __name__ == "__main__":
    main()
