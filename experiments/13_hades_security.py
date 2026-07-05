"""
experiments/13_hades_security.py — re-measure the algebraic security of the HADES
(full-partial-full) variant of Alaniz-AO. Partial rounds change the structure, so
D_I must be RE-MEASURED, not assumed.

Measures, on proxies (m=1 for small resolvable D_I), the CICO ideal degree D_I and
F4 solving degree as a function of (R_full, R_part). A full round multiplies D_I by
~14 (7 from the S-box, 2 from the coupling, per the verified full-round law); this
derives how much a PARTIAL round (one S-boxed coupled lane) contributes.

msolve -t 16. Fixed seeds, proxy 1073742091. Timeouts = gaps. Run:
    python experiments/13_hades_security.py
"""
import os
import re
import subprocess
import sys
import tempfile
from math import log2

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from crypto.alaniz_hades import HadesAO, build_hades_cico
from crypto.spn_cico import write_msolve
from crypto.spn_field import PROXY_PRIME_30


def _mnt(path):
    d, r = path.replace("\\", "/").split(":", 1)
    return f"/mnt/{d.lower()}{r}"


def _run(ms, groebner, timeout=400):
    args = ["wsl", "msolve", "-t", "16"]
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
    p = PROXY_PRIME_30
    tmp = tempfile.mkdtemp(prefix="hades_")
    t, m = 4, 1
    c_fixed = t - m
    print(f"=== HADES algebraic security, t={t}, m={m} (proxy {p}) ===")
    print("full-round law (m=1): D_I = 7^R * 2^(R-1); each full round x14.\n")
    print(f"{'R_f':>4}{'R_p':>4}{'sboxes':>8}{'D_I':>9}{'sd':>4}"
          f"{'D_I/prev(R_p)':>15}", flush=True)
    prev = None
    for (rf, rp) in [(2, 0), (2, 1), (2, 2), (2, 3), (4, 0)]:
        h = HadesAO(t, rf, rp, p=p)
        v, po, _ = build_hades_cico(h, c_fixed)
        ms = os.path.join(tmp, f"h_rf{rf}_rp{rp}.ms")
        write_msolve(ms, v, po, p)
        di = ideal_degree(ms)
        sd = solving_degree(ms)
        ratio = ""
        if rf == 2 and isinstance(di, int) and isinstance(prev, int):
            ratio = f"x{di/prev:.2f}/partial"
        if rf == 2:
            prev = di if isinstance(di, int) else prev
        print(f"{rf:>4}{rp:>4}{h.sbox_count():>8}{str(di):>9}{str(sd):>4}{ratio:>15}",
              flush=True)

    print("\nReading: the per-PARTIAL-round D_I multiplier (vs x14 for a full round)")
    print("tells how much algebraic security a cheap partial round buys. If a")
    print("partial round multiplies D_I by ~7 (one S-box) it is ~half a full round's")
    print("log-degree at 1/t the S-box cost -> net R1CS win.  D_I stays the FreeLunch")
    print("cost driver (solving degree grows, not collapses).")


if __name__ == "__main__":
    main()
