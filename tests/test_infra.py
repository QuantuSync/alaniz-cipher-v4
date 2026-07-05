"""
tests/test_infra.py — infrastructure invariants for the reference path.

Guards two Phase-0 properties:
  1. The reference (pq128) path imports WITHOUT galois (galois is optional).
  2. find_irreducible produces genuinely irreducible polynomials via Rabin,
     with no galois dependency.
"""
import os
import sys
import subprocess

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(REPO_ROOT, "src")
sys.path.insert(0, SRC)


def test_reference_path_is_galois_free():
    """Importing the reference path must NOT pull galois into sys.modules.

    Run in a fresh subprocess so the result is independent of what the
    current pytest process already imported.
    """
    code = (
        "import sys; sys.path.insert(0, r'%s');"
        "import core, crypto;"
        "from core.complex2d import Complex2D;"
        "from crypto.protocol_v4r3_pq128 import setup_pq128, keygen_pq128, encrypt_pq128;"
        "from crypto.decrypt_v4r3_pq128 import decrypt_pq128;"
        "assert 'galois' not in sys.modules, 'reference path imported galois';"
        "print('OK')" % SRC
    )
    out = subprocess.run([sys.executable, "-c", code],
                         capture_output=True, text=True)
    assert out.returncode == 0, f"stdout={out.stdout!r} stderr={out.stderr!r}"
    assert "OK" in out.stdout


def test_find_irreducible_is_irreducible():
    from crypto.field_pd import find_irreducible
    from crypto.irreducible import is_irreducible_rabin
    for p, d in [(7, 2), (7, 3), (257, 4), (257, 6)]:
        asc = find_irreducible(p, d)
        assert len(asc) == d + 1
        assert asc[-1] == 1  # monic
        assert is_irreducible_rabin(asc, p), f"reducible for p={p}, d={d}"
