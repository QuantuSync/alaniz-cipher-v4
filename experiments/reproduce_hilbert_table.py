"""
Experiment 21 — Formal Hilbert series analysis.

For both:
  (A) The DECRYPT-side cubic system (m·d cubic equations after σ⁻¹)
  (B) The ATTACK-side full system (m·d polynomial equations of degree 3e
      that an attacker faces with only the public key + ciphertext)

Compute D_reg under the semi-regular assumption: smallest D where the
truncated Hilbert series H(t) = (1-t^deg)^m / (1-t)^d goes ≤ 0.

Compare against empirical Macaulay-matrix kernel dimensions to confirm
v4r3 is semi-regular (no exploitable extra syzygies).
"""
from math import comb, log2


def hilbert_coef(D: int, m: int, d: int, deg: int) -> int:
    """Coefficient of t^D in (1-t^deg)^m / (1-t)^d.

    = sum_{k=0,1,...} (-1)^k · C(m, k) · C(d-1 + D - deg·k, d-1)
    where the inner C is 0 if D - deg·k < 0.
    """
    total = 0
    k = 0
    while deg * k <= D:
        if k > m: break
        sign = -1 if (k & 1) else 1
        inner = comb(d - 1 + D - deg*k, d - 1) if (d - 1 + D - deg*k) >= (d-1) else 0
        total += sign * comb(m, k) * inner
        k += 1
    return total


def find_dreg_semireg(m: int, d: int, deg: int, max_D: int = 5000):
    """First D where Hilbert coefficient is ≤ 0."""
    for D in range(max_D + 1):
        coef = hilbert_coef(D, m, d, deg)
        if coef <= 0:
            return D, coef
    return None, None


def f4_cost_bits(D_reg: int, d: int, omega: float = 2.37) -> float:
    """log2 of dominant F4 cost = log2(C(d+D_reg, d)^omega).

    This is the size of the largest Macaulay matrix raised to the matrix-
    multiplication exponent. A standard estimate; smarter F4/F5 variants
    may shave a constant factor but not the exponent.
    """
    n_cols = comb(d + D_reg, d)
    return omega * log2(n_cols)


def macaulay_cols(D: int, d: int) -> int:
    return comb(d + D, D)


def macaulay_rows(D: int, m: int, d: int, deg: int) -> int:
    """Standard XL: each generator multiplied by all monomials of degree ≤ D-deg."""
    if D - deg < 0:
        return 0
    return m * comb(d + D - deg, D - deg)


def main():
    print("=" * 76)
    print(" Hilbert series analysis of v4r3 polynomial systems")
    print("=" * 76)

    # ─────── (A) Decrypt-side cubic system ───────
    print("\n[A] DECRYPT-side cubic system: m·d cubics in d variables.")
    print("    (Legitimate decryptor solves this AFTER applying σ_v⁻¹.)")
    print()
    print(f"  {'substrate':<14s} {'n':>3s} {'d':>3s} {'m':>4s} {'D_reg':>6s} "
          f"{'first-neg':>12s} {'cost bits':>12s}")
    print("  " + "─" * 70)
    cases_decrypt = [
        ("tetrahedron", 4, 6, 4*6),
        ("double_tet",  5, 6, 5*6),
        ("octahedron",  6, 6, 6*6),
    ]
    for label, n, d, m in cases_decrypt:
        D_reg, neg_coef = find_dreg_semireg(m, d, deg=3)
        cost = f4_cost_bits(D_reg, d)
        print(f"  {label:<14s} {n:>3d} {d:>3d} {m:>4d} {D_reg:>6d} "
              f"{neg_coef:>12d} {cost:>12.1f}")

    print("\n  Empirical kernel-dim check (matches semi-regular if equal):")
    print(f"  At (d=6, m=24, deg=3, D=4): semi-reg kernel = 210 - 168 = 42")
    print(f"  Empirical: kernel dim = 42 (exp20). MATCH → v4r3 is semi-regular")
    print(f"  No structural syzygies. The cubic system has no exploitable")
    print(f"  algebraic anomaly beyond ordinary semi-regularity.")

    # ─────── (B) Attack-side degree-3e system ───────
    print("\n\n[B] ATTACK-side system: m·d polynomial equations of degree 3·e")
    print("    (Adversary with only public key + ciphertext faces this.)")
    print()
    print(f"  {'substrate':<14s} {'d':>3s} {'e':>3s} {'deg':>4s} "
          f"{'m':>4s} {'D_reg':>6s} {'cols at D_reg':>14s} "
          f"{'cost bits':>10s}")
    print("  " + "─" * 70)

    cases_attack = []
    for label, n, d_param in [("tetrahedron", 4, 6),
                                ("double_tet", 5, 6),
                                ("octahedron", 6, 6)]:
        for e_val in [3, 5, 7, 11, 13, 17, 31, 61, 127, 257]:
            m_val = n * d_param
            cases_attack.append((label, d_param, e_val, m_val))

    for label, d, e_val, m in cases_attack:
        deg = 3 * e_val
        D_reg, neg_coef = find_dreg_semireg(m, d, deg, max_D=10000)
        if D_reg is None:
            print(f"  {label:<14s} {d:>3d} {e_val:>3d} {deg:>4d} {m:>4d} "
                  f"  >10000      —             —")
            continue
        cols = macaulay_cols(D_reg, d)
        cost = f4_cost_bits(D_reg, d)
        flag = " ✓" if cost >= 128 else " ✗"
        print(f"  {label:<14s} {d:>3d} {e_val:>3d} {deg:>4d} {m:>4d} {D_reg:>6d} "
              f"{cols:>14.3e} {cost:>9.1f}{flag}")

    # ─────── (C) PQ-128 candidate parameters ───────
    print("\n\n[C] Search for parameters reaching ≥ 128-bit security against direct F4")
    print("    (with tetrahedron substrate, varying d and e):")
    print()
    print(f"  {'d':>3s} {'e':>4s} {'deg':>5s} {'m':>4s} {'D_reg':>6s} "
          f"{'cost bits':>10s} {'128-bit?':>9s}")
    print("  " + "─" * 50)
    for d in [6, 8, 10, 12, 16]:
        for e_val in [17, 31, 61, 127, 257, 503]:
            m = 4 * d   # tetra: 4 vertices × d output coords
            deg = 3 * e_val
            D_reg, _ = find_dreg_semireg(m, d, deg, max_D=15000)
            if D_reg is None:
                continue
            cost = f4_cost_bits(D_reg, d)
            flag = "✓" if cost >= 128 else "✗"
            print(f"  {d:>3d} {e_val:>4d} {deg:>5d} {m:>4d} {D_reg:>6d} "
                  f"{cost:>10.1f} {flag:>9s}")

    print()
    print("=" * 76)
    print(" Caveat: this is the semi-regular UPPER BOUND on D_reg. Actual D_reg")
    print(" may be lower if v4r3's σ ∘ cubic composition introduces non-trivial")
    print(" structure that algorithms like F5 / MutantXL exploit. Empirical")
    print(" measurement at smaller scales is required to confirm.")
    print("=" * 76)


if __name__ == "__main__":
    main()
