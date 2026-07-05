# Project status

Last updated: 2026-07-05.

## Fase 0 — Hallazgos de honestidad (bloquean afirmaciones previas)

Registrados al reformular el track (ver [DECISION.md](DECISION.md) y
[HARDNESS.md](HARDNESS.md)). Estos hallazgos **invalidan afirmaciones hechas más
abajo y en `DESIGN.md`/`SECURITY.md`/`findings/CSI_AND_INDCPA.md`**, que están
pendientes de reescritura:

| # | Hallazgo | Impacto | Estado |
|---|----------|---------|--------|
| **H1** | Cifrar requiere el secreto (`encrypt_pq128` usa A,B,C y β). **El esquema es SIMÉTRICO, no de clave pública.** | Toda mención de "clave pública" / "pk = (K,p,d,e,L,A,B,C,H₀)" es **FALSA** respecto al código. | ❌ docs por reescribir |
| **H2** | El "sistema público de grado 3e con coeficientes conocidos" no es público: sus coeficientes dependen de β (secreto). | La cota Bardet-Faugère se aplicaba a un sistema que el atacante no posee. Problema reformulado como NL-SMIP. | ❌ cifras suspendidas |
| **H3** | Muestreo `int(rng.integers(0,2**62)) % p^d` colapsa β y L a un subconjunto casi-escalar (~2⁶² de ~2³⁶⁶ en d=6). | Debilidad de escala tipo Langa; σ casi-lineal. Ataque a montar en Fase 1 (A1/A5). | ❌ por corregir + atacar |

**Cifras de seguridad suspendidas.** Hasta que NL-SMIP se cuantifique sobre el
sistema que ve el atacante (β incógnita) y se revalide, los números 74 / 126 /
133 / 147 bits quedan **sin respaldo** y no deben citarse como hechos.

### Progreso de saneamiento (Fase 0)

| Paso | Estado | Evidencia |
|------|--------|-----------|
| Paso 1 — Infra baseline | ✓ | `pytest -q` verde (11 tests), ruta de referencia **galois-free** (`field_pd.find_irreducible` → Rabin; `core`/`crypto` importan el stack galois de forma perezosa). CI en `.github/workflows/ci.yml`; reproducción con `make reproduce-all` (o `python experiments/reproduce_all.py`). Guard en `tests/test_infra.py`. |
| Paso 2 — Corregir H3 (muestreo β/L) | ✓ | Muestreo por rechazo uniforme sobre `[0,p^d)` en `crypto/sampling.py` (β, L, matrices GL, PRG con domain separation). Helpers F_p consolidados en `crypto/linalg_fp.py`. Medición antes/después en `experiments/01_h3_entropy_collapse.py` (viejo ~62 bits → nuevo ~366 bits). Tests en `tests/test_sampling.py`. Registrado en [CRYPTANALYSIS.md](CRYPTANALYSIS.md#h3). `pytest -q` verde (18 tests). |
| Paso 3 — Spike A5/A6 (GO/NO-GO track A) | ✓ (parcial) | A5a **verificado**: β cae con 1 inversión de campo/vértice dado (A,B,C) (`attacks/A5_key_recovery.py`). A6 **parcial**: gap D_reg−Hilbert = +5 (d=2), +3 (d=3), d≥4 pendiente Sage (`attacks/A6_dreg_public_system.py`). Veredicto: **GO condicional a Track A simétrico**; sin asimetría KEM viable; cifras siguen suspendidas. Detalle en [CRYPTANALYSIS.md](CRYPTANALYSIS.md) y [DECISION.md](DECISION.md). |

## Fase 1 (reencuadre AO) — Infra de álgebra

Reencuadre a primitiva orientada a aritmetización (AO), evaluada por CICO. Ataques
diana: FreeLunch (2024/347), CheapLunch (2025/2040), Resultant (2025/259,
2026/1281).

| Backend | Estado | Uso |
|---------|--------|-----|
| **python-flint 0.9.0** | ✓ verificado | `nmod_mat` RREF/rank/nullspace sobre F_p (Macaulay → solving-degree/D_reg) y resultantes univariadas. Cross-check: rango flint == numpy en A6 d=2 (275), **×21.6** más rápido. `make algebra-check`. |
| Sage / msolve / Magma / Singular | ❌ **BLOQUEADO** | Motor Gröbner completo (F4/F5/Buchberger, orden monomial) no instalable en este Windows (sin WSL — requiere admin+reboot; sin toolchain para msolve; Magma comercial). Análisis que exijan GB con orden monomial quedan **pendientes**. |

**Implicación:** el análisis AO (solving degree, first-fall, FreeLunch) se mide vía
Macaulay + rango, acelerado por flint. Réplicas exactas de Gröbner con orden
monomial elegido: pendientes de un motor GB.

### Progreso Fase 1 (AO)

| Paso | Estado | Evidencia |
|------|--------|-----------|
| Paso 1 — Infra álgebra | ✓ | python-flint verificado; Sage/msolve bloqueado (ver arriba). |
| Paso 2 — Reencuadre AO + CICO | ✓ | `docs/AO_SPEC.md` (permutación, mezcla=capa lineal, σ=S-box; **matiz: σ NO es permutación**, solo `π_e` lo es). `src/crypto/ao_permutation.py`, `src/crypto/ao_cico.py`. Consistencia `c=R(H₀α)−r` en `tests/test_ao.py` (3 tests verdes). |
| Paso 3 — Suite de ataques | ✓ | **A6-CICO (verificado, BREAK):** solving degree CICO = **4–5**, ⊥ de e, vs bound 3e=17–33 (`attacks/A6_cico_solving_degree.py`). **A2 (verificado):** nonce fresco load-bearing (`attacks/A2_nonce_discipline.py`). FreeLunch/CheapLunch/Resultant N/A en 1 ronda; A5b N/A (params públicos). Tabla en [CRYPTANALYSIS.md](CRYPTANALYSIS.md). |
| Paso 4 — Coste AO + veredicto | ✓ | Coste ~42× Poseidon2 (1 ronda) → ~250–420× (multi-ronda) en `experiments/02_ao_cost_estimate.py`. **Veredicto: NO-GO como primitiva AO → Track B (paper de criptoanálisis)**; ver [DECISION.md](DECISION.md). Cifras 74/126/133/147 **enterradas** en modelo AO. |

**Estado de afirmaciones AO:** que la seguridad AO descansa en el solving degree
CICO = **verificado (roto: cúbico)**. Que un rediseño multi-ronda podría ser AO
viable = **abierto/conjetura** (obstáculo de coste). Ninguna cifra de seguridad
vigente.

## Fase 2 (SPN multi-ronda) — permutación AO nueva

Sesión 2 (2026-07-05). Motor Gröbner **desbloqueado**: msolve 0.6.5 en
WSL/Ubuntu-24.04, verificado sobre F_p con grevlex (ver `docs/WSL_SETUP.md`).
La fila "Sage/msolve BLOQUEADO" de Fase 1 queda **superada**.

| Paso | Estado | Evidencia |
|------|--------|-----------|
| 2a — Cuerpo + S-box | ✓ | **Goldilocks p=2⁶⁴−2³²+1, d=7 mínimo biyectivo** (verificado; coincide con Plonky2). Proxies msolve 31/65551/1073742091 con idéntica estructura de exponente. `src/crypto/spn_field.py`, tests en `tests/test_spn.py`. Spec: `docs/SPN_SPEC.md` §1-3. |
| 2b — Capa de mezcla + mini-gate MDS | ✓ (**GATE: esperando confirmación**) | Matriz tipo-haz pública (patrón Laplaciano de haz) en `src/crypto/spn_mix.py`. Rama exacta (5 semillas, 2 cuerpos): **tetra t=4: 5/5 = MDS**; doble-tetra t=5: 5/6; octaedro t=6: 6/7. M² densa en los 3. `experiments/03_mix_branch_number.py`; resultados pinneados en tests. `pytest -q` verde (32). |
| 3 — SPN completa + suite de ataques (FreeLunch/CheapLunch/resultantes, msolve) | ✓ | Permutación x⁷ biyectiva (`src/crypto/spn_permutation.py`); CICO estilo FreeLunch (`src/crypto/spn_cico.py`). **Ley verificada en msolve real** `D_I=7^(R·m)` (R∈{1,2,3}, t∈{4,6}); **D_I independiente de t/nº de rama** (S2-tind: t=4 MDS y t=6 haz idénticos, grado F4 máx 14). `experiments/04_spn_cico_attacks.py`. Detalle en [CRYPTANALYSIS.md](CRYPTANALYSIS.md#fase-2). |
| 4 — Coste vs Poseidon2 + veredicto | ✓ | R\* extrapolado (ω=2): κ=2⇒**12 rondas**, t-independiente. R1CS octaedro ~1.23× Poseidon2; capa densa cara en nativo; near-MDS impide rondas parciales. `experiments/05_spn_cost.py`. **Veredicto: Track B (paper comparativo "haz vs MDS")**; ver [DECISION.md](DECISION.md#veredicto-fase-2). |

## Camino 1 (haz como NO-LINEALIDAD) — acoplamiento de S-boxes

Sesión 2 (2026-07-05). Estructura de haz movida de la capa lineal al
**acoplamiento entre S-boxes** (2-símplices), sobre capa MDS Cauchy neutra.

| Paso | Estado | Evidencia |
|------|--------|-----------|
| 1 — Acoplamiento triangular biyectivo | ✓ | `src/crypto/spn_coupling.py`, 3 modos (indep/add/input). Biyección **exhaustiva** (31⁴) + roundtrip. `tests/test_coupling.py`. `docs/COUPLING_SPEC.md`. |
| 2 — Mini-gate de grado | ✓ | msolve real: `add`=baseline (no acelera); **`input` acelera** (`D_I=7^(Rm)·m·2^(R-1)`, +1 bit/ronda). `experiments/06`. |
| 3 — ¿real o trampa FreeLunch? | ✓ | **REAL**: solving degree F4 más alto (9-10 vs 7-9); modelo solo-en-x reproduce D_I. No es trampa Griffin/Arion. [CRYPTANALYSIS.md](CRYPTANALYSIS.md) (C1). |
| 4 — Coste vs Poseidon2 + veredicto | ✓ | R\* baja 17-22%; acoplamiento denso ~empata en R1CS, **acoplamiento mínimo → net 0.87-0.89×** (victoria). `experiments/07`. |
| A — Acoplamiento mínimo conserva la ley | ✓ | **Densidad-independiente** (medido, t=4 y t=6): D_I idéntico k=1…full. No-trampa (solving degree mín=10≥full=9>base=7). `experiments/08`. |
| C — Escalar: punto grande resuelto | ✓ | **(R=2,m=2)=9604 resuelto** (msolve -t 16, 35s) ⇒ ley `7^(Rm)·m·2^(R-1)` **verificada** (descarta base-14 y nulo). Puntos mayores: F4/FGLM-limitados (timeouts reportados). |
| D — Coste neto + veredicto | ✓ (**GATE: esperando OK**) | Mínimo: net 0.87-0.89× baseline, tetra 0.73× Poseidon2. **Veredicto: CANDIDATO REAL**; ver [DECISION.md](DECISION.md#veredicto-camino-1). |

---


## Verification status of each claim

Each claim made in the documentation is one of:

- ✓ **Verified**: backed by empirical data in this repo, reproducible.
- ⚠ **Partially verified**: components verified, full integration pending.
- 🟡 **Theoretical**: argued mathematically but not empirically tested.
- ❌ **Open**: stated as expected but not validated.

### Functionality

| Claim | Status | Evidence |
|-------|--------|----------|
| Scheme works end-to-end at (d=6, e=17, p=2⁶¹-1, tetra) | ✓ | `experiments/reproduce_e2e_d6.py`, 10 seeds verify=True |
| Scheme works end-to-end at (d=8, e=17) | ⚠ | Components verified; full pipeline timeout |
| Scheme works end-to-end at (d=12, e=17) — recommended params | ⚠ | All components individually verified, F4 RREF requires SageMath (matrix 4368×6188 over F_(2⁶¹-1)). State persisted in `experiments/data/d12_*.pkl` |
| Scheme works at non-tetra substrates (double_tet, octahedron) | ⚠ | Verified for small p (d=2,3), not at PQ-128 |

### Security analysis

| Claim | Status | Evidence |
|-------|--------|----------|
| v3 parameters (d=6, e=17) give ~74 bits classical | ✓ | `experiments/reproduce_hilbert_table.py` |
| Cubic system of decryptor is semi-regular at d=6 | ✓ | `experiments/reproduce_semireg_d6.py`, kernel=42 = 210-168 |
| Cubic system is semi-regular at d=12 | ❌ | Cannot verify in this environment (requires SageMath RREF at D=5) |
| Public system regularity matches Hilbert + gap | ✓ | 13 instances at d=2,3 (`reproduce_dreg_d23.py`, `reproduce_attack_public.py`) |
| Gap regression `gap ≈ -0.5n + 0.67d + 1.33e - 0.83` | ✓ | RMS residual 0.24 on 9 datapoints |
| Gap regression extrapolates correctly to d=12 | ❌ | Open question; recommended to verify at d=4-8 first |
| Specific attacks (Beullens, MinRank) fail | ✓ | Earlier experiments (exp11-14 in development logs) |
| σ_v non-injectivity does NOT enable side-channel attack | 🟡 | N=30 χ² tests show no significant correlation; needs larger N |
| Syzygy-hiding argument (decryptor's syzygies do not lift) | 🟡 | Structural argument formalized in `findings/SYZYGY_PROOF.md`, no rigorous algebraic proof |
| IND-CPA reduction under CSI | 🟡 | Sketched in `findings/CSI_AND_INDCPA.md`, not formalized |
| IND-CCA via Fujisaki-Okamoto | 🟡 | Standard transformation; no specific obstruction identified |

### Quantum security

| Claim | Status | Evidence |
|-------|--------|----------|
| Quantum F4 cost model (ω=2.0 conservative, ω=1.5 aggressive) | ✓ | Computational, `reproduce_quantum_analysis.py` |
| `pq128-q-cons` parameters give 147 bits quantum-conservative | ✓ | Computational under standard model |
| ω=1.5 is plausible upper bound on quantum F4 speedup | 🟡 | Heuristic; literature on quantum F4 is sparse |

### Implementation quality

| Claim | Status | Evidence |
|-------|--------|----------|
| Reference implementation correctly implements spec | ✓ | Verified by 10-seed roundtrip at d=6 |
| Implementation is timing-constant | ❌ | NOT timing-constant. Production deployment requires constant-time σ⁻¹. |
| Implementation is memory-safe | ⚠ | Python implementation; production deployment requires C/Rust with safety review |
| Implementation passes static analysis | ❌ | No static analysis performed |

## What works in this environment vs. what doesn't

**Works**:
- Pure Python implementation runs correctly with `numpy` + `galois`
- Reproducible experiments at d ≤ 6, p ≤ 257 (small primes) or p = 2⁶¹-1 with timing ~100s per decrypt
- Generation of all tables in `findings/EXPERIMENTAL_FINDINGS.md`

**Does NOT work in this environment** (but is straightforward elsewhere):
- F4 RREF of 4368×6188 over F_(2⁶¹-1) — requires SageMath or Magma. Estimated time on a modest workstation: 2–5 minutes.
- Direct F4 attack at d ≥ 4 — Macaulay matrix exceeds available memory.
- Side-channel statistical analysis at N ≥ 500 trials — sandbox time limits.

## Priority for external collaboration

If you want to help validate or extend this work, the highest-impact tasks are:

1. **Run `pending_validations/sage_d12_complete.sage`** (5 minutes of SageMath compute). Confirms verify=True at the recommended parameters.

2. **Empirically measure D_reg at d=4-8** using Magma's Gröbner basis solver. Validates the gap regression extrapolation.

3. **Independent review of `findings/SYZYGY_PROOF.md`** by a multivariate cryptography expert. The argument is structural, not formal.

4. **Implementation of optimized C/Rust version** with constant-time σ⁻¹. Necessary for any deployment context.

5. **Larger-N side-channel study** (1000+ ciphertexts per key, multiple keys). Confirms or refutes the marginal ρ(v_0, v_3) = -0.38 observation.

See [ROADMAP.md](ROADMAP.md) for the full priority list with rationale.

## Project history

See [HISTORY.md](HISTORY.md) for the version evolution v1 → v4r3 and key decisions.
