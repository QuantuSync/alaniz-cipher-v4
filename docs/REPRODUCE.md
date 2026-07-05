# REPRODUCE — un comando por resultado

Requisitos: Python 3 (`pip install -r requirements.txt`). Los que llevan **[msolve]**
necesitan msolve en WSL/Linux (`sudo apt install msolve`); ver
[WSL_SETUP.md](WSL_SETUP.md). Semillas fijas ⇒ salida determinista. Ejecutar desde
la raíz del repo.

## Suite de tests (todo verde)

```bash
pytest -q                     # 55 tests: biyecciones (incl. exhaustivas 31⁴),
                              # consistencia de los sistemas CICO, cotas S-box,
                              # estructura del CICO del esponja, regresiones de ley
```

## Resultado central — acoplamiento a la entrada (+1 bit/ronda)

| resultado | comando | [msolve] |
|---|---|---|
| Gate: `add` no acelera, `input` sí (ley D_I=7^(R·m)·m·2^(R-1)) | `python experiments/06_coupling_grade_gate.py` | sí |
| Density-independencia (1 término = full) | `python experiments/08_coupling_density_sweep.py` | sí |
| Control haz vs genérico (idénticos ⇒ genérico) | `python experiments/09_coupling_sheaf_vs_generic.py` | sí |
| R\* y coste del acoplamiento (ω=2) | `python experiments/07_coupling_cost_verdict.py` | no |

## Suite de ataques sobre la construcción mínima

| ataque | comando | [msolve] |
|---|---|---|
| FreeLunch (D_I-bound, no colapsa) | `python attacks/A_freelunch_minimal.py` | sí |
| CheapLunch + resultantes (D_I-bound; eliminante=D_I) | `python attacks/A_cheaplunch_resultant.py` | sí |
| Wide-trail diferencial/lineal (MDP/MLC, R\*_difflin) | `python experiments/10_wide_trail.py` | no |
| Transferencia proxy→Goldilocks (D_I idéntico 5–31 bits) | `python experiments/11_transfer_proxies.py` | sí |

## Primitiva Alaniz-AO y esponja

| resultado | comando | [msolve] |
|---|---|---|
| Hash de ejemplo (4 elementos de Goldilocks) | `python -c "import sys;sys.path.insert(0,'src');from crypto.alaniz_ao import sponge_hash;print(sponge_hash([1,2,3,4,5]))"` | no |
| CICO real del esponja (m_efectivo=4, seguridad) | `python experiments/12_sponge_cico.py` | sí |
| Rondas parciales: parcial=completa para D_I | `python experiments/13_hades_security.py` | sí |
| Coste HADES vs Poseidon2 (0.74×) | `python experiments/14_hades_cost.py` | no |

## Fase haz-como-capa-lineal (resultado comparativo previo)

| resultado | comando | [msolve] |
|---|---|---|
| Número de rama de la matriz tipo-haz vs MDS | `python experiments/03_mix_branch_number.py` | no |
| Ley D_I=7^(R·m), independiente del nº de rama | `python experiments/04_spn_cico_attacks.py` | sí |
| Coste SPN de haz vs Poseidon2 | `python experiments/05_spn_cost.py` | no |

## Fases 0–1 (saneamiento y 1 ronda AO — registro histórico)

| resultado | comando | [msolve] |
|---|---|---|
| Baseline reproducible del repo | `python experiments/reproduce_all.py` | no |
| H3: colapso de entropía β/L y su corrección | `python experiments/01_h3_entropy_collapse.py` | no |
| A5a: β cae con una inversión de campo | `python attacks/A5_key_recovery.py` | no |
| A6-CICO: 1 ronda rota (solving degree cúbico) | `python attacks/A6_cico_solving_degree.py` | no |
| A2: disciplina de nonce | `python attacks/A2_nonce_discipline.py` | no |

## Notas

- Invocación de msolve desde los scripts: `wsl msolve -f <archivo> [-g 2] [-t 16]`.
- Los puntos grandes (R≥4, D_I≳10⁵) hacen **timeout** y se reportan como huecos, no
  como confirmación (ver [OPEN_PROBLEMS.md](OPEN_PROBLEMS.md) §1).
- Notas de fidelidad del motor (CRLF, primo 65551 que segfaultea, sintaxis) en
  [CRYPTANALYSIS.md](CRYPTANALYSIS.md).
