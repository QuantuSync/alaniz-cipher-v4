# COUPLING_SPEC — Estructura de haz como NO-LINEALIDAD (Camino 1)

**Estado:** Paso 1 (acoplamiento triangular biyectivo) completado y verificado.
Paso 2 (mini-gate de grado) en curso. Ver [DECISION.md](DECISION.md) para el
resultado previo (haz como capa lineal = sin ventaja algebraica) que motiva
mover la geometría a la no-linealidad.

## 0. Idea y pregunta de investigación

La seguridad algebraica vive en la no-linealidad, no en la capa lineal (ley
verificada `D_I = 7^(R·m)`, [CRYPTANALYSIS.md](CRYPTANALYSIS.md#fase-2)). Este
camino mueve la estructura de haz al **acoplamiento entre S-boxes**, guiado por
los **2-símplices (triángulos)** del complejo (coborde). Pregunta: ¿hace el
acoplamiento crecer el grado del ideal D_I **más rápido por ronda** que S-boxes
independientes?

## 1. Restricción dura: biyectividad (lección A5a) y su consecuencia

Una capa no-lineal no inyectiva regala atajos (A5a). **La forma literal
`y_v = x_v⁷ + Σ_{u<v} w·(x_u·x_v)` NO es biyectiva:** fijados los vértices
anteriores queda `y_v = x_v⁷ + c·x_v`, y `x⁷ + c·x` no es polinomio de
permutación de F_p salvo para c especiales.

**Consecuencia de diseño (obligatoria):** el acoplamiento debe ser **triangular**
— `y_v` depende solo de S-boxes de **vértices anteriores** (u < v en un orden
fijo), nunca del propio `x_v` dentro del término de acoplamiento. Entonces cada
vértice se invierte con una única raíz 7-ésima y la capa es biyección **por
construcción**. Verificado **exhaustivamente** (31⁴ = 923521 entradas, t=4, las
tres modalidades) en `tests/test_coupling.py`.

## 2. Orden de vértices y acoplamiento de haz

Orden natural `0 < 1 < … < t−1`. Para cada **triángulo** `{u,u',v} ∈ T` con
`v = máx`, el vértice v recibe el término cruzado cuadrático `x_u·x_{u'}` (ambos
anteriores), con peso público `c_{uu'v}` del PRG de haz (domain-separated, no
nulo). Ejemplo (tetraedro): solo los vértices 2 (triángulo {0,1,2}) y 3
(triángulos {0,1,3},{0,2,3},{1,2,3}) reciben acoplamiento; 0 y 1 no (no son
máximo de ningún triángulo). La difusión se restaura con la capa lineal.

## 3. Tres modalidades (medidas lado a lado en el gate)

Todas triangulares ⇒ biyectivas. Comparten la **misma capa lineal MDS Cauchy
neutra** (para aislar el efecto del acoplamiento; la geometría vive ahora en la
no-linealidad, no en la lineal). Ronda: `x → coupling(x) → M_Cauchy → +rc`.

| modo | fórmula | grado de ronda | rol |
|---|---|---|---|
| `indep` | `y_v = x_v⁷` | 7 | **baseline A** (ley `D_I=7^(R·m)`) |
| `add` | `y_v = x_v⁷ + Σ c·x_u·x_{u'}` | 7 | B-add (cruce bajo grado; predicción: no acelera) |
| `input` | `y_v = (x_v + Σ c·x_u·x_{u'})⁷` | 14 | B-in (candidata real; la que caza FreeLunch) |

`add` suma el cruce **tras** la potencia (subdominante a x_v⁷). `input` lo pliega
en la **entrada** de la S-box (su potencia 7 lo eleva a grado 14 de ronda — la
variante que puede acelerar D_I y la que FreeLunch/CheapLunch atacan).

Implementación: `src/crypto/spn_coupling.py` (permutación + inversa + CICO estilo
FreeLunch, con variable auxiliar `a{r}_v` por S-box en modo `input` para mantener
el sistema en grado 7 y sin paréntesis, que msolve malinterpreta).

## 4. STATUS de esta fase

| Afirmación | Estado |
|---|---|
| Acoplamiento triangular ⇒ biyección (3 modos) | **verificado** (exhaustivo 31⁴ + roundtrip Goldilocks) |
| `indep` reproduce la ley baseline `D_I=7^(R·m)` | **verificado** (gate, Paso 2) |
| `add` NO acelera (= baseline) | **verificado** (§5) |
| `input` acelera D_I: `7^(Rm)·m·2^(R-1)` (+1 bit/ronda) | **verificado** (§5-6) |
| el grado extra de `input` es seguridad REAL (no trampa) | **verificado** (§6) |
| acoplamiento mínimo → victoria neta de coste | **conjetura respaldada** (§6) |

Reproducir: `python experiments/06_coupling_grade_gate.py` y `pytest -q`.

## 5. Resultado del mini-gate 2 (VERIFICADO) — el acoplamiento a la entrada acelera

`experiments/06_coupling_grade_gate.py`, msolve real, proxy p=1073742091,
CICO mínima m=1 (c=t−1). **Idéntico para t=4 (control) y t=6 (principal):**

| R | baseline 7^R | `indep` | `add` | `input` |
|---|---|---|---|---|
| 1 | 7 | 7 | 7 | 7 |
| 2 | 49 | 49 | 49 | **98** |
| 3 | 343 | 343 | 343 | **1372** |

- **`indep` = 7^R**: reproduce la ley baseline.
- **`add` = 7^R**: el cruce cuadrático **aditivo** (tras la potencia) **no aporta
  nada** — el término x_v⁷ domina el grado, como se predijo.
- **`input` = 2^(R−1)·7^R = 14^R/2**: el acoplamiento en la **entrada** de la
  S-box **sí acelera** el grado del ideal, de base 7 a base ~14 por ronda
  (crecimiento log ~1.36× más rápido: log₂14/log₂7). Independiente de t.

**Veredicto del gate 2: POSITIVO** (D_I(input) > D_I(baseline)).

## 6. Pasos 3-4 (VERIFICADO) — la aceleración es REAL; beneficio neto marginal

Ley completa (msolve, todos los puntos t=4, incl. (R=1,m=3)=1029 que desambiguó):

> `D_I(input) = 7^(R·m) · m · 2^(R-1)`  vs baseline `7^(R·m)`  →  **+1 bit/ronda**.

**Real, NO trampa de grado nominal** (contra el riesgo Griffin/Arion):
- solving degree F4 de `input` **más alto** (9-10 vs 7-9), no más bajo;
- el modelo **solo-en-x** (sin variables auxiliares) reproduce D_I exacto ⇒ no es
  artefacto del modelado; D_I es intrínseco e invariante ⇒ FreeLunch/CheapLunch
  no lo reducen remodelando.

**R\* y coste** (`experiments/07_coupling_cost_verdict.py`, ω=2): R\* baja 22%
(m=1) a 17% (m=2). Pero con el acoplamiento **triangular denso** el recargo por
ronda ~cancela el ahorro en R1CS (net ~empate a m=2). El **+1 bit/ronda es
independiente de la densidad** ⇒ un **acoplamiento mínimo (1 término/ronda)**
conserva la ganancia a coste mínimo → net ~0.87-0.89× (victoria). Detalle y tablas
en [CRYPTANALYSIS.md](CRYPTANALYSIS.md) (C1) y [DECISION.md](DECISION.md).

**Estado:** ley + no-trampa **verificadas** (R≤3); R\*/coste **extrapolados**;
acoplamiento mínimo **conjetura respaldada**.
