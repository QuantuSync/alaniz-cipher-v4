# CRYPTANALYSIS — registro de ataques (romper es una victoria)

Cada entrada: ataque → resultado → coste, con script reproducible y semilla fija.
Nunca se borra evidencia negativa. Clasificación: verificado / parcial / conjetura
/ abierto.

## Tabla resumen

| ID | Ataque | Escala | Resultado | Estado |
|----|--------|--------|-----------|--------|
| H3 | Colapso de entropía en muestreo de β y L | p=2⁶¹-1, d=6 | **ROMPE** el sampler viejo (β casi-escalar, ~62 bits); corregido | verificado |
| A5a | β es lineal dado (A,B,C) + texto claro conocido | d∈{2,3,4} | **β cae** (1 inversión de campo/vértice) | verificado |
| A5b | Recuperación de clave completa (β+A,B,C) | d∈{2,3,4} | superficie estructural reportada; reduce a recuperar (A,B,C) | parcial |
| A6 | D_reg real del sistema de recuperación de mensaje | d∈{2,3} | gaps **+5, +3** (Hilbert es cota inferior); d≥4 pendiente | parcial |
| **A6-CICO** | Solving degree real de CICO (modelo AO, permutación pública) | d∈{2,3,4,6} | **BREAK: solving degree = 4–5 (cúbico), ⊥ de e**; el bound 3e no se paga | verificado |
| A2 | Disciplina de nonce (fresco vs reutilizado) | d∈{2,3} | nonce fresco es la única aleatoriedad; reutilizarlo → CICO roto | verificado |
| A-FreeLunch / A-CheapLunch | GB "gratis" / multi-salida (2024/347, 2025/2040) | 1 ronda | **N/A**: el sistema ya se resuelve a grado cúbico en 1 ronda sin necesitarlos | N/A (1 ronda) |
| A-Resultant | Eliminación por resultantes (2025/259, 2026/1281) | 1 ronda | subsumido: el residual cúbico lo resuelve la linealización | subsumido |
| A5b | Recuperar (A,B,C) con Gröbner | — | **N/A en modelo AO** (parámetros públicos); relevante solo al modelo simétrico abandonado | N/A |

---

## H3 — Colapso de entropía en el muestreo de β y L

**Estado:** verificado (ROMPE el esquema con el sampler original).
**Script:** `experiments/01_h3_entropy_collapse.py` (semilla 20260705, N=2000).

### Vulnerabilidad

El keygen original sorteaba material de clave como:

```python
int(rng.integers(0, 2**62)) % (p ** d)     # β_v  y  L
```

A parámetros PQ-128 (p = 2⁶¹−1, d = 6, |F_q| = p^d ≈ 2³⁶⁶) el sorteo nunca supera
2⁶². Como `from_int` codifica en base p, el elemento de campo resultante es
`(a₀, a₁, 0, 0, 0, 0)` con a₁ ∈ {0,1}. Es decir, β y L caen en un subconjunto
**casi-escalar** de ~2⁶² elementos en un campo de ~2³⁶⁶.

### Medición (reproducible, semilla 20260705)

| Sampler | frac. no-nula por coordenada | a₁ distintos | entropía/elem | Grover |
|---------|------------------------------|--------------|---------------|--------|
| **VIEJO** | `[1.0, 0.524, 0.0, 0.0, 0.0, 0.0]` | {0, 1} | ~62 bits | ~31 bits |
| **NUEVO** | `[1.0, 1.0, 1.0, 1.0, 1.0, 1.0]` | — | ~366 bits | ~183 bits |

Las coordenadas 2..5 de β y L eran **siempre cero** con el sampler viejo.

### Impacto

- **Invalida directamente la afirmación de 147 bits cuánticos.** Con β y L
  confinados a ~62 bits de entropía, una búsqueda tipo Grover sobre el material de
  clima de clave cuesta ~31 bits por elemento — muy por debajo de 128.
- Es una debilidad de **homogeneidad de escala** (β casi-escalar ⇒ σ_v casi-lineal),
  del mismo tipo que hundió al esquema Langa. Un revisor externo la habría
  detectado de inmediato.

### Corrección (Paso 2, Fase 0)

- `crypto/sampling.py::random_fq_element` sortea uniformemente en `[0, p^d)` por
  rechazo (`uniform_int_below`), excluyendo {0} (para L) o {0,1} (para β).
- El mismo módulo corrige el sesgo de módulo en las matrices invertibles
  (`random_invertible_matrix_fp`) y en el PRG (`prg_vec`, rechazo por coordenada +
  domain separation por longitud).
- Regresión: `tests/test_sampling.py::test_random_fq_element_uses_full_field` falla
  con el código viejo y pasa con el nuevo.

### Nota

Este hallazgo **mide el bug de implementación, no la fortaleza del cifrado**. Por
eso era prerrequisito corregirlo antes del spike A5/A6: atacar el esquema con β
casi-escalar mediría el bug, no NL-SMIP.

---

## A5 — Recuperación algebraica de clave (spike Fase 0)

**Estado:** A5a verificado (β cae); A5b parcial.
**Script:** `attacks/A5_key_recovery.py` (semilla 20260705, tetra, esquema
corregido post-H3).

### A5a — β es afín, se recupera con una división en el campo

Modelo: atacante con **texto claro conocido** que además conoce el acoplamiento
(A, B, C). Por vértice v, con nonce público (r_v conocido):

```
w_v := c_v + r_v = σ_v(τ_v),   τ_v = ι(arg_v(α) + r_v)
σ_v(τ) = β_v·τ + (β_v − 1)·(L·τ + 1)^e
```

Como τ_v y P := (L·τ_v + 1)^e son conocidos, σ_v es **afín en β_v**:

```
w = β_v·(τ + P) − P   ⇒   β_v = (w + P)·(τ + P)^{-1}
```

**Resultado (verificado):**

| d | p | e | β recuperado exactamente | coste |
|---|---|---|--------------------------|-------|
| 2 | 5 | 5 | sí | 1 inversión de campo/vértice |
| 3 | 11 | 3 | sí | 1 inversión de campo/vértice |
| 4 | 5 | 5 | sí | 1 inversión de campo/vértice |

**Implicación (load-bearing para el track):** β **no** es una fuente de dureza
independiente. Toda la dureza de recuperación de clave descansa en (A, B, C).
Esto confirma y refuerza la decisión de `DECISION.md` de clasificar A,B,C como
secretos: si fueran públicos, β caería y con él el trapdoor.

### A5b — sistema de recuperación de clave completa

Con β **y** (A,B,C) desconocidos, τ es afín en (A,B,C) y el sistema es de grado
e+1 en las incógnitas de clave. Tamaños (tetra):

| d | p | e | incógnitas de clave (A,B,C,β) | ecs/ciphertext | grado |
|---|---|---|-------------------------------|----------------|-------|
| 2 | 5 | 5 | 64 (16,24,16,8) | 8 | 6 |
| 3 | 11 | 3 | 138 (36,54,36,12) | 12 | 4 |
| 4 | 5 | 5 | 240 (64,96,64,16) | 16 | 6 |

Por A5a, NL-SMIP-KR se reduce a recuperar (A,B,C) — el objetivo estructural /
MinRank de Fase 1 (A4). Gröbner directo sobre las incógnitas completas queda para
Fase 1 con Sage/msolve.

---

## A6 — D_reg real del sistema de recuperación de mensaje (spike Fase 0)

**Estado:** parcial (d∈{2,3} medido; d≥4 pendiente Sage/Magma).
**Script:** `attacks/A6_dreg_public_system.py` (semilla 20260705, nonce fijo).

### Modelo y alcance (honestidad, ver [HARDNESS.md](HARDNESS.md) §H2)

El sistema de grado 3e en α **solo** es accesible a un atacante de texto claro
**elegido** que **fija el nonce** e interpola el mapa α→c con consultas al oráculo
(no necesita la clave: es ajuste entrada/salida). Con **nonce fresco** el mapa
cambia por consulta y no se puede interpolar (esa defensa es A2). Aquí se mide el
**peor caso** (nonce fijo/reutilizado), que **acota por arriba** el poder del
atacante y es la cantidad sobre la que se basaban las cifras suspendidas (74/…).

### Medición (reproducible, semilla 20260705, tetra)

| d | p | e | 3e | m_eqs | Hilbert D_reg | D_reg empírico | gap | tiempo |
|---|---|---|----|-------|---------------|----------------|-----|--------|
| 2 | 17 | 5 | 15 | 8 | 17 | **22** | **+5** | 0.7s |
| 3 | 11 | 3 | 9 | 12 | 12 | **15** | **+3** | 27.9s |
| 4 | — | — | — | — | — | **PENDIENTE** | — | Sage/Magma |

- El gap **+5** en (d=2, e=5) **reproduce exactamente** la tabla histórica del
  repo (tetra d=2 e=5), ahora sobre el esquema corregido post-H3. La maquinaria
  de medición queda validada.
- Ambos gaps son **positivos**: el D_reg empírico **excede** la predicción de
  Hilbert, confirmando a pequeña escala que Hilbert es una **cota inferior
  conservadora** del coste del atacante (en el peor caso de nonce fijo).

### Qué NO valida esto

- **No resucita las cifras suspendidas.** El gap positivo se confirma solo en
  d∈{2,3}. La extrapolación de la regresión de gap a d=12 sigue **sin validar**
  (d≥4 requiere RREF de matrices de interpolación C(d+3e,d)² — p.ej. 3876×3876 en
  d=4 — inviable en Python puro). Las cifras 74/126/133/147 **siguen suspendidas**.
- **No mide NL-SMIP real.** Mide el sistema del atacante-con-oráculo-y-nonce-fijo,
  cota superior de su poder, no el atacante pasivo (que ni siquiera tiene el mapa).

### Nota de reproducibilidad

Requisito de la interpolación: `p^d ≥ C(d+3e, d)` (nº de monomios) y `p > 3e`.
Con p demasiado pequeño no hay suficientes puntos distintos en F_p^d y la
interpolación es imposible (guard explícito en el script).

---

## A6-CICO — Solving degree real de CICO en el modelo AO (Fase 1, reencuadre)

**Estado:** verificado (BREAK de la seguridad AO en 1 ronda).
**Script:** `attacks/A6_cico_solving_degree.py` (semilla 20260705, tetra).
**Backend:** python-flint (rango de Macaulay). Ver [AO_SPEC.md](AO_SPEC.md).

### Modelo

En una primitiva AO la permutación es **pública** (A,B,C,β,L son round-constants
públicos, como la matriz MDS de Poseidon). Esto **disuelve H2**: el atacante sí
tiene el sistema de coeficientes conocidos. Alaniz tiene **una sola ronda**
`R = S ∘ (M + rc)`.

### El ataque (= el propio decryptor)

Para CICO con una salida fijada, el atacante **invierte la σ pública** en esa
salida por búsqueda de raíces (barato; σ no inyectiva ⇒ ~2.1 candidatos/vértice,
un pequeño factor combinatorio) y le queda el **sistema de mezcla de grado 3** en
las variables libres. El grado alto e **no se compone** a 3e porque hay una sola
capa de S-box y las salidas fijadas son conocidas. El algoritmo del decryptor
legítimo (σ⁻¹ + F4 cúbico) **ES** este ataque CICO.

### Medición (reproducible)

| d | p | e | 3e | naive-3e D_reg | **CICO solving degree** | σ⁻¹ combos | rango@D |
|---|---|---|----|----------------|-------------------------|------------|---------|
| 2 | 17 | 5 | 15 | 17 | **4** | 9 | 24×15, ker=1 |
| 3 | 11 | 3 | 9  | 12 | **4** | 1 | 48×35, ker=1 |
| 4 | 257 | 7 | 21 | 33 | **4** | 2 | 80×70, ker=1 |
| 6 | 257 | 5 | 15 | 29 | **5** | 6 | 672×462, ker=1 |

### Conclusión (BREAK)

El solving degree CICO real es **4–5** (el de un sistema cúbico), **independiente
de e**, frente al bound naive de grado-3e (17–33) sobre el que se apoyaban las
cifras suspendidas. **La S-box de grado alto no aporta ninguna seguridad CICO en
una ronda.** Esto rompe la afirmación de seguridad AO del objeto actual y
sepulta definitivamente las cifras 74/126/133/147 en este modelo.

Ataques de vanguardia (FreeLunch 2024/347, CheapLunch 2025/2040, Resultant
2025/259 y 2026/1281) están **diseñados para primitivas multi-ronda** cuyo solving
degree naive es alto; aquí **no hacen falta**: el diseño de una ronda cae por
inversión directa de la S-box. Se aplicarían a un hipotético rediseño multi-ronda.

---

## A2 — Disciplina de nonce

**Estado:** verificado. **Script:** `attacks/A2_nonce_discipline.py`.

Los `rc_v = PRG(nonce, "v", v)` son la **única** aleatoriedad por cifrado.
Verificado (d∈{2,3}): nonce fijo ⇒ mapa determinista; nonce fresco ⇒ el mapa
cambia; nonce reutilizado ⇒ mapa público fijo. **La IND-CPA depende críticamente
de nonce fresco**: reutilizarlo colapsa el esquema al setting CICO público, que
A6-CICO rompe a grado cúbico ⇒ recuperación de mensaje.

## A5b / FreeLunch / CheapLunch / Resultant — no aplican al objeto actual

- **A5b (recuperar A,B,C):** en el modelo AO los parámetros son **públicos**, así
  que la recuperación de clave no es el problema de seguridad. Era relevante solo
  al modelo simétrico abandonado (donde A5a ya mostró que β cae dado A,B,C).
- **FreeLunch / CheapLunch / Resultant:** herramientas para primitivas multi-ronda
  con solving degree naive alto. El Alaniz de una ronda se resuelve a grado cúbico
  sin ellas (N/A / subsumido). Serían el arsenal correcto para atacar un rediseño
  multi-ronda, si se persigue.

---

# Fase 2 (SPN multi-ronda) — suite CICO contra el rediseño

Aquí SÍ se aplican FreeLunch/CheapLunch/resultantes: la construcción es
multi-ronda con S-box biyectiva barata (x⁷), justo su dominio. Motor Gröbner
**real**: msolve 0.6.5 (WSL). Ver [SPN_SPEC.md](SPN_SPEC.md) para el diseño.

## Tabla resumen (Fase 2)

| ID | Ataque | Escala | Resultado | Estado |
|----|--------|--------|-----------|--------|
| **S1-CICO** | Grado del ideal D_I del CICO (modelado por variables intermedias, estilo FreeLunch) | t∈{4,6}, R∈{1,2,3}, msolve | **Ley verificada** `D_I = 7^(R·m)`, m=ramas libres | verificado |
| **S2-tind** | ¿Depende D_I del ancho t o del nº de rama? | t=4 (MDS) vs t=6 (haz), R=2, m=2 | **NO**: D_I=7⁴ idéntico; perfil de grado F4 idéntico (máx 14) | verificado |
| S-FreeLunch | 2024/347 (GB "gratis" + FGLM) | modelado | coste ⇒ `D_I^ω`; R* extrapolado | parcial (ley verificada, R* extrapolado) |
| S-CheapLunch | 2025/2040 (multi-salida) | modelado | misma escala D_I; capacidad óptima del atacante = m mínimo | parcial |
| S-Resultant | 2025/259, 2026/1281 (eliminación) | msolve param. | el eliminante univariado tiene grado = D_I | parcial |

## S1-CICO — Modelado y ley del grado del ideal

**Modelado (fiel a FreeLunch 2024/347, NO Gröbner genérico).** Una variable por
**entrada de S-box** en cada ronda (`x{r}_i`, t·R variables); ecuaciones de
enlace `x{r+1}_i = Σ_j M[i][j]·x{r}_j⁷ + rc` (grado 7, no 7^R). CICO de capacidad
c: se fijan c coords de entrada y t−c de salida ⇒ sistema cuadrado 0-dim.
Implementado en `src/crypto/spn_cico.py`; driver `experiments/04_spn_cico_attacks.py`.

**Métrica medible = grado del ideal D_I** (= nº de soluciones sobre la clausura =
3er campo de la parametrización racional de msolve). Es el **coste dominante
compartido** por FreeLunch (FGLM ~ D_I^ω), CheapLunch y resultantes (eliminante de
grado D_I). Medición (semillas fijas, proxy p=1073742091 Goldilocks-like):

| t | R | c | m=t−c | D_I medido | 7^(R·m) | ✓ |
|---|---|---|-------|-----------|---------|---|
| 4 | 1 | 1 | 3 | 343 | 7³ | ✓ |
| 4 | 2 | 2 | 2 | 2401 | 7⁴ | ✓ |
| 4 | 2 | 3 | 1 | 49 | 7² | ✓ |
| 4 | 3 | 3 | 1 | 343 | 7³ | ✓ |
| 6 | 1 | 1 | 5 | 16807 | 7⁵ | ✓ |
| 6 | 1 | 5 | 1 | 7 | 7¹ | ✓ |
| 6 | 2 | 4 | 2 | 2401 | 7⁴ | ✓ |

(10/10 instancias factibles verifican la ley; casos 7⁶ confirman lo mismo pero el
FGLM tarda minutos monohilo.)

> **Ley verificada:** `D_I = 7^(R·m)`, con m = t − c = número de **ramas libres**
> de entrada. Es el grado de Bézout del mapa (ramas libres) → (salidas fijadas)
> tras eliminar las variables intermedias: cada rama libre recorre R S-boxes de
> grado 7. Verificada para R∈{1,2,3}; la extrapolación a R mayor es **conjetura
> respaldada** por la ley a R≤3.

## S2-tind — El nº de rama NO afecta al ataque algebraico (hallazgo central)

Comparando el control MDS (t=4, rama 5) con la principal de haz (t=6, rama 6,
**sub-MDS**) a **igual (R=2, m=2)**:

| construcción | rama | D_I | perfil de grado F4 (por ronda) | solving degree máx |
|---|---|---|---|---|
| tetraedro (MDS) | 5 | 2401 = 7⁴ | 7,7,8,9,10,11,12,13,14 | 14 |
| octaedro (haz) | 6 | 2401 = 7⁴ | 7,7,8,9,10,11,12,13,14 | 14 |

**Idénticos.** Ni D_I ni el grado de resolución distinguen la capa de haz de la
MDS. Los **ceros de la matriz de haz (no-adyacencia) NO abren ningún atajo
algebraico**: el sistema no se desacopla. Conclusión: el **déficit de 1 rama del
haz cuesta 0 rondas extra** frente a FreeLunch/CheapLunch/resultantes. El nº de
rama gobierna solo la cota estadística (differential/linear wide-trail), medida
aparte en `experiments/03_mix_branch_number.py`, no la seguridad algebraica CICO.

## R* — nº mínimo de rondas seguras (extrapolado de la ley verificada)

Modelo de coste conservador (favorable al atacante): resolver un ideal 0-dim de
grado D_I cuesta ~`D_I^ω` operaciones en F_p con **ω=2** (sparse-FGLM). Seguridad
= `ω·log₂(D_I) = 2·R·m·log₂7`. El atacante usa el m mínimo que constituye un
break (= capacidad κ del esponja). `R*(m) = ⌈128 / (2·m·log₂7)⌉`, **independiente
de t**:

| capacidad m (=κ) | R* (cualquier t) | nota |
|---|---|---|
| 1 | 23 | cota más conservadora (sin supuesto de esponja) |
| **2** | **12** | **punto de diseño**: 128-bit sobre Goldilocks (κ=2) |
| 3 | 8 | κ=3 |

**Estado:** ley `D_I=7^(R·m)` **verificada** (R≤3); R* **extrapolado (conjetura
respaldada)**; el modelo de coste ω=2 es una hipótesis estándar explícita.

## Notas de fidelidad del motor (msolve) — evidencia negativa preservada

Dos fallos del pipeline detectados y documentados (no borrar; ahorran tiempo a
quien reproduzca):

1. **CRLF rompe el parser de msolve.** Python en Windows escribe `\r\n` en modo
   texto; msolve lo malinterpreta y reporta variedad vacía espuria (`[-1]` /
   GB=`[1]`) aun con sistema consistente. Fix: `spn_cico.write_msolve` fuerza LF.
   Regresión en `tests/test_spn.py::test_msolve_serialization_has_no_carriage_returns`.
2. **msolve segfaultea con el primo 65551** (y otros justo sobre 2¹⁶). Se usan
   proxies Goldilocks-like que msolve maneja (31 / **65371** / 1073742091). Además
   msolve malinterpreta la multiplicación explícita `v*v*...` (usar siempre `^`) y
   los paréntesis (emitir polinomios expandidos).

---

# Camino 1 (estructura de haz como NO-LINEALIDAD) — acoplamiento de S-boxes

Movida la geometría de la capa lineal (donde no comparaba nada, Fase 2) al
**acoplamiento entre S-boxes** vía los 2-símplices del complejo. Capa lineal =
MDS Cauchy neutra idéntica en todas las modalidades. Diseño en
[COUPLING_SPEC.md](COUPLING_SPEC.md). Motor: msolve real, proxy 1073742091.

## Tabla resumen (Camino 1)

| ID | Ataque | Escala | Resultado | Estado |
|----|--------|--------|-----------|--------|
| **C1-grade** | ¿Acelera el acoplamiento el grado del ideal? | t∈{4,6}, R∈{1,2,3}, msolve | `add` NO (=7^Rm); **`input` SÍ**: `D_I=7^(Rm)·m·2^(R-1)` (+1 bit/ronda) | verificado |
| **C1-real** | ¿Es seguridad real o trampa de grado nominal (Griffin/Arion)? | t=4, R∈{2,3}, m=1 | **REAL**: solving degree F4 **más alto** (9-10 vs 7-9); modelo solo-en-x reproduce D_I exacto | verificado |
| C1-FreeLunch/CheapLunch | 2024/347, 2025/2040 (coste = D_I) | modelado | D_I(input) genuinamente mayor ⇒ coste mayor bajo ambos; sin atajo por remodelado (D_I invariante) | parcial |

## C1-grade — El acoplamiento a la entrada acelera D_I (verificado)

Tres modalidades biyectivas triangulares sobre la misma capa MDS Cauchy:
`indep` (y_v=x_v⁷), `add` (y_v=x_v⁷+Σc·x_u·x_{u'}), `input` (y_v=(x_v+Σc·x_u·x_{u'})⁷).
CICO estilo FreeLunch (`src/crypto/spn_coupling.py`; en modo `input`, variable
auxiliar `a{r}_v` por S-box). Medición (msolve, m=1, idéntico t=4 y t=6):

| R | baseline 7^R | `indep` | `add` | `input` |
|---|---|---|---|---|
| 1 | 7 | 7 | 7 | 7 |
| 2 | 49 | 49 | 49 | **98** |
| 3 | 343 | 343 | 343 | **1372** |

Puntos adicionales `input` (t=4): (R=1,m=2)=98, (R=1,m=3)=1029. **Ley ajustada a
todos los puntos:**

> `D_I(input) = 7^(R·m) · m · 2^(R-1)`  vs baseline `7^(R·m)`.

El factor `m·2^(R-1)` = **+1 bit de grado del ideal por ronda** (el `2^(R-1)`).
A m=1 coincide con duplicar la base (7→14); al crecer m el peso relativo baja.
`add` (cruce aditivo, subdominante a x_v⁷) **no aporta nada**, como se predijo.

## C1-real — Es seguridad real, NO trampa de grado nominal (verificado)

La advertencia Griffin/Arion: acoplamiento cruzado ⇒ D_I nominal alto pero solving
degree efectivo bajo. Aquí lo contrario:

1. **Solving degree F4 MÁS ALTO para `input`** (t=4, m=1): R=2 → 9 vs 7; R=3 → 10
   vs 9. F4 trabaja genuinamente más, no menos.
2. **El modelo solo-en-x reproduce D_I exacto** (98, 1372): las variables
   auxiliares `a` NO inflan D_I; es intrínseco al ideal. (D_I = nº de soluciones,
   invariante al modelado ⇒ FreeLunch/CheapLunch no pueden reducirlo remodelando.)

Conclusión: la estructura de haz **como acoplamiento a la entrada de la S-box SÍ
compra grado algebraico real** — lo que la versión lineal (Fase 2) no hacía.

## R* y coste (Paso 4) — la aceleración es real pero su beneficio neto es marginal

`experiments/07_coupling_cost_verdict.py` (ω=2). R* (128-bit):

| capacidad m | R*(baseline) | R*(input) | rondas ahorradas |
|---|---|---|---|
| 1 | 23 | 18 | 22% |
| 2 | 12 | 10 | 17% |
| 3 | 8 | 7 | 12% |

Coste R1CS (solo S-boxes + 1 mult por producto de acoplamiento/ronda):

| m | complejo | base | input (triáng.) | net | input/Pos2 | **coupling mínimo** |
|---|---|---|---|---|---|---|
| 2 | tetraedro | 192 | 190 | 0.99× | 0.81× | **0.89×** |
| 2 | octaedro | 288 | 300 | 1.04× | 1.28× | **0.87×** |

**Con el acoplamiento triangular (denso) el recargo por ronda ~cancela el ahorro
de rondas a m=2 (net ~empate).** Clave: el **+1 bit/ronda es independiente de la
densidad** del acoplamiento (lo da cualquier acoplamiento a la entrada que suba el
grado), pero el **coste escala con #términos** ⇒ un **acoplamiento mínimo (1
término/ronda)** conserva toda la ganancia a +1 mult/ronda → **net ~0.87-0.89×
(victoria real)**. Ese es el diseño accionable.

**Estado:** ley `D_I=7^(Rm)·m·2^(R-1)` y realidad (no-trampa) **verificadas**
(R≤3); R\* y coste **extrapolados** (ω=2 explícito). El acoplamiento mínimo es
**conjetura respaldada** (misma física de grado, coste menor) — a validar.
