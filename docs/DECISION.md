# DECISION — Track técnico y de publicación

**Fecha:** 2026-07-05
**Estado:** confirmado (Fase 0).
**Decisor:** L. Alaniz Pintos.

Este memo fija el track de trabajo y el reparto público/secreto que gobierna toda
decisión de diseño posterior. Cualquier cambio requiere un nuevo memo fechado.

## Contexto

Dos restricciones no negociables gobiernan el proyecto:

1. **Restricción estructural (ACTION_PLAN §0).** La σ de Alaniz es de grado alto
   (e). El mapa público compuesto α→c tendría grado 3e, impublicable. Por tanto
   **una PKE multivariante estándar con esta σ no es viable.**

2. **Realidad del código (hallazgo H1, Fase 0).** La implementación de referencia
   (`encrypt_pq128`) necesita `A`, `B`, `C` y `β` para cifrar (β entra vía
   `sigma_v3`). Es decir, **cifrar requiere el secreto**. Hoy el esquema es de
   **clave simétrica**, no de clave pública. Ninguna afirmación de "clave pública"
   es cierta respecto al código.

## Decisión

- **Track técnico objetivo: A — KEM / primitiva simétrica sobre NL-SMIP.**
  Se asume clave compartida `key = (A, B, C, β)`. La cohomología de haces sobre el
  2-complejo es la estructura del problema duro (ver `HARDNESS.md`). Una eventual
  asimetría tipo KEM se diseñará y validará en Fase 1, no se da por supuesta.

- **Track de publicación garantizado: B — paper de criptoanálisis / espacio de
  diseño.** El arco v1→Langa→v4 (construcciones, ataques, lo que sobrevive y por
  qué) se documenta con el mismo trabajo de Fase 1. Los resultados negativos
  también se publican.

- **C — PKE novedosa: descartado**, salvo que en Fase 1 aparezca una asimetría
  genuinamente nueva y validada.

## Reparto público / secreto (confirmado)

| Elemento | Clasificación | Razón |
|---|---|---|
| K, p, d, e, L, H₀, PRG/domain-sep | **Público** | Parámetros de setup; no dependen de la clave. |
| nonce, ciphertext c | **Público** | Se transmiten. |
| A_v, B_e, C_t | **Secreto (parte de la clave compartida)** | Necesarias para cifrar y descifrar; se tratan como secretas (simétrico puro). Su estatus se reevaluará solo si Fase 1 (A4 MinRank, A5 recuperación de β) muestra que son recuperables o inertes. |
| β_v | **Secreto (parte de la clave compartida)** | Trapdoor de σ; necesario para cifrar y descifrar. |

> Nota: la clasificación de A,B,C como secretas es la formulación **más
> conservadora** del problema duro. No cierra la puerta al Track A: si Fase 1
> demuestra que publicar A,B,C no reduce la dureza, podrá revisarse aquí con un
> memo nuevo.

## Consecuencias inmediatas (Fase 0)

1. Toda la documentación deja de afirmar "clave pública". `DESIGN.md`,
   `SECURITY.md` y `findings/CSI_AND_INDCPA.md` se reescriben en clave
   simétrica/KEM (pendiente, ligado a la unificación de código).
2. El problema duro se reenuncia sobre datos realmente públicos en `HARDNESS.md`
   como **NL-SMIP**, con β (y A,B,C) como incógnitas del atacante.
3. Las afirmaciones cuantitativas de seguridad (74 / 147 / … bits) quedan
   **suspendidas** hasta reformularse sobre el sistema que realmente ve el
   atacante y revalidarse. Se re-etiquetan en `STATUS.md`.

## Expectativa

Gane o pierda la construcción, la contribución sale de: (a) el problema
duro bien planteado (NL-SMIP), (b) el criptoanálisis propio (Fase 1), (c) un
KEM/simétrico bien analizado si sobrevive. Ese es el objetivo de este track.

---

## Recomendación tras el spike de reconocimiento (Paso 3, Fase 0)

**Fecha:** 2026-07-05. **Evidencia:** [CRYPTANALYSIS.md](CRYPTANALYSIS.md) (A5, A6),
esquema ya corregido post-H3. Escala pequeña (d∈{2,3,4}), semillas fijas.

### Veredicto: **GO condicional a Track A — pero SOLO como primitiva SIMÉTRICA.**

Nada rompió el esquema corregido a pequeña escala, así que no hay NO-GO. Pero el
spike acota con fuerza lo que Track A puede ser:

1. **β NO es un trapdoor independiente (A5a, verificado).** Dado (A,B,C) y un texto
   claro conocido, β se recupera con **una inversión de campo por vértice**. Por
   tanto:
   - **No existe (todavía) una asimetría KEM viable.** No se puede publicar (A,B,C)
     y guardar β: β caería. La parte "KEM" de Track A **no está soportada** por la
     evidencia; el objetivo realista hoy es **simétrico puro**.
   - La narrativa de seguridad debe reescribirse: la dureza **no** está en invertir
     σ vía β, sino en recuperar **(A,B,C)**. Ese es el verdadero problema
     (NL-SMIP-KR) y el objetivo de Fase 1 (A4 MinRank / estructural).

2. **Evidencia de dureza a pequeña escala, pero cifras aún suspendidas (A6, parcial).**
   Los gaps D_reg empírico − Hilbert son **positivos** (+5 en d=2, +3 en d=3) y el
   caso d=2 reproduce exactamente la tabla histórica. Es señal favorable en el peor
   caso (nonce fijo), pero **solo** en d∈{2,3}; d≥4 queda pendiente (Sage/Magma).
   **Las cifras 74/126/133/147 siguen suspendidas.**

3. **σ no necesita rediseño por ahora.** No se observó colapso ni distinguisher en
   el esquema corregido a esta escala. El fallo grave (H3) era de **muestreo**, ya
   corregido. Un rediseño de σ solo se justificaría si Fase 1 lo exige.

### Acciones que habilita esta recomendación

- Reescribir `DESIGN.md`/`SECURITY.md`/`CSI_AND_INDCPA.md` al modelo **simétrico**,
  y corregir la narrativa "β = trapdoor" → "la dureza está en (A,B,C)".
- Fase 1 se enfoca en **recuperar (A,B,C)**: A4 (MinRank sobre B_e, C_t), A2
  (interpolación con nonce fresco vs. reutilizado), A7 (distinguisher). A6 a escala
  (d≥4) con Sage antes de cualquier cifra de bits.
- **Prohibido** afirmar KEM/clave pública o cualquier número de bits hasta que la
  evidencia lo respalde.

### Qué invalidaría este GO (disparadores de NO-GO / rediseño)

- Que A4 recupere (A,B,C) por debajo de la seguridad afirmada → rediseño del
  acoplamiento.
- Que A2 con nonce reutilizado recupere estructura de clave de forma barata →
  el esquema depende críticamente de nonce fresco (documentar o rediseñar).
- Que A6 a escala (d≥4) muestre gap ≤ 0 o D_reg muy por debajo de lo extrapolado →
  enterrar las cifras y rehacer parámetros.

---

## Veredicto tras el reencuadre AO + suite CICO (Fase 1)

**Fecha:** 2026-07-05. **Evidencia:** [CRYPTANALYSIS.md](CRYPTANALYSIS.md)
(A6-CICO, A2), [AO_SPEC.md](AO_SPEC.md), coste en
`experiments/02_ao_cost_estimate.py`. Backend: python-flint (Sage/msolve
bloqueados, ver STATUS).

### Veredicto: **NO-GO como primitiva AO → PIVOTAR a Track B (paper de criptoanálisis).**

Se cumplen **dos** disparadores de NO-GO simultáneamente:

1. **Roto en una ronda (más barato que FreeLunch).** A6-CICO (verificado,
   d∈{2,3,4,6}): el modelo AO hace la permutación **pública**, y con una sola
   ronda el atacante invierte la σ pública en las salidas fijadas y resuelve un
   sistema **cúbico** (solving degree **4–5**, independiente de e). El bound de
   grado-3e (17–33) **no se paga**. La S-box de grado alto —el corazón del
   diseño— **no aporta ninguna seguridad CICO en una ronda**. Ni siquiera hace
   falta FreeLunch/CheapLunch/resultantes: caen por inversión directa.

2. **Coste AO no competitivo.** Una ronda ya cuesta ~9.8k mult. F_p (~42×
   Poseidon2 en d=12,e=31). Como una ronda es insegura, una versión segura
   necesitaría muchas rondas → **~250–420× Poseidon2** (6–10 rondas). La tensión
   central (e alto = caro) se agrava: aquí e es **caro e inútil** para CICO en
   una ronda.

### Consecuencia: Track B (paper de criptoanálisis / espacio de diseño)

Contenido publicable ya disponible, con scripts reproducibles:
- **H1** — no es clave pública (cifrar necesita el secreto).
- **H3** — colapso de entropía tipo Langa (β casi-escalar, ~62 bits), detectado y
  corregido por nosotros antes de cualquier revisor.
- **A5a** — β no es un trapdoor: cae con una inversión de campo dado (A,B,C).
- **A6-CICO** — el hallazgo central: acoplamiento por haz + S-box de grado alto en
  **una ronda** no da seguridad CICO; el solving degree colapsa a cúbico ⊥ de e.
- **A2** — la seguridad descansa por completo en la frescura del nonce.
- **Coste** — cuantificación de por qué el diseño es no competitivo como AO.

Narrativa: el arco v1 → ataque Langa → v4 → reencuadre AO como estudio del
espacio de diseño, con la lección de que **crecer el grado algebraico con una
S-box cara en una sola capa no compra seguridad de aritmetización**.

### Dirección futura (abierta, NO una afirmación)

Un objeto AO genuino requeriría: (a) **múltiples rondas**, (b) S-box **biyectiva**
(la potencia pura `π_e`, no la σ actual no inyectiva), (c) parámetros públicos, y
entonces re-analizar con FreeLunch/CheapLunch/resultantes. Pero la tensión de
coste (e alto) es un **obstáculo fundamental** a la competitividad. Se registra
como problema abierto, sin ninguna cifra de seguridad asociada.

### Estado de las cifras de seguridad

**Definitivamente enterradas** en el modelo AO (74/126/133/147): A6-CICO muestra
que el coste real del atacante es un Gröbner cúbico (grado 4–5), no grado-3e.
Cualquier número futuro exige un diseño nuevo (multi-ronda) y su propia medición.

---

## Veredicto Fase 2 — SPN de haz vs Poseidon2 (Paso 4)

**Fecha:** 2026-07-05. **Evidencia:** [SPN_SPEC.md](SPN_SPEC.md),
[CRYPTANALYSIS.md](CRYPTANALYSIS.md#fase-2) (S1-CICO, S2-tind, ley `D_I=7^(R·m)`
verificada en **msolve real**), coste en `experiments/05_spn_cost.py`. Motor
Gröbner desbloqueado (msolve/WSL). Escala pequeña (proxies Goldilocks-like),
semillas fijas.

### Veredicto: **Track B — PAPER COMPARATIVO** ("difusión por haz vs MDS").

El rediseño multi-ronda cumple la lección (grado por composición, no por S-box
cara): **nada lo rompe barato** — la seguridad CICO crece limpiamente como
`D_I=7^(R·m)`, sin colapso. Es un objeto AO **sano**, a diferencia del anterior.
Pero la pregunta de investigación —¿difunde el haz tan bien como MDS a coste
comparable?— se responde **NO en el eje que importa**, y por una razón precisa y
publicable:

1. **La estructura de haz no compra seguridad algebraica (S2-tind, verificado).**
   A igual (R, capacidad), el grado del ideal D_I y el perfil de grado F4 son
   **idénticos** para la capa de haz (t=6, rama 6, sub-MDS) y el control MDS
   (t=4, rama 5). Los ceros de no-adyacencia **no abren atajo**. Disparador
   cumplido: *"difunde igual/peor sin ventaja"* → el nº de rama del haz es
   **irrelevante** para FreeLunch/CheapLunch/resultantes. R\* es t-independiente.

2. **El déficit de rama no cuesta rondas algebraicas, pero sí estorba la
   optimización de coste.** R\*(κ=2)=12 rondas completas para ambos t. El coste
   R1CS de una capa lineal (densa o MDS) es **cero** (solo cuentan S-boxes), así
   que el octaedro a 12 rondas ≈ **1.23× Poseidon2** en restricciones (288 vs
   234) — dentro de 2×. **Pero** la palanca real de coste de Poseidon2 son las
   **rondas parciales** (1 S-box/ronda), que requieren una capa **MDS** para el
   argumento wide-trail. La capa de haz **no es MDS** (rama 6<7 en t=6), lo que
   **dificulta justificar rondas parciales** — precisamente la optimización que
   haría competitivo el diseño.

3. **En evaluación nativa/MPC/FHE la capa densa es estrictamente más cara.** El
   haz cuesta ~nnz(M) mults/ronda (30 en t=6) frente a la M4 de Poseidon2
   (~8 sumas + doblados, ~0 mults genéricas): ~648 vs. mucho menos por
   permutación. La estructura geométrica y el coste AO están **en tensión**.

### Contribución publicable (con scripts reproducibles)

Narrativa: *"Difusión estructurada por haz — casi-óptima (déficit de exactamente
1 rama vs MDS) pero sin ventaja algebraica y en tensión con el coste de
aritmetización."* Resultados propios:
- **Ley `D_I = 7^(R·m)`** medida en motor Gröbner real (msolve), R∈{1,2,3}.
- **Independencia de t / nº de rama** del coste algebraico CICO (S2-tind): un
  resultado limpio y algo contraintuitivo (la geometría de la mezcla no ayuda al
  atacante algebraico; solo importa al wide-trail estadístico).
- **Tensión estructura-coste**: near-MDS impide rondas parciales; capa densa cara
  en nativo. Explica *por qué* una capa lineal "bonita" geométricamente no es la
  palanca correcta en AO.
- Arco completo v1 → Langa → v4 (1 ronda, roto) → **SPN de haz (sano pero no
  competitivo)**, con la lección de diseño AO destilada.

### Qué reabriría Track A (candidato real) — disparadores NO cumplidos hoy

- Que una **capa de haz MDS** (p.ej. otro complejo con 1-esqueleto completo y
  pesos Cauchy-like) permita **rondas parciales** y baje R1CS ≤ ~1.5× Poseidon2
  manteniendo la ley `D_I=7^(R·m)`. Abierto.
- Que la estructura de haz habilite un argumento de seguridad **no** capturado por
  D_I (p.ej. contra un ataque futuro) que MDS no dé. No observado.

### Cifras (estado)

`D_I=7^(R·m)` **verificada** (R≤3). **R\* extrapolado (conjetura respaldada)**:
κ=2 ⇒ **R\*=12** rondas, t-independiente, bajo modelo de coste ω=2 explícito.
Ninguna cifra de bits se declara "segura" sin ese etiquetado.

---

## Veredicto Camino 1 — estructura de haz como NO-LINEALIDAD (acoplamiento)

**Fecha:** 2026-07-05. **Evidencia:** [COUPLING_SPEC.md](COUPLING_SPEC.md),
[CRYPTANALYSIS.md](CRYPTANALYSIS.md) (C1-grade, C1-real), coste en
`experiments/07_coupling_cost_verdict.py`. Motor: msolve real, proxies.

### Veredicto (actualizado tras Pasos A/C/D): **CANDIDATO REAL — el acoplamiento mínimo conserva la ley (medido) y da victoria neta de coste; ley apoyada por punto grande resuelto.**

> **Actualización 2026-07-05 (Pasos A/C/D).** Lo que antes era conjetura ahora está
> medido: **(A)** el acoplamiento **mínimo (1 término/ronda)** conserva la ley
> `D_I=7^(Rm)·m·2^(R-1)` **idéntica** en todas las densidades (t=4 y t=6); **(C)**
> punto grande **(R=2,m=2)=9604 resuelto** (35 s, msolve -t 16) que descarta base-14
> (19208) y el nulo (2401) ⇒ ley **verificada**, no solo conjetura; **(D)** con el
> mínimo el coste neto es **0.87-0.89× baseline**, tetraedro **0.73× Poseidon2**.
> Dispara el criterio de **candidato real**. Detalle: [CRYPTANALYSIS.md](CRYPTANALYSIS.md)
> (C1-A, C1-C). Sigue el criterio: timeouts (R=4, R=2/m=3) se reportan como
> huecos, no como confirmación.

> **Campaña final 2026-07-05 (primitiva candidata, Bloques 1-5).** Flancos
> cubiertos: **(1) wide-trail** — R*_difflin=2 ≪ algebraico; el acoplamiento a la
> entrada NO degrada la uniformidad diferencial (MDP 2⁻⁶¹, MLC 2⁻²⁹); gobierna el
> algebraico. **(3) CheapLunch + resultantes corridos** — ambos D_I-bound (CICO-2 >
> CICO-1; eliminante = D_I), sin atajo. **(4) Instanciación Alaniz-AO** — t=8, R=8,
> esponja, ~1.30× Poseidon2 en R1CS (`src/crypto/alaniz_ao.py`, `docs/SPEC.md`).
> **(5) Transferencia** — D_I idéntico en proxies de 5–31 bits ⇒ estructural ⇒
> transfiere a Goldilocks (residual real abierto). **Hueco (2):** escalar
> más allá de R=3 excede el motor (F4/FGLM); mayor punto resuelto = 9604; R≥4
> abierto. **Veredicto: primitiva candidata con todos los flancos medidos salvo el
> escalado del motor y el convenio de capacidad, ambos abiertos y documentados.**

> **Cierre de seguridad 2026-07-05 (FreeLunch sobre la mínima).** El +1 bit/ronda
> **RESISTE FreeLunch** (2024/347). Como `D_I` es invariante al orden y al modelado,
> la métrica que hemos reportado (D_I) *es* el coste de FreeLunch; se corre sobre la
> construcción mínima y `D_I` sigue la nominal `7^(R·m)·m·2^(R-1)` en todos los
> puntos resueltos (98/1372/9604), sin colapsar al baseline. Caso más fuerte: t=6
> R=3, GB casi "gratis" (solving degree 7) y aun así `D_I=1372` (4× baseline) ⇒ el
> FGLM(D_I) es genuinamente mayor incluso con la ventaja completa de FreeLunch.
> (R=4 timeout = hueco.) Evidencia: [CRYPTANALYSIS.md](CRYPTANALYSIS.md)
> (C1-freelunch), `attacks/A_freelunch_minimal.py`.
>
> **VEREDICTO FINAL: principio de diseño AO verificado + candidato mínimo.** El
> resultado central publicable es el **principio genérico** (acoplamiento no-lineal a
> la entrada de la S-box ⇒ +1 bit de grado CICO/ronda, independiente de incidencia,
> resistente a FreeLunch). La construcción **mínima** que lo instancia es un candidato
> con coste neto 0.87-0.89× baseline (tetraedro 0.73× Poseidon2), con R\*/coste
> extrapolados (ω=2) y palancas abiertas (rondas parciales, wide-trail, escalado).

> **Control decisivo 2026-07-05 (¿haz o genérico?).** El +1 bit/ronda es
> **GENÉRICO**, no de haz: cuatro incidencias triangulares (haz, denso, chain, star)
> dan **D_I y F4 idénticos** (octaedro, m=1: 98/1372/deg-9; punto grande m=2: haz y
> chain ambos 4802). Los pesos ya eran PRG arbitrarios; variar la semilla tampoco
> cambia D_I. **La estructura de haz fue inspiración, no mecanismo.** El hallazgo se
> reformula como principio general de diseño AO: *colocar el acoplamiento en la
> ENTRADA no-lineal de la S-box (no en la capa lineal, no aditivo tras la potencia)
> añade +1 bit de grado CICO por ronda, con independencia de la incidencia*.
> Evidencia: [CRYPTANALYSIS.md](CRYPTANALYSIS.md) (C1-generic),
> `experiments/09`. **Camino: redactar** (el mecanismo es general y publicable).

### Veredicto previo (Paso 3-4 inicial): primer resultado positivo — candidato promisorio.

Tras dos negativos (haz lineal = sin ventaja; SPN de haz no competitivo), mover la
estructura de haz al **acoplamiento a la entrada de la S-box** es lo primero que
**compra grado algebraico real**:

1. **Aceleración verificada y REAL (no trampa).** `D_I(input)=7^(Rm)·m·2^(R-1)`,
   un **+1 bit de grado del ideal por ronda** sobre el baseline. Confirmado no-
   trampa (a diferencia de Griffin/Arion): el solving degree F4 sube (9-10 vs
   7-9) y el modelo solo-en-x reproduce D_I ⇒ intrínseco, no reducible por
   FreeLunch/CheapLunch (D_I es invariante). El acoplamiento **aditivo** (`add`)
   no aporta nada; solo el de **entrada** (`input`).

2. **Pero el beneficio neto con acoplamiento denso es marginal.** R\* baja 17-22%,
   pero el recargo del acoplamiento **triangular** (3-6 mults/ronda) ~cancela el
   ahorro en R1CS (net ~empate a m=2: tetra 0.99×, octa 1.04×).

3. **La palanca: el +1 bit/ronda es INDEPENDIENTE de la densidad del
   acoplamiento.** Lo da cualquier acoplamiento a la entrada que suba el grado.
   Un **acoplamiento mínimo (1 término/ronda)** conserva toda la ganancia a +1
   mult/ronda ⇒ **net ~0.87-0.89× vs baseline** y ≤ ~1.3× Poseidon2 (tetra 0.81×).
   Dispara el criterio de **candidato real** (baja R\*, resiste FreeLunch/
   CheapLunch, ≤2× Poseidon2).

### Contribución (positiva)

- **Fenómeno nuevo y limpio:** la geometría simplicial, como acoplamiento no-lineal
  a la entrada de la S-box, **añade exactamente +1 bit de grado CICO por ronda** —
  medido, real, no-trampa. Contrasta con el resultado negativo de la capa lineal:
  *dónde* se pone la estructura (no-linealidad vs linealidad) decide si compra
  seguridad.
- **Diseño accionable:** acoplamiento **mínimo/disperso** (1 término/ronda) sobre
  una capa MDS — conserva la ganancia y da victoria neta de coste. La capa MDS
  (a diferencia del haz lineal sub-MDS) además **no bloquea las rondas parciales**,
  otra palanca de coste aún sin explotar.

### Disparadores de NO-GO (no cumplidos)

- Que a escala (R,m grandes en msolve/Sage) la ley `+1 bit/ronda` se rompa o el
  solving degree colapse (trampa tardía). No observado a R≤3.
- Que el acoplamiento mínimo pierda la ganancia (que dependa de la densidad tras
  todo). A verificar en la validación (Paso siguiente propuesto).

### Cifras (estado)

Ley `D_I=7^(Rm)·m·2^(R-1)` y no-trampa **verificadas** (R≤3, dos modelados).
R\* y coste **extrapolados** (ω=2 explícito). Acoplamiento mínimo = **conjetura
respaldada**. Ninguna cifra "segura" sin ese etiquetado.
