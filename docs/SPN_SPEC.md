# SPN_SPEC — Permutación AO SPN multi-ronda sobre F_p (Fase 2)

**Estado:** Pasos 2a (cuerpo + S-box) y 2b (capa de mezcla + mini-gate MDS)
completados y medidos. Paso 3 (SPN completa + suite de ataques) **pendiente de
confirmación del gate 2b**. Ver [DECISION.md](DECISION.md) para el pivote que
origina este diseño y [CRYPTANALYSIS.md](CRYPTANALYSIS.md) para el ataque
(A6-CICO) que gobierna la lección de diseño.

## 0. Lección que gobierna el diseño (no violar)

El grado algebraico debe crecer por **composición de rondas**, NO por una S-box
cara de un solo golpe: A6-CICO demostró que una S-box de grado alto en una capa
se invierte en las salidas fijadas y el solving degree CICO colapsa a cúbico,
independiente de e. Por tanto: S-box **biyectiva y barata de grado bajo** +
**multi-ronda**; parámetros **públicos**; sin secreto en la permutación.

## 1. Cuerpo: Goldilocks p = 2⁶⁴ − 2³² + 1

**Por qué este p** (verificado en `tests/test_spn.py`):

- Es el cuerpo AO estándar de Plonky2/Plonky3; aritmética nativa de 64 bits
  rápida (reducción especial por la forma 2⁶⁴−2³²+1).
- **Poseidon2 tiene instanciación de referencia sobre Goldilocks** — la
  comparación de la pregunta de investigación (capa tipo-haz vs capa lineal de
  Poseidon2) se hace sobre el mismo cuerpo, sin traducción.
- p − 1 = 2³²·3·5·17·257·65537 (factorización verificada por test).

**Alternativa considerada y descartada:** el cuerpo escalar de BN254 (donde
Poseidon usa x⁵). Descartado porque: (a) 254 bits ⇒ toda la experimentación
Gröbner quedaría fuera del límite de msolve (char < 2³¹) igualmente, (b) la
aritmética es ~4× más cara por elemento, y (c) Goldilocks es el objetivo AO
actual de los sistemas basados en FRI, el nicho natural de una permutación
nueva.

## 2. S-box: x → x⁷ (d mínimo biyectivo)

x → x^d es biyección de F_p ⟺ gcd(d, p−1) = 1. Para Goldilocks, 2, 3, 4, 5 y 6
comparten factor con p−1 (3 y 5 dividen p−1), así que el mínimo es **d = 7**
(coincide con la x⁷ de Plonky2/Poseidon2-Goldilocks — verificado por
`min_bijective_exponent`). Inversa: y → y^(7⁻¹ mod p−1); biyectividad probada
exhaustivamente en el proxy diminuto p′=31 y por roundtrip en Goldilocks.

**Coste:** x⁷ = 4 mults (x², x⁴, x³=x²·x, x⁷=x⁴·x³) — barata, grado bajo;
el grado de la permutación crece como 7^rondas por composición.

## 3. Primos proxy para msolve (experimentos Gröbner, Paso 3)

msolve solo admite característica < 2³¹, y Goldilocks tiene 64 bits. Los
ataques del Paso 3 se corren sobre **primos proxy con la misma estructura de
exponente**: 3 | p′−1, 5 | p′−1, 7 ∤ p′−1 ⇒ el mismo d = 7 es mínimo. Pinneados
y verificados (`crypto/spn_field.py::PROXY_PRIMES`):

| proxy | valor | uso |
|---|---|---|
| `PROXY_PRIME_TINY` | 31 (= 2·3·5 + 1) | tests exhaustivos de biyectividad |
| `PROXY_PRIME_16` | 65551 | instancias msolve pequeñas |
| `PROXY_PRIME_30` | 1073742091 | instancias msolve a máxima escala |

Hipótesis de transferencia (etiquetada **conjetura** hasta el Paso 3): el
solving degree CICO medido sobre los proxies transfiere a Goldilocks porque los
sistemas polinomiales tienen idéntica estructura (mismo d, misma capa); solo
cambia el tamaño del cuerpo.

## 4. Capa de mezcla tipo-haz (lineal, pública) — `crypto/spn_mix.py`

La estructura de haces sobre el 2-complejo K = (V, E, T) se aterriza como
**matriz t×t sobre F_p** (t = |V|), patrón Laplaciano de haz sin signos, con
pesos públicos por vértice/arista/triángulo derivados del PRG auditado
(semilla pública, domain-separated, pesos no nulos):

```
M[u][u] = a_u + Σ_{e∋u} w_e + Σ_{T∋u} c_T
M[u][v] = w_uv + Σ_{T⊇{u,v}} c_T      si (u,v) ∈ E
M[u][v] = 0                            si (u,v) ∉ E   (no-adyacencia ⇒ cero)
```

A diferencia de la construcción descartada, la mezcla es **lineal** (los
tensores de multiplicación de F_{p^d} desaparecen) y **sin secreto**.

**Obstrucción estructural (verificada):** una matriz MDS no tiene entradas
cero (menores 1×1), así que el patrón tipo-haz solo puede ser MDS si el
1-esqueleto de K es completo. Tetraedro = K₄ ⇒ denso; doble-tetra y octaedro
tienen pares no adyacentes ⇒ **no pueden ser MDS**, la pregunta es cuánta rama
pierden exactamente.

## 5. Resultados del mini-gate 2b (VERIFICADO)

`experiments/03_mix_branch_number.py`, 5 semillas fijas, número de rama
diferencial **exacto** (enumeración soporte+rango, con verificación cruzada
contra el test de menores MDS). Idéntico sobre Goldilocks y el proxy de 30
bits; idéntico en las 5 semillas:

| matriz | t | rama | cota MDS (t+1) | MDS | ceros | nnz | ceros(M²) |
|---|---|---|---|---|---|---|---|
| haz[tetraedro] | 4 | **5** | 5 | **SÍ** | 0 | 16 | 0 |
| Poseidon2 M4 | 4 | 5 | 5 | SÍ | 0 | 16* | 0 |
| Cauchy MDS | 4 | 5 | 5 | SÍ | 0 | 16 | 0 |
| haz[doble-tetra] | 5 | **5** | 6 | no | 2 | 23 | 0 |
| Cauchy MDS | 5 | 6 | 6 | SÍ | 0 | 25 | 0 |
| haz[octaedro] | 6 | **6** | 7 | no | 6 | 30 | 0 |
| Cauchy MDS | 6 | 7 | 7 | SÍ | 0 | 36 | 0 |

\* nnz cuenta entradas no nulas; la ventaja real de M4 es que se aplica con
**8 sumas + doblados** (sin mults genéricas), mientras que la matriz de haz es
densa-simétrica y cuesta ~t² mults por aplicación. La difusión empata en t=4;
el **coste de aplicación no** — esa es la tensión a juzgar en el Paso 4.

Lecturas:

1. **t=4 (tetraedro): la matriz tipo-haz ES MDS** (rama 5 = cota), en las 5
   semillas y en ambos cuerpos. En K₄ el patrón de haz genera matrices
   simétricas densas genéricas ⇒ MDS con probabilidad ≈ 1 (honestidad: en t=4
   "estructura de haz" ≈ "simétrica densa"; la estructura no restringe).
2. **t=5, t=6: déficit de exactamente 1** respecto a la cota MDS (5/6 y 6/7),
   con los ceros exactamente en los pares no adyacentes. Mejor de lo que la
   cuenta de ceros sugería a priori.
3. **M² es densa en los tres complejos** — la composición de 2 capas difunde
   totalmente incluso donde M tiene ceros (relevante para el conteo de rondas
   del Paso 3).

## 6. STATUS de afirmaciones de esta fase

| Afirmación | Estado |
|---|---|
| d=7 mínimo biyectivo en Goldilocks; proxies replican la estructura | **verificado** (tests) |
| Haz-K₄ (t=4) es MDS; Poseidon2 M4 es MDS; rama exacta t=5,6 = cota−1 | **verificado** (experimento + tests pinneados, 5 semillas, 2 cuerpos) |
| Coste de aplicación de M (haz denso ~t² mults vs M4 8 sumas) | **parcial** (nnz medido; conteo fino de restricciones → Paso 4) |
| Transferencia proxy → Goldilocks del solving degree | **parcial→verificado** (ley D_I medida en proxies; ver §7) |
| Nº de rondas seguras frente a FreeLunch/CheapLunch/resultantes | **verificado la ley; R\* extrapolado** (§7) |

Reproducir: `python experiments/03_mix_branch_number.py` y `pytest -q`.

## 7. SPN completa y suite de ataques CICO (Paso 3, VERIFICADO)

`src/crypto/spn_permutation.py`: ronda `R_r(x) = M·SB(x) + rc^(r)`, SB = x⁷ en las
t posiciones (SPN completo; rondas parciales tipo Poseidon2 = optimización
diferida, anotada). Biyectiva; inversa exacta (tests). CICO modelado con
variables intermedias estilo FreeLunch en `src/crypto/spn_cico.py`, resuelto en
**msolve real** (`experiments/04_spn_cico_attacks.py`).

**Ley verificada (R∈{1,2,3}, t∈{4,6}, varias capacidades):**
`D_I = 7^(R·m)`, m = ramas libres. **D_I es independiente de t y del nº de rama**
(t=4 MDS y t=6 haz dan D_I y perfil de grado F4 idénticos a igual R,m). El déficit
de rama del haz cuesta **0 rondas** frente a FreeLunch/CheapLunch/resultantes.
Detalle completo y tablas en [CRYPTANALYSIS.md](CRYPTANALYSIS.md#fase-2).

**R\*** (extrapolado, ω=2): κ=1→23, **κ=2→12 (diseño 128-bit Goldilocks)**, κ=3→8;
mismo para t=4 y t=6. Coste en §Paso 4 (`experiments/05_spn_cost.py`).
