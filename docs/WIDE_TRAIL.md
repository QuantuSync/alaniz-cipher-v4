# WIDE_TRAIL — resistencia diferencial/lineal de la construcción mínima (Bloque 1)

**Estado:** verificado (cotas de S-box exhaustivas en proxies; wide-trail estándar).
`experiments/10_wide_trail.py`. Complementa el flanco algebraico
([CRYPTANALYSIS.md](CRYPTANALYSIS.md)) para llamar a la construcción "primitiva
candidata".

## 1. S-box x⁷ sobre F_p

- **Diferencial (MDP).** `(x+a)⁷ − x⁷ = b` es de grado 6 ⇒ ≤ **d−1 = 6** raíces ⇒
  `MDP = (d−1)/p`. Verificado exhaustivamente: p=257 → DDT máx = 6; p=31 → 4 (≤6).
  Sobre **Goldilocks: MDP = 2⁻⁶¹·⁴** por S-box activa.
- **Lineal (MLC).** Cota de Weil `|corr| ≤ (d−1)/√p`. Verificado: p=257 → 0.167 <
  0.374; p=31 → 0.412 < (bound vacío a p pequeño). Sobre **Goldilocks:
  MLC ≤ 2⁻²⁹·⁴** por S-box activa.

## 2. Efecto del acoplamiento a la entrada (el punto nuevo)

La ronda mínima es `y_v = (x_v + q_v)⁷`, `q_v = w·x_a·x_b` (a,b anteriores). Para un
diferencial en `x_v`, la función es una potencia de una entrada **desplazada** por
`q_v`, con la **misma MDP que x⁷** (invariante al offset). `q_v` depende de OTROS
vértices ⇒ solo puede hacer que haya **más** S-boxes activas en una traza, nunca
menos. Verificado a pequeña escala (p=31): la uniformidad diferencial del vértice
acoplado `(x_v + 13·x_a·x_b)⁷` es **igual** a la de x⁷ puro (4 = 4). **El
acoplamiento no degrada la cota diferencial/lineal.**

## 3. Wide-trail y nº de rondas seguras

Capa MDS Cauchy ⇒ **número de rama B = t+1**. Argumento wide-trail estándar: 2
rondas consecutivas activan ≥ B S-boxes ⇒ R rondas activan ≥ ⌊R/2⌋·B.

- Seguridad diferencial (128-bit): `MDP^activas ≤ 2⁻¹²⁸` ⇒ activas ≥ ⌈128/61.4⌉ = **3**.
- Seguridad lineal (corr ≤ 2⁻⁶⁴): activas ≥ ⌈64/29.4⌉ = **3**.

Con B = t+1 ∈ {5,7}, **R = 2** ya da ≥ B ≥ 5 activas ⇒ `R*_difflin = 2` (t=4 y t=6),
con margen enorme (R=4 daría 2⁻⁶¹⁴ de prob. diferencial).

## 4. Veredicto del bloque

| t | rama B | R\*_difflin | R\*_algebraico (κ=2) | gobierna |
|---|---|---|---|---|
| 4 | 5 | 2 | 12 | **algebraico** |
| 6 | 7 | 2 | 12 | **algebraico** |

**R = max(R\*_alg, R\*_difflin) = 12.** La resistencia diferencial/lineal está
holgadamente cubierta por muy pocas rondas (típico de primitivas AO sobre F_p con
p grande): el coste real de rondas lo fija el **flanco algebraico**. El acoplamiento
a la entrada **no** abre debilidad diferencial/lineal — la refuerza si acaso. Flanco
cubierto ⇒ el resultado asciende hacia primitiva candidata.

**Estado:** cotas S-box **verificadas** (exhaustivo, proxies); wide-trail = método
estándar del campo; `R*_difflin` derivado de esas cotas. `R*_alg=12` sigue
**extrapolado** (ω=2) del flanco algebraico.
