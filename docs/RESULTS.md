# RESULTS — resumen ejecutivo del proyecto

Registro técnico consolidado. Estado por afirmación: **verificado** (medido,
reproducible) / **extrapolado (ω=2)** (derivado de una ley verificada bajo un
modelo de coste explícito) / **abierto** (límite de motor/hardware o análisis
pendiente; ver [OPEN_PROBLEMS.md](OPEN_PROBLEMS.md)). Reproducción por comando en
[REPRODUCE.md](REPRODUCE.md).

## Índice

1. [Qué se buscaba](#1-qué-se-buscaba)
2. [El recorrido (v4 → Langa → AO → acoplamiento)](#2-el-recorrido)
3. [El resultado central: +1 bit de grado CICO por ronda](#3-el-resultado-central)
4. [La primitiva: Alaniz-AO](#4-la-primitiva-alaniz-ao)
5. [Tabla de flancos (cerrados / abiertos)](#5-tabla-de-flancos)
6. [Estado por afirmación](#6-estado-por-afirmación)

## 1. Qué se buscaba

Desarrollar y fortalecer una primitiva criptográfica nueva hasta algo fuerte o
publicable, en el nicho de la **criptografía orientada a aritmetización (AO)**
(hashes/permutaciones para ZK/SNARK sobre F_p), evaluada por el problema **CICO** y
comparada con **Poseidon2** sobre Goldilocks (p = 2⁶⁴−2³²+1).

## 2. El recorrido

| etapa | qué era | resultado |
|---|---|---|
| **v4 (PKE por haces)** | cifrado de clave pública multivariante sobre cohomología de haces | **descartado** (H1: cifrar necesita el secreto ⇒ simétrico, no PKE) |
| **Saneamiento** | muestreo de material de clave | **H3**: colapso de entropía (β/L ~62 bits) detectado y corregido (~366 bits) |
| **1 ronda AO** | σ de grado alto en una capa | **roto** (A6-CICO: solving degree cúbico 4–5, ⊥ de e; la S-box cara no compra seguridad AO en una ronda) |
| **Haz como capa LINEAL** | matriz de mezcla tipo-haz | **sin ventaja algebraica**: `D_I=7^(R·m)` independiente del nº de rama; ~1.23–1.30× Poseidon2 (resultado comparativo "haz vs MDS") |
| **Haz como NO-LINEALIDAD** | acoplamiento a la ENTRADA de la S-box | **el positivo** (ver §3) |

Lección destilada: *el grado algebraico crece por composición de rondas y por la
colocación NO-LINEAL del acoplamiento; una S-box cara de un golpe o una capa lineal
"bonita" no compran seguridad AO.*

## 3. El resultado central

En un SPN algebraico (S-box `x⁷` sobre Goldilocks, capa MDS), **acoplar las S-boxes
en su ENTRADA con un término cuadrático triangular** hace crecer el grado del ideal
CICO:

```
baseline (S-boxes independientes):  D_I = 7^(R·m)
acoplamiento a la entrada:          D_I = 7^(R·m) · m · 2^(R-1)      (+1 bit/ronda)
```

Todo medido en un motor de Gröbner real (msolve):

| propiedad | evidencia | estado |
|---|---|---|
| Real, no trampa de grado nominal | solving degree F4 **sube** (9→16); modelo solo-en-x reproduce D_I; punto grande **(R=2,m=2)=9604** descarta rivales (base-14=19208, nulo=2401) | **verificado** |
| Genérico, no de haz | haz/denso/chain/star dan D_I y F4 **idénticos** | **verificado** |
| Independiente de la densidad | 1 término/ronda conserva toda la ganancia | **verificado** |
| Resiste FreeLunch/CheapLunch/resultantes | todas D_I-bound; CICO-2 > CICO-1; grado del eliminante = D_I | **verificado** (puntos chicos; grandes = huecos) |
| Sin coste diferencial/lineal | MDP=2⁻⁶¹, MLC=2⁻²⁹; el acoplamiento no degrada; R\*_difflin=2 | **verificado** |
| Transfiere a Goldilocks | D_I idéntico en proxies de 5–31 bits ⇒ estructural | **verificado (parcial)** |

Reformulado como **principio de diseño AO**: *la colocación no-lineal del
acoplamiento (entrada de la S-box — no la capa lineal, no aditivo tras la potencia)
añade +1 bit de grado CICO por ronda, con independencia de la incidencia.*

## 4. La primitiva: Alaniz-AO

Esponja sobre Goldilocks. `src/crypto/alaniz_ao.py`, spec en [SPEC.md](SPEC.md).

| parámetro | valor |
|---|---|
| cuerpo / S-box | Goldilocks 2⁶⁴−2³²+1 / x⁷ |
| estado t / rate / capacidad | 8 / 4 / 4 |
| capa lineal | Cauchy MDS 8×8 (rama 9) |
| acoplamiento | cadena mínimo a la entrada (`x_v += c·x_{v-2}·x_{v-1}`) |
| rondas R | 8 (= R\*_alg(m=4)=6 + margen) |

**Seguridad (m_efectivo=4, ω=2):** preimagen **≥179 bits** (baseline, sin
acoplamiento) / 197 (con), colisión **128** genérica (256-bit capacidad) / 179
algebraica. **Coste:** full 1.30× Poseidon2; variante **HADES (rondas parciales)
0.74×** Poseidon2 (reparto moderado R_f=4), verificada a m=1 (parcial=completa para
D_I). `src/crypto/alaniz_hades.py`.

## 5. Tabla de flancos

| flanco | estado | evidencia |
|---|---|---|
| Algebraico (FreeLunch/CheapLunch/resultantes) | **CERRADO** | ley D_I verificada; todas D_I-bound |
| Diferencial/lineal (wide-trail) | **CERRADO** | R\*_difflin=2 ≪ algebraico; acoplamiento no degrada |
| Capacidad del esponja | **CERRADO** | m=4; R=8 ⇒ ≥179-bit preimagen, 128 colisión |
| Coste vs Poseidon2 | **competitivo** | HADES 0.74× (R_f=4) |
| Escalado del motor (R≥4, D_I≳10⁵) | **abierto** | límite F4/FGLM (hardware) |
| Confirmación m>1 de rondas parciales | **abierto** | timeout de motor a m=2 |
| R_f mínimo seguro (ataques dedicados de parciales) | **abierto** | análisis dedicado pendiente |
| Goldilocks real (char 2⁶⁴) | **abierto** | ningún motor Gröbner lo alcanza |

Detalle de abiertos y qué haría falta para cerrarlos: [OPEN_PROBLEMS.md](OPEN_PROBLEMS.md).

## 6. Estado por afirmación

- **Verificado (medido, reproducible):** ley `D_I=7^(R·m)·m·2^(R-1)`; no-trampa;
  genericidad; density-independencia; biyectividad (exhaustiva 31⁴); resistencia a
  FreeLunch/CheapLunch/resultantes (D_I-bound); wide-trail (MDP/MLC, R\*_difflin=2);
  capacidad esponja (m=4); transferencia estructural (proxies 5–31 bits);
  parcial=completa para D_I a m=1.
- **Extrapolado (ω=2, de una ley verificada):** R\* (rondas seguras) y el coste vs
  Poseidon2 (incluido el 0.74× de HADES).
- **Abierto:** ver §5 y [OPEN_PROBLEMS.md](OPEN_PROBLEMS.md).

Ningún número de bits se declara "seguro" sin la etiqueta ω=2/extrapolado; los
timeouts se reportan como huecos, nunca como confirmación; la evidencia negativa se
conserva (ver [CRYPTANALYSIS.md](CRYPTANALYSIS.md) y [DECISION.md](DECISION.md)).
