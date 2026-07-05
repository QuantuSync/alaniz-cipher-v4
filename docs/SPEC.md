# SPEC — Alaniz-AO: permutación y hash-esponja orientados a aritmetización

**Estado:** instanciación concreta y reproducible (Bloque 4). Implementación:
`src/crypto/alaniz_ao.py`; test `tests/test_alaniz_ao.py`. Parámetros justificados
por las mediciones ([CRYPTANALYSIS.md](CRYPTANALYSIS.md), [WIDE_TRAIL.md](WIDE_TRAIL.md)).
**No** es un artefacto de despliegue (sin tiempo constante ni KAT de producto).

## 1. Parámetros

| símbolo | valor | justificación |
|---|---|---|
| p | 2⁶⁴−2³²+1 (Goldilocks) | cuerpo AO estándar; Poseidon2 de referencia sobre él |
| t (carriles) | 8 | rate 4 + capacidad 4 (256-bit ⇒ 128-bit colisión/preimagen esponja) |
| S-box | x⁷ | menor exponente biyectivo en Goldilocks (gcd(7,p−1)=1) |
| capa lineal | Cauchy MDS 8×8 | rama = t+1 = 9 (MDS); permite rondas parciales (palanca futura) |
| acoplamiento | mínimo tipo cadena: `x_v += c_v·x_{v−2}·x_{v−1}` (v≥2), a la ENTRADA | +1 bit grado CICO/ronda (verificado, genérico); cubre todos los carriles; t−2 mults/ronda |
| R (rondas) | 8 | ver §3 |
| constantes | PRG SHAKE-256 público, domain-separated | sin secreto en la permutación |

## 2. La permutación

Estado `x ∈ F_p^8`. Ronda `r`: `x ← M·SB(x) + rc^(r)`, con
`SB(x)_v = (x_v + Σ c·x_{v−2}·x_{v−1})^7` (acoplamiento solo para v≥2; v∈{0,1}
son `x_v^7`). Precede una suma de constante inicial. El acoplamiento es
**triangular** (cada v usa solo carriles anteriores) ⇒ la capa es **biyección** e
invertible carril a carril con una raíz 7-ésima; verificado por roundtrip y (a
escala pequeña) exhaustivamente. Esponja: absorción/exprimido con rate 4 y padding
inyectando un 1.

## 3. Contabilidad de seguridad y elección de R (honesta)

Rondas seguras = `max(R*_algebraico, R*_diff/lin)` + margen. Bajo el modelo de
coste **ω=2** (sparse-FGLM) y la ley **verificada** `D_I = 7^(R·m)·m·2^(R−1)`:

| flanco | cota | fuente |
|---|---|---|
| Diferencial/lineal | R*_difflin = **2** (rama MDS 9, MDP 2⁻⁶¹, MLC 2⁻²⁹) | [WIDE_TRAIL.md](WIDE_TRAIL.md) |
| Algebraico, CICO capacidad m=4 | R*_alg ≈ **6** (2·log₂ D_I ≥ 128) | experiment 07, ley verificada |
| Algebraico, CICO mínima m=1 (conservador) | R*_alg ≈ **18** | experiment 07 |

**R = 8** = R*_alg(m=4)=6 + ~33% de margen. Corresponde al ataque CICO que rompe
la **capacidad** del esponja (m = capacidad = 4 carriles), el relevante para
colisión/preimagen. **Honestidad sobre el convenio:** la cota más conservadora
(CICO mínima m=1, que no rompe el esponja de capacidad 4 pero acota la dureza de
la permutación) daría R*_alg=18 ⇒ R≈24; pinchar cuál CICO es el vinculante para un
uso concreto del esponja es **trabajo abierto**. Se documentan ambos; R=8 es la
instancia de investigación calibrada al ataque de capacidad.

## 4. Coste (R=8, t=8)

Por ronda: 8 S-boxes × 4 mults + 6 mults de acoplamiento = **38 mults**; la capa
MDS es gratis en R1CS. Total ≈ **8×38 = 304 restricciones R1CS** ≈ **1.30×
Poseidon2** (234). El acoplamiento a la entrada aporta el +1 bit/ronda verificado a
+6 mults/ronda; las **rondas parciales** (habilitadas por la capa MDS, aún sin
explotar) son la palanca para bajar de aquí.

## 5. STATUS

| afirmación | estado |
|---|---|
| Permutación biyectiva + inversa exacta | **verificado** (roundtrip; test) |
| Esponja determinista y sensible | **verificado** (test) |
| Ley D_I, no-trampa, resistencia FreeLunch/CheapLunch/resultantes | **verificado** (R≤3 + punto grande 9604; huecos R≥4 reportados) |
| R*_alg / R\* / coste | **extrapolado** (ω=2, ley verificada); convenio de capacidad **abierto** |
| Wide-trail (diferencial/lineal) | **verificado** (cotas S-box; método estándar) |

Reproducir: `python -c "import sys;sys.path.insert(0,'src');from crypto.alaniz_ao import sponge_hash;print(sponge_hash([1,2,3,4,5]))"` y `pytest -q`.
