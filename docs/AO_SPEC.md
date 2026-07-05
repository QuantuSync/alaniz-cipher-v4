# AO_SPEC — Alaniz como primitiva orientada a aritmetización (AO)

**Estado:** borrador de trabajo (Fase 1, reencuadre AO). Ver [DECISION.md](DECISION.md).

Reencuadre confirmado: Alaniz se analiza como una **función/permutación sobre F_p**
evaluada por el problema **CICO** (constrained-input constrained-output), que es el
idioma de la criptografía orientada a aritmetización (ZK/SNARK, MPC, FHE). La
seguridad se mide por resistencia a Gröbner/resultantes sobre CICO; la eficiencia,
por multiplicaciones / restricciones R1CS-Plonk por evaluación.

## 1. Estado y capas

- **Estado:** `x ∈ F_p^{n·d}`, dividido en `n` bloques de vértice `x_v ∈ F_p^d`
  (`n = |V|`, `d` = grado de extensión; tetra ⇒ n=4). `ι : F_p^d ↔ F_{p^d}`.
- **Constantes de ronda:** `rc_v = PRG(nonce, "v", v) ∈ F_p^d` (dominio-separado,
  muestreo insesgado). Juegan el papel de round constants de una primitiva AO.

Una **ronda** `R = S ∘ (M + rc)` se compone de:

### 1a. Capa de mezcla `M` (acoplamiento por haz) — grado 3
Por vértice `v`:
```
arg_v(x) = A_v · x_v
         + Σ_{e=(u,v)∋v} B_e · ι⁻¹(ι(x_u)·ι(x_v))          (bilineal, grado 2)
         + Σ_{t=(a,v,b)∋v} C_t · ι⁻¹(ι(x_a)·ι(x_v)·ι(x_b))   (trilineal, grado 3)
```
A diferencia de una primitiva AO clásica (Poseidon/Griffin), la mezcla **no es
lineal**: es un polinomio de grado 3 dado por los tensores de estructura de F_{p^d}
y las matrices secretas `A, B, C`. Este es el rasgo distintivo (y el foco del
criptoanálisis: la dureza de recuperación de clave recae aquí, ver A5a).

### 1b. Capa S-box `S` (σ por vértice) — grado e
```
S(y)_v = σ_v(ι(y_v)) = β_v · ι(y_v) + (β_v − 1) · (L · ι(y_v) + 1)^e
```

> **Matiz crítico (honestidad):** σ_v **NO es una permutación** de F_{p^d}. El
> término potencia `(L·τ+1)^e` sí es biyección (afín ∘ potencia con `gcd(e,q−1)=1`),
> pero la suma `β·τ + (β−1)·(·)^e` rompe la inyectividad: el decryptor enumera en
> promedio ~2.1 raíces por vértice. Consecuencias:
> - La construcción **tal cual** es una **función**, no una permutación; una esponja
>   basada en permutación requeriría una S-box biyectiva.
> - La **S-box AO natural** aquí es la potencia pura `π_e(τ) = (L·τ+1)^e` (biyección,
>   grado algebraico e). Registramos ambas variantes; los ataques se corren contra
>   la σ implementada y, donde aplique, contra `π_e`.

## 2. Relación con el esquema actual (cifrado ⇒ una ronda restringida)

El cifrado actual es exactamente **una ronda** aplicada a una entrada restringida al
subespacio de secciones globales, con la máscara de nonce restada:
```
c = R(H₀·α) − r        (por bloques de vértice:  c_v = σ_v(arg_v(H₀α)+r_v) − r_v)
```
donde `H₀ ∈ F_p^{n·d × d}` es la base pública de H⁰ (subespacio de entrada de dim d).
Esto se verifica en `tests/test_ao.py::test_ao_forward_matches_encrypt`.

> **Nota:** el esquema tiene **una sola ronda**. Las primitivas AO suelen usar varias
> rondas para crecer el grado algebraico; aquí el grado ya es alto (e) en una ronda,
> a costa de multiplicaciones (ver §4). Si el análisis exige más rondas para
> seguridad, el coste AO sube proporcionalmente.

## 3. Problema CICO

Dada la función de ronda `R` (o su iterado), el problema **CICO** fija parte de la
entrada y parte de la salida y resuelve el resto:

> **CICO(R):** dados conjuntos de índices `I_in, I_out ⊆ {0,…,n·d−1}` y valores
> `u ∈ F_p^{|I_in|}`, `w ∈ F_p^{|I_out|}`, hallar `x ∈ F_p^{n·d}` con
> `x|_{I_in} = u` y `R(x)|_{I_out} = w`.

- **CICO-1:** una salida fijada (`|I_out| = 1` bloque/coordenada), resto libre.
- **CICO-2 / multi-salida:** varias salidas fijadas (dominio de CheapLunch).

**A6 como CICO (message-recovery):** la entrada está restringida al subespacio afín
`Im(H₀)` (equivalente a fijar `n·d − d` grados de libertad) y la salida está
totalmente fijada a `z* = c* + r` (`|I_out| = n·d`); las incógnitas son las `d`
coordenadas de `α`. Es un CICO fuertemente sobre-determinado. Implementado en
`src/crypto/ao_cico.py::build_cico_message_recovery`.

## 4. Dimensión de coste AO (a medir en Paso 4)

La métrica AO es multiplicaciones no lineales / restricciones R1CS-Plonk por
evaluación. Coste dominante por ronda:
- **S-box `σ_v`:** `(L·τ+1)^e` cuesta ~`⌈log₂ e⌉ + HW(e) − 1` multiplicaciones en
  F_{p^d} por vértice (square-and-multiply), y cada mult en F_{p^d} son ~`d²`
  mults en F_p ⇒ del orden de `n · (log e) · d²` mults F_p por ronda solo en S-box.
- **Mezcla `M`:** la parte trilineal aporta `O(l · d³)`-ish mults F_p (tensores).

Referencia competitiva: Poseidon2/Neptune ~228–240 restricciones por permutación.
La tensión central: `e` alto da grado algebraico (seguridad) pero infla las
restricciones. Se cuantifica en `attacks/`/`experiments/` y se juzga en Paso 4.

## 5. Qué se ataca (Paso 3)

Contra este modelo CICO: solving degree real (A6-CICO), FreeLunch (¿GB gratis bajo
algún orden?), CheapLunch (multi-salida), resultantes, recuperación de (A,B,C)
(A5b) y disciplina de nonce (A2). Resultados en [CRYPTANALYSIS.md](CRYPTANALYSIS.md).
