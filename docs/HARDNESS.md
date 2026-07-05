# HARDNESS — El problema duro sobre datos públicos (NL-SMIP)

**Estado:** confirmado como enunciado de trabajo (Fase 0). Track A/B, esquema
**simétrico**, `A,B,C,β` secretos (ver [DECISION.md](DECISION.md)).

Este documento reemplaza la formulación previa de "CSI" en `SECURITY.md` y
`findings/CSI_AND_INDCPA.md`, que suponía un sistema público de grado 3e con
coeficientes conocidos. Esa suposición es **incorrecta**: los coeficientes
dependen de β (secreto), así que el atacante no posee ese sistema. Aquí se
reenuncia el problema sobre lo que es realmente público.

## 1. Qué es público y qué es secreto (según el código)

De `setup_pq128` / `keygen_pq128` / `encrypt_pq128`:

- **Público:** el 2-complejo `K = (V, E, T)`; los enteros `p, d, e`; el escalar
  `L ∈ F_q`; la base `H₀` de secciones globales del haz; el PRG y su separación de
  dominios; y cada par transmitido `(nonce, c)`.
- **Secreto (clave simétrica compartida):** las matrices `A_v, B_e, C_t ∈ M_d(F_p)`
  y los escalares `β_v ∈ F_q\{0,1}`. Son **necesarios tanto para cifrar como para
  descifrar** — de ahí que el esquema sea simétrico.

Consecuencia clave: en `c_v = σ_v(arg_v(α) + r_v) − r_v`, tanto `σ_v` (a través de
β_v) como `arg_v` (a través de A,B,C) tienen **coeficientes secretos**. El
adversario ve entradas/salidas, no el polinomio.

## 2. Recordatorio de la construcción (referencia: `protocol_v4r3_pq128.py`)

Para un mensaje `α ∈ F_p^d`:

- Sección: `s = H₀ · α`, con bloque por vértice `s_v ∈ F_p^d`.
- Argumento por vértice (grado 3 en α, coeficientes secretos):

  ```
  arg_v(α) = A_v · s_v
           + Σ_{e=(u,v)∋v} B_e · ι⁻¹(ι(s_u)·ι(s_v))
           + Σ_{t=(a,v,b)∋v} C_t · ι⁻¹(ι(s_a)·ι(s_v)·ι(s_b))
  ```

- Máscara: `r_v = PRG(nonce, "v", v) ∈ F_p^d`.
- σ por vértice (grado e, coeficiente secreto β_v):

  ```
  σ_v(τ) = β_v · τ + (β_v − 1) · (L·τ + 1)^e
  c_v = ι⁻¹( σ_v( ι(arg_v(α) + r_v) ) ) − r_v
  ```

## 3. El problema NL-SMIP

**NL-SMIP** (NonLinear Sheaf Multivariate Inversion Problem).

**Instancia pública:** `(K, p, d, e, L, H₀, {(nonce_i, c_i)}_i)`, donde cada
`c_i = Enc_key(α_i)` para una clave `key = (A, B, C, β)` fija desconocida y
mensajes `α_i` desconocidos.

Variantes:

- **NL-SMIP-KR (key-recovery).** Recuperar `key` (o un equivalente funcional que
  permita cifrar/descifrar) a partir de los pares observados. Modelo reforzado
  opcional: se conceden pares elegidos `(α, c)` (oráculo de cifrado); si el ataque
  falla con oráculo, el atacante real (sin oráculo) no lo tiene más fácil.
- **NL-SMIP-MR (message-recovery) / distinguishing.** Dado `(nonce, c)` recuperar
  `α`, o distinguir `Enc(α₀)` de `Enc(α₁)`, sin `key`.

## 4. Suposición de dureza (CONJETURA, no reducción)

> Sin `key`, resolver NL-SMIP requiere reconstruir simultáneamente la acción de σ
> (grado e, β desconocido) y el acoplamiento sheaf de grado 3 (A,B,C
> desconocidos). No se reduce a resolver un sistema de coeficientes conocidos.

**Regla de cuantificación.** Toda cota de coste (Bardet-Faugère u otra) debe
formularse sobre **el sistema que realmente ve el atacante** —con β y A,B,C como
incógnitas— y validarse experimentalmente antes de citar bits. Las cifras
heredadas (74/147/…) están **suspendidas** hasta rehacerse bajo esta regla
(ver `STATUS.md`).

Evidencia a favor / en contra: **pendiente de Fase 1.** Nada aquí es "verificado"
todavía.

## 5. Riesgos de diseño ya identificados (a atacar en Fase 1)

- **Homogeneidad de escala / colapso de β (H3).** El muestreo actual de β y L
  (`int(rng.integers(0,2**62)) % p^d`) sortea valores < 2⁶² en un campo de ~2³⁶⁶
  (d=6): β y L caen en un subconjunto casi-escalar `(a₀, a₁, 0,…)` con `a₁` diminuto.
  Esto es exactamente el tipo de debilidad de escala que hundió a Langa. → Ataque
  A1/A5. Debe corregirse con muestreo por rechazo sobre todo F_q antes de medir
  cualquier bit.
- **β casi-escalar ⇒ σ casi-lineal.** Si β ≈ escalar, σ_v pierde no linealidad
  efectiva. → distinguisher / interpolación (A2, A7).
- **A,B,C ∈ GL vs M_d.** El código restringe a GL_d; el spec decía M_d. Afecta al
  rango de los tensores B_e, C_t → relevante para MinRank (A4).

## 6. Bloqueadores abiertos (a decidir con evidencia, no por deseo)

1. ¿Puede el Track A publicar A,B,C sin reducir la dureza (habilitando una
   asimetría KEM), o deben permanecer secretas? Se decide con A4/A5 (Fase 1),
   no antes.
2. Reenunciar IND-CPA/IND-CCA en el modelo simétrico/KEM correcto (el juego PKE
   de `CSI_AND_INDCPA.md` no aplica y será reescrito).
