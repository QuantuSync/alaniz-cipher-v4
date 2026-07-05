# Alaniz Cipher — Plan de acción hacia una contribución científica publicable

> Documento vivo. Estado y decisiones se actualizan en `docs/STATUS.md`.
> Regla de oro (lección Langa): **atacar antes de publicar**. Ningún número de
> seguridad se escribe sin un experimento reproducible detrás, o etiquetado
> explícitamente como conjetura.

## 0. Restricción estructural que gobierna el diseño

El cifrado multivariante de clave pública requiere un **mapa central de grado 2**
para que el mapa público compuesto sea publicable. La σ de Alaniz es de **grado
alto (e)** — de ahí su seguridad, pero también la imposibilidad de publicar el
mapa α→c (grado 3e). Consecuencia: **no es viable una PKE multivariante estándar
con esta σ**. Los caminos viables son KEM/simétrico con asimetría propia, o
publicación de análisis. Toda decisión de diseño se toma con esta restricción en
mente.

## 1. Decisión de track (hacer en Fase 0, no saltarse)

| Track | Qué es | Riesgo | Certeza de publicación |
|-------|--------|--------|------------------------|
| **A — KEM/simétrico sobre NL-SMIP** | Primitiva con clave precompartida o KEM con asimetría nueva; cohomología de haces como estructura | Medio-alto | Media-alta si el criptoanálisis aguanta |
| **B — Paper de criptoanálisis / espacio de diseño** | El arco v1→Langa→v4: construcciones, ataques, lo que sobrevive y por qué | Bajo | Alta (los resultados negativos se publican) |
| **C — PKE novedosa** | Nueva asimetría no basada en publicar el mapa | Muy alto | Baja |

**Recomendación**: perseguir **A** como objetivo técnico, con **B** como
publicación garantizada construida con el mismo trabajo. **C** solo si en Fase 1
aparece una idea de asimetría genuinamente nueva y validada.

**Salida de Fase 0**: memo de decisión (`docs/DECISION.md`) fijando el track y el
enunciado del problema duro sobre *datos realmente públicos*.

---

## Fase 0 — Saneamiento y rigor (1–2 semanas)

Objetivo: que el repo diga la verdad y tenga una única implementación de referencia.

Tareas
- **Unificar σ y protocolo.** Hoy hay dos σ (una con β usada, otra sin β en
  `sigma.py` que nunca se aplica pero se documenta) y dos protocolos
  (`protocol_v4r3.py`, `protocol_v4r3_pq128.py`). Dejar **una** σ y **una** ruta
  de referencia; borrar o marcar `deprecated/` el resto. Eliminar
  `find_secure_exponent` duplicado.
- **Corregir pk/sk.** Reetiquetar según el track: si A/B, documentar que el
  cifrado usa clave (precompartida/KEM), sin afirmar clave pública. Reescribir
  `docs/DESIGN.md` para que coincida con el código.
- **Redefinir el problema duro (`docs/HARDNESS.md`).** El CSI/NL-SMIP debe
  enunciarse sobre lo que es público. Si β es secreto y necesario para cifrar,
  el "sistema de grado 3e en α con coeficientes conocidos" no es lo que ve el
  atacante: hay que incluir β como incógnita o reformular. Este es el punto que
  un revisor mirará primero.
- **Higiene de muestreo.** Sustituir `rng.integers(0, 2**62) % (p**d)` por
  muestreo uniforme por rechazo (evitar sesgo de módulo). Domain separation
  explícito en el PRG.
- **Alinear spec/impl.** `DESIGN` dice B_e, C_t ∈ M_d; el código usa
  `random_invertible_matrix` (GL). Decidir y documentar.
- **Infra reproducible.** Semillas fijas, `pytest` verde, CI (GitHub Actions),
  `make reproduce-all`.

Gate 0: un colega puede leer el repo y entender exactamente qué es público, qué
es secreto y qué problema hay que resolver para romperlo. Un `pytest` limpio.

---

## Fase 1 — Criptoanálisis propio (la fase más importante) (3–6 semanas)

Objetivo: intentar romperlo tú, con un arsenal de ataques, y documentar cada
resultado (rompe / no rompe). Carpeta `attacks/`, cada ataque numerado,
semilla fija, resultado volcado a `docs/CRYPTANALYSIS.md`.

- **A1 — Homogeneidad de escala (Langa Exp.10).** Test de regresión: verificar
  que σ(λy) ≠ λ^e σ(y) sigue siendo cierto (debe *fallar* el ataque = seguro).
- **A2 — Interpolación univariante.** Consultar c(t·e_j) para t=0..3e e interpolar.
  Ejecutar en dos regímenes: **nonce fresco** (defensa esperada) y **nonce
  reutilizado/fijo** (peor caso). Si con nonce fijo se recupera estructura de
  clave, documentar que IND-CPA depende críticamente de nonce fresco y argumentarlo.
- **A3 — Diferencial por columnas (Langa Exp.13)** adaptado a la σ vectorial.
- **A4 — MinRank** sobre el tensor trilineal C_t y bilineal B_e (recuperación de
  estructura de bajo rango).
- **A5 — Recuperación algebraica de β.** Montar el sistema con β como incógnitas
  y correr Gröbner (Sage/msolve/Magma) a d pequeño; medir si β cae y a qué coste.
  Este es el ataque que decide si el track A es viable.
- **A6 — Ataque directo F4/Gröbner** y **medición real de D_reg en d ∈ {4,6,8}**.
  Aquí vive o muere la afirmación de 147 bits: el "gap empírico" está extrapolado
  desde d≤3 y hay que validarlo o enterrarlo.
- **A7 — Distinguisher IND-CPA** e invariantes estructurales (rangos, colisiones
  de gᵦ, correlaciones inter-vértice como el ρ(v0,v3)=−0.38 marginal ya observado).

Entregable: `docs/CRYPTANALYSIS.md` con tabla ataque→resultado→coste, todo
reproducible.

Gate 1: ningún ataque recupera clave/mensaje por debajo de la seguridad
afirmada. **Si alguno rompe → volver a diseño (es una victoria: mejor tú que un
tribunal).**

---

## Fase 2 — Fundamentar la seguridad cuantitativa (3–5 semanas)

Objetivo: que cada bit afirmado sea trazable a un experimento o a una conjetura
etiquetada.

- Medir D_reg real en d ∈ {4,6,8}; extrapolar a d=12 **con intervalos**, no como
  hecho. Rehacer tablas de parámetros solo con números validados.
- Verificar semi-regularidad (o caracterizar sicigias) en Sage/Magma. Completar
  el e2e en d=12 (script Sage pendiente).
- Revisar el modelo cuántico (ω=2.0/1.5) contra literatura; ser conservador.
- Publicar una fe de erratas explícita respecto a v3/v4 (los 74 vs 128 bits, etc.).

Gate 2: `docs/SECURITY.md` reescrito separando **verificado** de **conjetura**.
Ninguna cifra huérfana.

---

## Fase 3 — Endurecer la construcción (según track) (4–8 semanas)

- **CCA/KEM**: transformada Fujisaki–Okamoto correctamente citada e implementada;
  re-encriptación determinista de verificación; vectores KAT.
- **Tiempo constante**: σ⁻¹ que enumera siempre el mismo número de raíces
  (padding), orden aleatorizado; eliminar cualquier canal por conteo de combos.
- **Disciplina de nonce/IV** y separación de dominios en todo el PRG.
- Rediseño de σ o del acoplamiento **solo si** Fase 1 lo exige.

Gate 3: tiempo constante verificado, KEM con CCA, KATs estables.

---

## Fase 4 — Reproducibilidad y auditoría externa (continua)

- Docker + `reproduce-all` de un comando; artefacto de reproducibilidad.
- **Criptoanálisis externo antes de someter.** Invitar a 2–3 revisores
  independientes (el modelo Langa). Publicar un ciphertext-reto abierto.
- Opcional: implementación C/Rust de referencia para credibilidad de rendimiento.

Gate 4: al menos una revisión externa seria registrada.

---

## Fase 5 — Redacción y publicación (4–6 semanas)

- **IACR ePrint primero** (en cripto, "publicable" = "sobrevive al criptoanálisis
  público"; hay que exponerlo y dejar un periodo de ataque).
- Estructura del paper: problema duro → construcción → análisis de dureza →
  **criptoanálisis propio** → parámetros validados → limitaciones → problemas
  abiertos.
- Venue: workshop/conferencia PQC o venue de criptoanálisis; journal después.
- Si track B: narrar el arco v1→Langa→v4 como estudio del espacio de diseño.

Gate 5: preprint en ePrint + repo reproducible enlazado.

---

## Principios transversales (no negociables)

1. **Nada se afirma sin experimento o sin etiqueta de conjetura.**
2. **Cada cambio de diseño trae su ataque correspondiente en `attacks/`.**
3. **Separar siempre "verificado" / "parcial" / "conjetura" / "abierto"** (ya lo
   haces en STATUS: mantenerlo religiosamente).
4. **Exposición pública temprana** (ePrint) e invitación explícita a romperlo.
5. **Rigor sobre madurez**: nunca "producción", nunca "seguro" sin años de
   análisis externo. Modo híbrido si algún día se despliega.

## Expectativa realista

Una PKE novedosa casi siempre se rompe (SFLASH, Rainbow, GeMSS… y la propia línea
de grafos con Langa). Las contribuciones más seguras aquí son: (a) el **problema
duro** bien planteado, (b) el **criptoanálisis**, (c) un **KEM/simétrico** bien
analizado. El plan está diseñado para que, gane o pierda el cifrado, salga una
aportación científica rigurosa y publicable.
