# OPEN_PROBLEMS — agenda de lo que queda abierto

Cada abierto con **qué es**, **por qué está abierto** y **qué haría falta para
cerrarlo**. Ninguno es evidencia en contra del resultado central; son límites de
motor/hardware o análisis pendientes. Ver [RESULTS.md](RESULTS.md) §5 para el
contexto y [STATUS.md](STATUS.md) para el estado por afirmación.

## 1. Escalado del motor Gröbner (R ≥ 4, D_I ≳ 10⁵)

- **Qué:** la ley `D_I = 7^(R·m)·m·2^(R-1)` está verificada en R∈{1,2,3} y en el
  punto grande (R=2,m=2)=9604. Los puntos con R≥4 (F4-bound por el nº de variables)
  y con D_I≳10⁵ (FGLM-bound) hacen **timeout** en msolve, incluso con 24 GB / 16
  hilos.
- **Por qué:** el F4 escala con el nº de variables (R·t) y el FGLM con D_I; ambos
  exceden un portátil.
- **Para cerrarlo:** más RAM/cores o un clúster; o un motor Gröbner con FGLM
  paralelo/masivo (p.ej. una máquina de 256+ GB), o Magma. No requiere idea nueva,
  solo hardware.

## 2. Confirmación a m > 1 de "ronda parcial = ronda completa" (HADES)

- **Qué:** que una ronda parcial multiplica D_I por ×14 igual que una completa está
  **verificado a m=1**. A m=2 (esponja) tanto D_I como el solving degree de las
  configuraciones con parciales hacen **timeout**.
- **Por qué:** los sistemas HADES a m=2 con rondas añadidas superan el motor.
- **Para cerrarlo:** el mismo hardware/motor del punto 1; o una derivación teórica
  del grado con rondas parciales a m>1 (el argumento de difusión MDS lo sugiere pero
  no lo mide).

## 3. R_f mínimo seguro frente a ataques dedicados de rondas parciales

- **Qué:** las rondas parciales pueden habilitar ataques dedicados que D_I no
  captura (lección Poseidon). El nº mínimo de rondas **completas** R_f que los
  previene **no está derivado**; se usa R_f=4 (moderado, ⇒ 0.74× Poseidon2) o R_f=6
  (conservador, ⇒ paridad).
- **Por qué:** requiere modelar los ataques específicos de la estructura parcial
  (invariant subspace, etc.), no solo el grado del ideal.
- **Para cerrarlo:** un análisis dedicado de ataques de rondas parciales sobre esta
  construcción (grado por carril, subespacios invariantes), como el que Poseidon2
  hace para fijar su R_f.

## 4. Sistema real sobre Goldilocks (característica 2⁶⁴)

- **Qué:** toda la medición Gröbner es sobre **primos proxy** (< 2³¹, límite de
  msolve). La transferencia a Goldilocks está **argumentada y apoyada** (D_I
  idéntico en proxies de 5–31 bits ⇒ estructural), pero el sistema real sobre
  Goldilocks no se ha corrido.
- **Por qué:** ningún motor Gröbner de código abierto acepta característica ≈ 2⁶⁴.
- **Para cerrarlo:** un motor con aritmética de campo grande (Magma, o msolve
  extendido), o formalizar la transferencia como teorema (independencia de la
  característica del grado del ideal para esta familia de sistemas).

## 5. Margen en resistencia a colisión (capacidad κ)

- **Qué:** con κ=4 (256-bit de capacidad) la colisión genérica queda **exactamente
  en 128 bits** (birthday), que cumple el objetivo de 128-bit pero sin margen por el
  lado genérico (el algebraico tiene 179).
- **Por qué:** es una elección de parámetro, no un fallo; 128=target.
- **Para cerrarlo (si se quiere margen):** subir la capacidad a κ=5 (320-bit ⇒
  160-bit colisión), a costa de 1 carril de rate; es un ajuste de spec, no
  investigación.

## 6. R\* y coste son extrapolaciones (ω = 2)

- **Qué:** las rondas seguras R\* y el coste vs Poseidon2 se derivan de la ley
  **verificada** aplicando el modelo de coste sparse-FGLM con exponente ω=2.
- **Por qué:** el coste real de un Gröbner a escala de seguridad no se puede correr;
  ω=2 es la hipótesis estándar (favorable al atacante).
- **Para cerrarlo:** consenso comunitario sobre ω para esta familia, o mediciones a
  mayor escala (punto 1) que anclen la constante.

---

Prioridad sugerida: **3** (R_f mínimo — es análisis, no hardware, y separa 0.74× de
paridad) y **1–2** (hardware, desbloquean varias verificaciones a la vez). **4–5–6**
son formalización o ajuste de parámetros.
