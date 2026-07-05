# WSL_SETUP — estado de la instalación de WSL (handoff entre sesiones)

## Estado

**✅ WSL + MOTOR GRÖBNER OK (verificado Sesión 2, 2026-07-05).**

- ✅ **Ubuntu-24.04 (24.04.4 LTS), WSL2, estado Running**, kernel
  `6.18.33.2-microsoft-standard-WSL2`. Usuario Linux `lucas` creado.
- ✅ **msolve 0.6.5** instalado vía `apt` (paquete `msolve`, con `libflint18`).
- ✅ **Verificación funcional:**
  - Resolución sobre ℚ: sistema `{x²+y²−2, x−y}` → soluciones `x=y=±1` ✓.
  - **Base de Gröbner reducida sobre F_65521, orden grevlex**: sistema
    `{x²+y−3, y²+x−3}` → base `[y²+x−3, x²+y−3]` (2 elementos) ✓.
  - Esto es exactamente lo que necesita la suite FreeLunch/CheapLunch/resultantes.
- Invocación desde Windows: `wsl msolve -f <archivo> [-g 2]` (o
  `wsl -u root` para instalar paquetes sin pedir contraseña sudo).
- SageMath NO instalado (opcional, ~varios GB); msolve basta como motor F4.

### Historial Sesión 1 (2026-07-05, Windows 11 Pro build 26200)

Verificado por log elevado:

- ✅ **WSL núcleo 2.7.10** instalado (`Se ha instalado Subsistema de Windows para
  Linux 2.7.10`, exit 0).
- ✅ **VirtualMachinePlatform** habilitado (`los cambios se aplicarán tras
  reiniciar`).
- ✅ **Ubuntu** solicitado con `wsl --install -d Ubuntu --no-launch` (exit 0,
  aplica tras reiniciar). Aún no aparece en `wsl -l -v` porque todo el conjunto
  queda pendiente del reinicio.
- `CBS RebootPending: True` → **hay un reinicio pendiente**.

Nota: `wsl --install` directo (no elevado) FALLA cuando la shell corre SIN admin.
La instalación se hizo vía `Start-Process -Verb RunAs` (UAC aceptado por el
usuario) con salida a log.

### Pasos del usuario para completar (tras este punto)

1. **Reiniciar el ordenador** ahora.
2. Tras reiniciar, abrir **Ubuntu** (menú Inicio → "Ubuntu") o ejecutar `wsl` en
   una terminal. Aparecerá la creación de **usuario y contraseña** de Linux
   (apuntarlos; la contraseña NO se ve al teclear, es normal).
3. Si al arrancar Ubuntu/`wsl` sale un error de **virtualización** ("WSL2 no se
   puede iniciar porque la virtualización no está habilitada"), hay que **activar
   la virtualización (VT-x / AMD-V / SVM) en la BIOS/UEFI** del equipo y reiniciar.
   Ver https://aka.ms/enablevirtualization
4. Verificar: `wsl -l -v` debe listar Ubuntu en estado Running/Stopped, versión 2.

## Misión del proyecto

Desarrollar y fortalecer **un nuevo tipo de cifrado o solución criptográfica**,
hasta algo **fuerte o publicable** — una aportación científica honesta, no un
producto.

## Qué debe hacer la Sesión 2 (tras el reinicio) — pegar el **Prompt B**

1. **Verificar WSL:** `wsl -l -v` y `wsl --status` (debe aparecer Ubuntu). Si la
   ventana de Ubuntu pidió usuario/contraseña, confirmar que se creó.
2. **Instalar un motor Gröbner real dentro de WSL:** Sage (`sudo apt install
   sagemath`) o msolve (compilar / `apt`), que en Windows nativo estaban
   BLOQUEADOS. Verificar con un cálculo Gröbner pequeño.
3. **Seguir con el Prompt SPN:** analizar la nueva permutación AO SPN multi-ronda
   (ver resumen abajo) y atacarla con FreeLunch/CheapLunch/resultantes.

## Contexto (resumen de 5 líneas)

- La construcción anterior (acoplamiento por haz + σ de grado alto, 1 ronda) se
  **descartó**: A6-CICO la rompió (solving degree cúbico, independiente de e; ver
  `docs/CRYPTANALYSIS.md` y `docs/DECISION.md`).
- Ahora se explora una **permutación SPN** con **S-box biyectiva de grado bajo**
  (`x^d`) + **capa de mezcla** inspirada en la estructura de haces, con
  **parámetros públicos**, evaluada en **CICO**.
- Hay que atacarla con **FreeLunch (eprint 2024/347)**, **CheapLunch (2025/2040)**
  y **resultantes (2025/259, 2026/1281)**.
- Esos ataques necesitan un **motor Gröbner real (Sage/msolve)**, que solo es
  instalable en **WSL** (en Windows nativo estaba bloqueado; python-flint solo da
  álgebra lineal, no Gröbner con orden monomial).
- Backend actual sin WSL: `python-flint` (Macaulay/rango). Objetivo de WSL:
  desbloquear Gröbner F4/F5 para la fidelidad de la suite de ataques SPN.

## Notas de handoff

- Reproducibilidad y estado vivo: `docs/STATUS.md`. Ataques: `attacks/`.
  Reencuadre AO: `docs/AO_SPEC.md`.
- `pytest -q` verde (21 tests) al cierre de la Sesión 1.
