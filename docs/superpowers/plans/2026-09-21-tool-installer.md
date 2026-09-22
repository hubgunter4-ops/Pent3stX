# Instalador de herramientas y dependencias Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Añadir un flujo único y seguro para instalar las dependencias de ejecución y herramientas allowlisted de PentestX en Ubuntu/Kali/Fedora.

**Architecture:** Reutilizar la capa CLI existente, separar el mapa de paquetes base del mapa de perfiles de herramientas y ejecutar únicamente comandos construidos desde allowlists. El flujo requerirá `--confirm-tool-install` fuera de `--dry-run`, escribirá `installation_manifest.json` y mantendrá `--install-tools`/`--install-tool` compatibles.

**Tech Stack:** Python 3.11+, `argparse`, `subprocess`, `unittest`, gestores `apt-get`/`dnf`.

**Spec:** Solicitud del usuario: actualizar Pent3stX para una función de instalación de herramientas necesarias.

## Global Constraints

- Solo se permiten Ubuntu, Kali y Fedora.
- No se aceptan comandos, paquetes ni binarios arbitrarios desde argumentos o YAML.
- La instalación real requiere confirmación explícita; `--dry-run` nunca ejecuta gestores.
- Las acciones sobre targets y la instalación de dependencias permanecen separadas.

---

### Task 1: Añadir el flujo de dependencias base

**Files:**
- Modify: `pentestx.py`
- Test: `tests/test_installer.py`

- [ ] Añadir mapas allowlisted de paquetes runtime por distribución.
- [ ] Añadir `--install-dependencies` y conectarlo a `run()`.
- [ ] Hacer que el flujo incluya Python/Tkinter/coreutils/PyYAML y herramientas de sistema allowlisted.
- [ ] Mantener confirmación, `dry-run`, deduplicación y manifiesto.

### Task 2: Documentar el comando de instalación

**Files:**
- Modify: `README.md`
- Create: `.gitignore`

- [ ] Documentar el comando recomendado y sus variantes de simulación.
- [ ] Explicar que se usa `sudo` solo con confirmación y que no se instalan comandos arbitrarios.
- [ ] Ignorar workspace, cachés y entornos locales.

### Task 3: Validar y guardar el cambio

**Files:**
- Modify: `VALIDATION.md`

- [ ] Probar tests unitarios, compilación, ayuda y dry-run en las tres distribuciones.
- [ ] Revisar diff y ausencia de secretos/artefactos.
- [ ] Crear un commit atómico con mensaje `feat: add reproducible dependency installer`.

## Verification Commands

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile pentestx.py kk2_repaired.py pentestx_gui.py telemetry_sender.py
python3 pentestx.py --help
python3 pentestx.py --install-dependencies --distro ubuntu --confirm-tool-install --dry-run --no-color --no-animate
python3 pentestx.py --install-dependencies --distro kali --confirm-tool-install --dry-run --no-color --no-animate
python3 pentestx.py --install-dependencies --distro fedora --confirm-tool-install --dry-run --no-color --no-animate
```

## Self-review

- El cambio no ejecuta gestores durante `dry-run`.
- Los perfiles existentes siguen usando `--install-tools`.
- El nuevo comando no requiere target ni autorización de red.
- El manifiesto conserva la distribución solicitada, paquetes, herramientas y estado.
