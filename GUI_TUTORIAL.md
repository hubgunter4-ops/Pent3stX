# Tutorial de PentestX GUI

## 1. Propósito

`pentestx_gui.py` es una interfaz de escritorio local construida con **Tkinter/ttk**. Presenta visualmente el planificador de PentestX y delega la validación de target, alcance, autorización, perfiles, límites y generación de evidencia en `pentestx.py`. No abre un servidor web, no modifica `kk2_repaired.py` y no ejecuta nada en segundo plano después de cerrar la ventana.

La interfaz está pensada para operadores que necesitan revisar un plan antes de iniciar una evaluación autorizada. El diseño usa una jerarquía de cuatro bloques: **alcance**, **fases**, **parámetros** y **consola de ejecución**.

## 2. Instalación y arranque

En Kali o en una distribución con Python 3 y Tkinter:

```bash
sudo apt update
sudo apt install -y python3 python3-tk
cd /ruta/al/repositorio
python3 pentestx_gui.py
```

La GUI no requiere paquetes Python adicionales para funcionar. `PyYAML` continúa siendo opcional y solo se necesita para cargar políticas YAML.

## 3. Flujo recomendado: primero dry-run

1. Escribe un **Target** que controles o que esté incluido en una autorización escrita.
2. Selecciona `passive` para comenzar sin tráfico activo o `active` si el alcance aprobado lo permite.
3. Marca las fases necesarias. Si no se marca ninguna, la interfaz usa `passive` como valor seguro.
4. Deja activado **Modo dry-run**.
5. Pulsa **Previsualizar plan**.
6. Revisa la consola. El comando mostrado incluye `--dry-run`; PentestX debe generar un manifiesto local sin ejecutar acciones ni tráfico de red.
7. Revisa el workspace indicado y conserva únicamente la evidencia que corresponda a las reglas de compromiso.

El botón **Ejecutar plan** también mantiene `dry-run` mientras esa casilla esté activa. Para una ejecución real hay que desactivar la casilla, marcar la declaración de autorización y aceptar la confirmación adicional que muestra la interfaz.

## 4. Configuración de fases

Las fases disponibles son las acciones soportadas por la CLI: reconocimiento pasivo/activo, enumeración web, puertos, vulnerabilidades, revisión OWASP, revisión de findings, correlación, reporte, escaneo intrusivo controlado, perfiles allowlisted y pipelines correlacionados. Los parámetros de pipeline, perfil OWASP, perfil de herramienta, findings y exclusiones se pasan a la capa CLI sin reimplementar su lógica.

Para un pipeline correlacionado, selecciona `correlated` y elige `standard`, `with_intrusive`, `with_owasp` o `full_web`. Para `intrusive`, deja `auto` salvo que el propietario del alcance haya aprobado un perfil explícito. Los campos de puertos, tasa y timeout respetan las validaciones y los topes de `pentestx.py`.

## 5. Evidencia y resultados

La consola muestra stdout y stderr combinados del proceso. Los artefactos se escriben bajo el workspace configurado, incluyendo manifiestos de sesión, findings, capturas hashadas y reportes cuando la fase correspondiente se ejecuta. El código de salida aparece en la etiqueta de estado superior.

No interpretes un resultado `dry-run` como evidencia de una vulnerabilidad: es únicamente una comprobación de argumentos y plan. Los findings generados por la revisión basada en evidencia siguen requiriendo revisión manual.

## 6. Comprobación local sin tocar la red

```bash
python3 -m py_compile pentestx_gui.py pentestx.py kk2_repaired.py
printf 'q\n' | python3 pentestx.py --interactive --no-animate --no-color
python3 pentestx.py --target example.com --scope passive \
  --action passive correlate report \
  --confirm-written-authorization --dry-run
```

Para verificar la interfaz en una sesión gráfica, arráncala y usa un target de documentación como `example.com` con dry-run. El dry-run no resuelve el target ni contacta Internet.

## 7. Resolución de problemas

Si Python informa que no existe `tkinter`, instala el paquete del sistema `python3-tk`. Si una fase rechaza la operación, lee el mensaje de la consola: la interfaz no omite las restricciones de la CLI. Si un perfil YAML no carga, valida primero su sintaxis con `yaml.safe_load` y confirma que las claves estén dentro de las allowlists documentadas.

Usa únicamente targets propios o expresamente autorizados. No introduzcas credenciales, cookies, secretos ni datos de producción en los campos de la GUI o en archivos de evidencia.
