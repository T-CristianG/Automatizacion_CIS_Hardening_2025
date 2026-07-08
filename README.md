¿Cómo ejecutar el módulo de Windows?
 1. Abrir PowerShell como Administrador

Pasos:

Presiona Tecla Windows, escribe PowerShell.

Haz clic derecho sobre "Windows PowerShell" y selecciona "Ejecutar como administrador" .

Confirma el permiso de Control de Cuentas de Usuario (UAC) si aparece.

 2. Navegar al directorio del proyecto
Usa el comando cd para moverte a la carpeta donde tienes el código (ejemplo genérico):

powershell
cd C:\Users\TuUsuario\Documentos\Automatizacion_CIS_Hardening_2025

 3. (Opcional pero recomendado) Configurar la política de ejecución
Como tu script ejecuta comandos de PowerShell desde Python, es posible que necesites permitir la ejecución de scripts locales. Para la sesión actual (recomendado):

powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process

 4. Ejecutar el programa
Una vez en la carpeta, usa el comando python seguido del nombre del archivo principal. Según tu código, el punto de entrada es main.py:

powershell
python main.py

 5. ¿Qué pasa después?
Al ejecutar python main.py, la aplicación:

Verifica permisos de administrador (como en tu código).

Carga las 341 reglas desde checks.py.

Ejecuta la auditoría mostrando el progreso en tiempo real.

Genera el reporte HTML en la carpeta actual con el nombre CIS_WS2025_L1_Report.html.
