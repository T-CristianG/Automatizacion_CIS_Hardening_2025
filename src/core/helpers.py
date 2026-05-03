# helpers.py

import subprocess
import re
from pathlib import Path


# ---------- Helpers existentes ----------

def is_admin():
    """Check if script is running as administrator"""
    try:
        return subprocess.run(["net", "session"], capture_output=True).returncode == 0
    except Exception:
        return False


def run_ps(ps_command: str) -> str:
    """Run a PowerShell command and return stdout (strip)."""
    try:
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_command],
            capture_output=True, text=True, timeout=30
        )
        out = (completed.stdout or "").strip()
        err = (completed.stderr or "").strip()

        if completed.returncode != 0:
            return f"ERROR: {err or out or 'Unknown error'}"
        return out
    except subprocess.TimeoutExpired:
        return "ERROR: Timeout executing command"
    except Exception as e:
        return f"ERROR: {str(e)}"


def safe_int(value, default=None):
    """Safely convert to int"""
    try:
        return int(value) if value is not None else default
    except (ValueError, TypeError):
        return default


def normalize_registry_path(path):
    """
    Convierte rutas estilo PowerShell a rutas legibles por winreg.
    Ejemplos:
    HKLM:\\SOFTWARE\\...
    HKCU:\\SOFTWARE\\...
    """
    if not path:
        return path

    path = str(path).strip()

    mappings = {
        "HKLM:\\": "HKEY_LOCAL_MACHINE\\",
        "HKCU:\\": "HKEY_CURRENT_USER\\",
        "HKCR:\\": "HKEY_CLASSES_ROOT\\",
        "HKU:\\": "HKEY_USERS\\",
        "HKCC:\\": "HKEY_CURRENT_CONFIG\\",
        "HKLM:": "HKEY_LOCAL_MACHINE",
        "HKCU:": "HKEY_CURRENT_USER",
        "HKCR:": "HKEY_CLASSES_ROOT",
        "HKU:": "HKEY_USERS",
        "HKCC:": "HKEY_CURRENT_CONFIG",
    }

    for old, new in mappings.items():
        if path.startswith(old):
            path = path.replace(old, new, 1)
            break

    return path


def parse_net_accounts(label: str) -> int | None:
    """
    Parse value from `net accounts` output for a given label.
    Soporta español e inglés.
    """
    out = run_ps("net accounts")
    if out.startswith("ERROR:"):
        return None

    spanish_labels = {
        "Length of password history maintained": [
            "duración del historial de contraseñas",
            "historial de contraseñas"
        ],
        "Maximum password age (days)": [
            "duración máx. de contraseña (días)",
            "duración máxima de contraseña"
        ],
        "Minimum password length": [
            "longitud mínima de contraseña"
        ],
        "Lockout duration (minutes)": [
            "duración de bloqueo (minutos)"
        ],
        "Lockout threshold": [
            "umbral de bloqueo"
        ],
        "Lockout observation window (minutes)": [
            "ventana de obs. de bloqueo (minutos)",
            "ventana de observación de bloqueo"
        ]
    }

    search_terms = [label.lower()]
    if label in spanish_labels:
        search_terms.extend(spanish_labels[label])

    for line in out.splitlines():
        line_lower = line.lower()
        for term in search_terms:
            if term in line_lower:
                nums = re.findall(r"\d+", line)
                if nums:
                    return int(nums[0])
                if "ninguna" in line_lower or "none" in line_lower:
                    return 0
    return None


def get_secedit_value(key: str) -> str | None:
    """Export local security policy and return the value for `key`."""
    tmp = Path(r"C:\Windows\Temp\cis_secpol.txt")
    try:
        if tmp.exists():
            tmp.unlink()

        export_cmd = f'secedit /export /cfg "{tmp}" /quiet'
        result = run_ps(export_cmd)

        if result.startswith("ERROR:"):
            return None

        if tmp.exists():
            content = tmp.read_text(encoding="utf-16-le", errors="ignore")
            for line in content.splitlines():
                if line.strip().startswith(key):
                    parts = line.split("=", 1)
                    if len(parts) > 1:
                        value = parts[1].strip()
                        tmp.unlink()
                        return value
            tmp.unlink()

        return None

    except Exception:
        if tmp.exists():
            try:
                tmp.unlink()
            except Exception:
                pass
        return None


def _get_registry_hive_and_subkey(path):
    import winreg

    path = normalize_registry_path(path)

    hive_map = {
        "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
        "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
        "HKEY_CLASSES_ROOT": winreg.HKEY_CLASSES_ROOT,
        "HKEY_USERS": winreg.HKEY_USERS,
        "HKEY_CURRENT_CONFIG": winreg.HKEY_CURRENT_CONFIG,
    }

    hive_name, subkey = path.split("\\", 1)
    hive = hive_map[hive_name]
    return hive, subkey


def get_reg_dword(path, name):
    import winreg

    try:
        hive, subkey = _get_registry_hive_and_subkey(path)

        with winreg.OpenKey(hive, subkey) as key:
            value, regtype = winreg.QueryValueEx(key, name)

        if regtype == winreg.REG_DWORD:
            return value

        if regtype == winreg.REG_QWORD:
            return int(value)

        return None

    except Exception:
        return None


def get_reg_sz(path, name):
    import winreg

    try:
        hive, subkey = _get_registry_hive_and_subkey(path)

        with winreg.OpenKey(hive, subkey) as key:
            value, regtype = winreg.QueryValueEx(key, name)

        if regtype in (winreg.REG_SZ, winreg.REG_EXPAND_SZ):
            return str(value).strip()

        return None

    except Exception:
        return None


def get_reg_multisz(path, name):
    import winreg

    try:
        hive, subkey = _get_registry_hive_and_subkey(path)

        with winreg.OpenKey(hive, subkey) as key:
            value, regtype = winreg.QueryValueEx(key, name)

        if regtype == winreg.REG_MULTI_SZ:
            return value

        return None

    except Exception:
        return None


def get_firewall_profile_state(profile: str) -> bool | None:
    """Get firewall profile state"""
    ps = f'''
    $value = $null
    try {{
        $fw = Get-NetFirewallProfile -Profile {profile} -ErrorAction SilentlyContinue
        if ($fw) {{ $value = $fw.Enabled }}
    }} catch {{ }}
    $value
    '''
    result = run_ps(ps)

    if not result or result.startswith("ERROR:"):
        return None

    result = result.strip().lower()
    if result == "true":
        return True
    if result == "false":
        return False
    return None


def get_user_right(right_name: str) -> str:
    """
    Obtiene los SIDs asignados a un derecho de usuario.

    ESTRATEGIA:
    1. Lee GptTmpl.inf via PowerShell (Get-Content maneja UTF-16 BOM correctamente).
       Este archivo contiene EXACTAMENTE lo que configuraste en gpedit.msc,
       incluyendo S-1-5-90-0 (Window Manager Group) que secedit NO exporta.
    2. Fallback a secedit /export si GptTmpl.inf no existe o no tiene la clave.

    POR QUÉ secedit FALLA:
       secedit /export /areas USER_RIGHTS lee la base de datos local de seguridad
       que contiene los DEFAULTS de Windows (Users, Backup Operators, etc.),
       no los valores que configuraste en la GPO local.
    """
    gptmpl = r"C:\Windows\System32\GroupPolicy\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"

    # PowerShell Get-Content maneja UTF-16 con BOM automáticamente
    ps = (
        f'$f = "{gptmpl}"\n'
        'if (Test-Path $f) {\n'
        '    $lines = Get-Content $f\n'
        f'    $match = $lines | Where-Object {{ $_ -match "^{right_name}\\s*=" }}\n'
        '    if ($match) {\n'
        '        ($match -split "=", 2)[1].Trim()\n'
        '    }\n'
        '}\n'
    )
    result = run_ps(ps)

    if result and not result.startswith("ERROR:") and result.strip():
        return re.sub(r",\s+", ",", result.strip())

    # --- Fallback: secedit export ---
    tmp = Path(r"C:\Windows\Temp\cis_userrights.txt")
    try:
        if tmp.exists():
            tmp.unlink()

        export_cmd = f'secedit /export /cfg "{tmp}" /areas USER_RIGHTS /quiet'
        result = run_ps(export_cmd)

        if result.startswith("ERROR:"):
            return ""

        if tmp.exists():
            content = tmp.read_text(encoding="utf-16-le", errors="ignore")
            for line in content.splitlines():
                line = line.strip()
                if line.startswith(right_name):
                    parts = line.split("=", 1)
                    if len(parts) > 1:
                        value = parts[1].strip()
                        value = re.sub(r",\s+", ",", value)
                        tmp.unlink()
                        return value
            tmp.unlink()

        return ""

    except Exception as e:
        if tmp.exists():
            try:
                tmp.unlink()
            except Exception:
                pass
        return f"ERROR: {str(e)}"


def get_security_option(policy_name: str):
    """Get security option value from registry."""
    security_option_map = {
        "EnableGuestAccount": {
            "path": r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "name": "EnableGuestAccount",
            "type": "dword"
        },
        "LimitBlankPasswordUse": {
            "path": r"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa",
            "name": "LimitBlankPasswordUse",
            "type": "dword"
        },
        "NewAdministratorName": {
            "path": r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "name": "NewAdministratorName",
            "type": "sz"
        },
        "NewGuestName": {
            "path": r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "name": "NewGuestName",
            "type": "sz"
        }
    }

    if policy_name not in security_option_map:
        return None

    config = security_option_map[policy_name]

    if config["type"] == "dword":
        return get_reg_dword(config["path"], config["name"])
    elif config["type"] == "sz":
        return get_reg_sz(config["path"], config["name"])

    return None


SID_NAME_MAP: dict[str, str] = {
    "S-1-5-32-544": "Administrators",
    "S-1-5-32-545": "Users",
    "S-1-5-32-546": "Guests",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-114": "Local account and member of Administrators group",
    "S-1-5-113": "Local account",
    "S-1-5-19": "LOCAL SERVICE",
    "S-1-5-20": "NETWORK SERVICE",
    "S-1-5-6": "SERVICE",
    "S-1-5-83-0": "NT VIRTUAL MACHINE\\Virtual Machines",
    "S-1-5-32-568": "IIS_IUSRS",
    "S-1-5-90-0": "Window Manager\\Window Manager Group",
    "S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420": "NT SERVICE\\WdiServiceHost",
}


def sids_to_names(text) -> str:
    """Convierte una cadena de SIDs en nombres legibles."""
    if text is None:
        return ""
    if not isinstance(text, str):
        text = str(text)
    if "S-1-" not in text:
        return text

    parts = [p.strip() for p in text.split(",") if p.strip()]
    translated = []

    for part in parts:
        sid = part.lstrip("*").strip()
        name = SID_NAME_MAP.get(sid, sid)
        translated.append(name)

    return ", ".join(translated)


def get_auditpol_subcategory(subcategory_guid: str) -> int | None:
    """Devuelve el valor de auditoría para una subcategoría."""
    out = run_ps(f'auditpol /get /subcategory:"{subcategory_guid}" /r')
    if not out or out.startswith("ERROR:"):
        return None

    text = out.lower()

    if "success and failure" in text or "éxito y error" in text or "exito y error" in text:
        return 3
    if "success" in text or "éxito" in text or "exito" in text:
        return 1
    if "failure" in text or "error" in text or "fallo" in text:
        return 2
    if "no auditing" in text or "sin auditoría" in text or "sin auditoria" in text:
        return 0

    nums = re.findall(r"\d+", out)
    if nums:
        return safe_int(nums[0])

    return None


def get_guest_account_status() -> str:
    """
    Consulta el estado de la cuenta de invitado local.
    Retorna:
        "Enabled" si la cuenta está habilitada
        "Disabled" si está deshabilitada
        "Not Found" si la cuenta no existe
        "Unknown" en cualquier otro caso
    """
    ps_command = """
    try {
        $user = Get-LocalUser -Name "Guest" -ErrorAction Stop
        if ($user.Enabled) {
            "Enabled"
        } else {
            "Disabled"
        }
    } catch {
        "Not Found"
    }
    """

    result = run_ps(ps_command)
    if result in ("Enabled", "Disabled", "Not Found"):
        return result

    return "Unknown"