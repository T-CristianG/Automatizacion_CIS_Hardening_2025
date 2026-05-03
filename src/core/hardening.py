# core/hardening.py
"""
Funciones de aplicación de hardening CIS para Windows Server 2025 Level 1.
Cada función aplica un tipo específico de control de seguridad.
"""

from pathlib import Path
import re
from .helpers import run_ps


# ---------------------------------------------------------------------------
# Registro
# ---------------------------------------------------------------------------

def ensure_reg_path(path: str) -> None:
    """Crea la clave de registro si no existe."""
    ps = f'if (-not (Test-Path "{path}")) {{ New-Item -Path "{path}" -Force | Out-Null }}'
    run_ps(ps)


def set_reg_dword(path: str, name: str, value: int) -> tuple[bool, str]:
    """Establece un valor DWORD en el registro."""
    ensure_reg_path(path)
    ps = f'Set-ItemProperty -Path "{path}" -Name "{name}" -Value {int(value)} -Type DWord -Force'
    result = run_ps(ps)
    if result.startswith("ERROR:"):
        return False, result
    return True, f"OK Registro DWORD: {path}\\{name} = {value}"


def set_reg_sz(path: str, name: str, value: str) -> tuple[bool, str]:
    """Establece un valor String (SZ) en el registro."""
    ensure_reg_path(path)
    escaped = str(value).replace('"', '`"').replace("'", "`'")
    ps = f'Set-ItemProperty -Path "{path}" -Name "{name}" -Value "{escaped}" -Type String -Force'
    result = run_ps(ps)
    if result.startswith("ERROR:"):
        return False, result
    return True, f"OK Registro SZ: {path}\\{name} = {value}"


def set_reg_multisz(path: str, name: str, values: list) -> tuple[bool, str]:
    """Establece un valor MultiString en el registro."""
    ensure_reg_path(path)
    if not values:
        values_ps = "[string[]]@()"
    else:
        values_ps = "[string[]]@(" + ",".join(f'"{v}"' for v in values) + ")"
    ps = f'Set-ItemProperty -Path "{path}" -Name "{name}" -Value {values_ps} -Type MultiString -Force'
    result = run_ps(ps)
    if result.startswith("ERROR:"):
        return False, result
    return True, f"OK Registro MultiSZ: {path}\\{name} = {values}"


# ---------------------------------------------------------------------------
# Net Accounts (política de contraseñas y bloqueo)
# ---------------------------------------------------------------------------

def set_net_accounts(param: str, value) -> tuple[bool, str]:
    """Aplica un parámetro de net accounts."""
    result = run_ps(f'net accounts /{param}:{value}')
    if result.startswith("ERROR:"):
        return False, result
    return True, f"OK net accounts /{param}:{value}"


# ---------------------------------------------------------------------------
# Secedit (política de seguridad local)
# ---------------------------------------------------------------------------

def _apply_secedit_config(key: str, value: str, section: str) -> tuple[bool, str]:
    """
    Exporta la política de seguridad local, modifica un valor específico y reimporta.
    Funciona para [System Access], [Privilege Rights] y [Event Audit].
    """
    tmp_export = r"C:\Windows\Temp\cis_harden_exp.cfg"
    tmp_import = r"C:\Windows\Temp\cis_harden_imp.cfg"
    tmp_db     = r"C:\Windows\Temp\cis_harden.sdb"

    try:
        # Exportar política actual
        run_ps(f'secedit /export /cfg "{tmp_export}" /quiet')

        exp_path = Path(tmp_export)
        if exp_path.exists():
            try:
                content = exp_path.read_text(encoding="utf-16-le", errors="ignore")
            except Exception:
                content = exp_path.read_text(encoding="utf-8", errors="ignore")
        else:
            content = f"[Unicode]\r\nUnicode=yes\r\n\r\n[{section}]\r\n"

        lines = content.splitlines(keepends=True)
        new_lines = []
        found_key = False
        in_target_section = False
        section_header_idx = None

        for i, line in enumerate(lines):
            stripped = line.strip()

            if stripped.startswith("["):
                # Salir de la sección anterior sin haber encontrado la clave
                if in_target_section and not found_key:
                    new_lines.append(f"{key} = {value}\r\n")
                    found_key = True
                in_target_section = (section in stripped)
                if in_target_section:
                    section_header_idx = len(new_lines)
                new_lines.append(line)
                continue

            if in_target_section and re.match(rf"^\s*{re.escape(key)}\s*=", stripped):
                new_lines.append(f"{key} = {value}\r\n")
                found_key = True
            else:
                new_lines.append(line)

        # Si llegamos al final sin encontrar la sección/clave
        if not found_key:
            if in_target_section:
                new_lines.append(f"{key} = {value}\r\n")
            else:
                new_lines.append(f"\r\n[{section}]\r\n{key} = {value}\r\n")

        # Escribir cfg modificado
        imp_path = Path(tmp_import)
        imp_path.write_text("".join(new_lines), encoding="utf-16-le")

        # Importar y forzar actualización
        import_result = run_ps(
            f'secedit /configure /cfg "{tmp_import}" /db "{tmp_db}" /quiet /overwrite'
        )
        run_ps("gpupdate /force /quiet")

        # Limpieza
        for p in [tmp_export, tmp_import, tmp_db]:
            try:
                Path(p).unlink(missing_ok=True)
            except Exception:
                pass

        if import_result.startswith("ERROR:"):
            return False, import_result

        return True, f"OK secedit [{section}] {key} = {value}"

    except Exception as e:
        for p in [tmp_export, tmp_import, tmp_db]:
            try:
                Path(p).unlink(missing_ok=True)
            except Exception:
                pass
        return False, f"ERROR secedit: {str(e)}"


def set_secedit_value(key: str, value, section: str = "System Access") -> tuple[bool, str]:
    """Establece un valor en la sección [System Access] de la política local."""
    return _apply_secedit_config(str(key), str(value), section)


# ---------------------------------------------------------------------------
# Derechos de usuario (User Rights Assignment)
# ---------------------------------------------------------------------------

def set_user_right(right_name: str, sids_value: str) -> tuple[bool, str]:
    """
    Aplica un derecho de usuario via secedit.
    sids_value: string de SIDs separados por coma, p.ej. "*S-1-5-32-544,*S-1-5-19"
                o cadena vacía para "No One".
    """
    return _apply_secedit_config(right_name, sids_value, section="Privilege Rights")


# ---------------------------------------------------------------------------
# Política de auditoría (auditpol)
# ---------------------------------------------------------------------------

def set_audit_policy(
    subcategory_guid: str,
    success: bool = True,
    failure: bool = True
) -> tuple[bool, str]:
    """Aplica política de auditoría para una subcategoría."""
    s = "enable" if success else "disable"
    f = "enable" if failure else "disable"
    result = run_ps(
        f'auditpol /set /subcategory:"{subcategory_guid}" /success:{s} /failure:{f}'
    )
    if result.startswith("ERROR:"):
        return False, result
    return True, f"OK auditpol {subcategory_guid}: success={s} failure={f}"


# ---------------------------------------------------------------------------
# Firewall
# ---------------------------------------------------------------------------

def set_firewall_profile(profile: str, enabled: bool = True) -> tuple[bool, str]:
    """Habilita o deshabilita un perfil de firewall."""
    val = "True" if enabled else "False"
    result = run_ps(f'Set-NetFirewallProfile -Profile {profile} -Enabled {val}')
    if result.startswith("ERROR:"):
        return False, result
    return True, f"OK Firewall {profile} Enabled={val}"


# ---------------------------------------------------------------------------
# Cuenta Guest
# ---------------------------------------------------------------------------

def disable_guest_account() -> tuple[bool, str]:
    """Deshabilita la cuenta de invitado local."""
    result = run_ps(
        'try { Disable-LocalUser -Name "Guest" -ErrorAction Stop; "OK" } '
        'catch { net user guest /active:no }'
    )
    if result.startswith("ERROR:"):
        return False, result
    return True, "OK: Cuenta Guest deshabilitada"
