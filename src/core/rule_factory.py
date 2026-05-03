# rule_factory.py

from .rule_engine import Rule
from .helpers import (
    parse_net_accounts,
    get_secedit_value,
    get_reg_dword,
    get_firewall_profile_state,
    get_user_right,
    get_security_option,
    safe_int,
    get_reg_multisz,
    get_reg_sz,
    get_auditpol_subcategory,
    get_guest_account_status,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def resolve_registry_target(check_params):
    """
    Soporta estas variantes:
    1. path + name
    2. hive + path + value_name
    3. evidence estilo HKLM\\...:Valor
    """
    path = check_params.get("path")
    name = check_params.get("name")

    if not name and "value_name" in check_params:
        name = check_params.get("value_name")

    if path and name:
        hive = check_params.get("hive")
        if hive and not path.startswith("HK"):
            if not hive.endswith(":"):
                hive = hive + ":"
            path = f"{hive}\\{path}"
        return path, name

    evidence = check_params.get("evidence")
    if evidence and ":" in evidence and "\\" in evidence:
        root_and_sub, value_name = evidence.split(":", 1)
        root_and_sub = root_and_sub.strip()
        value_name = value_name.strip()
        if "\\" in root_and_sub:
            hive, subkey = root_and_sub.split("\\", 1)
            hive = hive.strip()
            subkey = subkey.strip()
            if not hive.endswith(":"):
                hive = hive + ":"
            path = f"{hive}\\{subkey}"
            return path, value_name

    return None, None


# ---------------------------------------------------------------------------
# Mapa de net accounts
# ---------------------------------------------------------------------------

_NET_FIELD_MAP = {
    "Length of password history maintained": ("uniquepw",         24),
    "Maximum password age (days)":           ("maxpwage",        365),
    "Minimum password age (days)":           ("minpwage",          1),
    "Minimum password length":               ("minpwlen",         14),
    "Lockout duration (minutes)":            ("lockoutduration",  15),
    "Lockout threshold":                     ("lockoutthreshold",  5),
    "Lockout observation window (minutes)":  ("lockoutwindow",    15),
}


def _net_target_from_expected(field: str, expected: str) -> int:
    """Calcula el valor objetivo de net accounts a partir del string 'expected'."""
    _, default = _NET_FIELD_MAP.get(field, ("", 0))
    if expected.startswith(">="):
        return int(expected[2:].strip())
    if ".." in expected:
        min_v, max_v = map(int, expected.split(".."))
        # Para umbral de bloqueo y edad máxima: usar máximo (más permisivo, pero cumple)
        if "threshold" in field.lower() or "maximum" in field.lower() or "age" in field.lower():
            return max_v
        return min_v
    return default


# ---------------------------------------------------------------------------
# Mapa security_option → registro
# ---------------------------------------------------------------------------

_SECURITY_OPTION_REGISTRY = {
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


# ---------------------------------------------------------------------------
# Factory de remediación (devuelve un callable o None)
# ---------------------------------------------------------------------------

def _make_remediate_fn(check_type: str, check_params: dict, expected: str):
    """
    Construye y devuelve una función de remediación basada en el tipo de control.
    Retorna None si no hay remediación automatizada.
    """
    # Importación tardía para evitar importación circular en el paquete
    from .hardening import (
        set_reg_dword, set_reg_sz, set_reg_multisz,
        set_net_accounts, set_secedit_value, set_user_right,
        set_audit_policy, set_firewall_profile, disable_guest_account,
    )

    # ------------------------------------------------------------------
    if check_type in ("registry", "user_registry"):
        path, name = resolve_registry_target(check_params)
        if not path or not name:
            return None

        # Determinar valor objetivo
        if "allowed_values" in check_params:
            target = check_params["allowed_values"][0]
        elif "expected_value" in check_params:
            ev = check_params["expected_value"]
            target = ev if isinstance(ev, int) else safe_int(ev)
            if target is None:
                return None
        else:
            mode = check_params.get("expected_mode")
            if mode == "min_int":
                target = check_params.get("min_value")
            elif mode == "max_int":
                target = check_params.get("max_value")
            elif mode == "range_int":
                target = check_params.get("min_value")
            else:
                ev_str = str(check_params.get("expected_value", "")).strip()
                if ".." in ev_str:
                    target = int(ev_str.split("..")[0])
                else:
                    target = safe_int(ev_str)
            if target is None:
                return None

        _path, _name, _target = path, name, int(target)

        def _rem_registry():
            return set_reg_dword(_path, _name, _target)
        return _rem_registry

    # ------------------------------------------------------------------
    elif check_type == "net_accounts":
        field = check_params.get("field", "")
        if field not in _NET_FIELD_MAP:
            return None
        param, _ = _NET_FIELD_MAP[field]
        target_val = _net_target_from_expected(field, expected)
        _param, _val = param, target_val

        def _rem_net():
            return set_net_accounts(_param, _val)
        return _rem_net

    # ------------------------------------------------------------------
    elif check_type == "secedit":
        key = check_params.get("key")
        ev  = check_params.get("expected_value")
        if key is None or ev is None:
            return None
        _key, _val = key, ev

        def _rem_secedit():
            return set_secedit_value(_key, _val)
        return _rem_secedit

    # ------------------------------------------------------------------
    elif check_type == "user_right":
        right = check_params.get("right_name")
        sids  = check_params.get("expected_value", "")
        if not right:
            return None
        _right, _sids = right, sids

        def _rem_user_right():
            return set_user_right(_right, _sids)
        return _rem_user_right

    # ------------------------------------------------------------------
    elif check_type == "auditpol":
        guid = check_params.get("subcategory_guid")
        if not guid:
            return None

        allowed = check_params.get("allowed_values", [])
        base_ev = check_params.get("expected_value", 3)

        # Usar el valor de auditoría más completo disponible
        target_audit = max(allowed) if allowed else base_ev
        success_en = int(target_audit) in (1, 3)
        failure_en = int(target_audit) in (2, 3)

        _guid, _s, _f = guid, success_en, failure_en

        def _rem_audit():
            return set_audit_policy(_guid, _s, _f)
        return _rem_audit

    # ------------------------------------------------------------------
    elif check_type == "firewall":
        profile = check_params.get("profile")
        ev      = check_params.get("expected_value", True)
        if not profile:
            return None
        _profile, _ev = profile, ev

        def _rem_fw():
            return set_firewall_profile(_profile, _ev)
        return _rem_fw

    # ------------------------------------------------------------------
    elif check_type == "registry_sz":
        path = check_params.get("path")
        name = check_params.get("name")
        if not path or not name:
            return None

        mode = check_params.get("expected_mode", "exact_str")
        if mode == "exact_str":
            target_val = str(check_params.get("expected_value", ""))
            _path, _name, _tv = path, name, target_val

            def _rem_reg_sz():
                return set_reg_sz(_path, _name, _tv)
            return _rem_reg_sz
        else:
            # Para min_int / max_int / range_int en SZ, convertimos a DWORD
            if mode == "min_int":
                t = check_params.get("min_value", 0)
            elif mode == "max_int":
                t = check_params.get("max_value", 0)
            elif mode == "range_int":
                t = check_params.get("min_value", 0)
            else:
                return None
            _path, _name, _t = path, name, t

            def _rem_reg_sz_int():
                from .hardening import set_reg_dword as _srd
                return _srd(_path, _name, _t)
            return _rem_reg_sz_int

    # ------------------------------------------------------------------
    elif check_type == "registry_multisz":
        path = check_params.get("path")
        name = check_params.get("name")
        if not path or not name:
            return None
        allowed_sets = check_params.get("allowed_sets", [[]])
        target_values = allowed_sets[0] if allowed_sets else []
        _path, _name, _vals = path, name, target_values

        def _rem_multisz():
            return set_reg_multisz(_path, _name, _vals)
        return _rem_multisz

    # ------------------------------------------------------------------
    elif check_type == "registry_range":
        path = check_params.get("path")
        name = check_params.get("name")
        if not path or not name:
            return None
        min_val  = check_params.get("min_val")
        max_val  = check_params.get("max_val")
        disallow = check_params.get("disallow", [])

        if min_val is not None:
            target = min_val
        elif max_val is not None:
            target = max_val
        else:
            return None

        if target in disallow:
            target = (max_val if max_val is not None else min_val + 1)

        _path, _name, _target = path, name, int(target)

        def _rem_reg_range():
            return set_reg_dword(_path, _name, _target)
        return _rem_reg_range

    # ------------------------------------------------------------------
    elif check_type == "security_option":
        policy_name = check_params.get("policy_name")
        ev          = check_params.get("expected_value")
        if not policy_name or policy_name not in _SECURITY_OPTION_REGISTRY:
            return None

        cfg = _SECURITY_OPTION_REGISTRY[policy_name]
        _path, _name, _typ, _ev = cfg["path"], cfg["name"], cfg["type"], ev

        def _rem_sec_opt():
            if _typ == "dword":
                return set_reg_dword(_path, _name, int(_ev))
            return set_reg_sz(_path, _name, str(_ev))
        return _rem_sec_opt

    # ------------------------------------------------------------------
    elif check_type == "guest_account_status":
        _exp = expected.lower()

        def _rem_guest():
            if _exp == "disabled":
                return disable_guest_account()
            return False, "Habilitación de Guest no se automatiza por seguridad"
        return _rem_guest

    # ------------------------------------------------------------------
    # manual, unknown → sin remediación
    return None


# ---------------------------------------------------------------------------
# Factory principal
# ---------------------------------------------------------------------------

def create_rule(cis_id, title, expected, check_type, check_params):
    """Factory para crear reglas estandarizadas con auditoría y remediación."""

    # ------------------------------------------------------------------ net_accounts
    if check_type == "net_accounts":
        def check():
            value = parse_net_accounts(check_params["field"])
            if expected.startswith(">="):
                min_val = int(expected[2:])
                return value, value is not None and value >= min_val
            elif ".." in expected:
                min_val, max_val = map(int, expected.split(".."))
                return value, value is not None and min_val <= value <= max_val
            return value, False

        return Rule(
            cis_id, title, expected, check, "net accounts",
            remediate_fn=_make_remediate_fn(check_type, check_params, expected)
        )

    # ------------------------------------------------------------------ secedit
    elif check_type == "secedit":
        def check():
            value = get_secedit_value(check_params["key"])
            expected_value = check_params["expected_value"]
            current_int = safe_int(value, -1)
            return value, current_int == expected_value

        return Rule(
            cis_id, title, expected, check, "secedit export",
            remediate_fn=_make_remediate_fn(check_type, check_params, expected)
        )

    # ------------------------------------------------------------------ registry
    elif check_type == "registry":
        path, name = resolve_registry_target(check_params)

        if not path or not name:
            def check():
                return "INVALID_REGISTRY_PARAMS", False
            return Rule(cis_id, title, expected, check, check_params.get("evidence", "registry"))

        evidence = check_params.get("evidence", f"{path}:{name}")

        def check():
            value = get_reg_dword(path, name)

            if value is None:
                sz_val = get_reg_sz(path, name)
                sz_int = safe_int(sz_val, None)
                if sz_int is not None:
                    value = sz_int

            if value is None and check_params.get("missing_is_compliant", False):
                return "Not configured (default)", True

            if "allowed_values" in check_params:
                allowed = tuple(check_params["allowed_values"])
                return value, value is not None and value in allowed

            mode = check_params.get("expected_mode")
            if mode == "max_int":
                max_value = check_params["max_value"]
                current_int = safe_int(value, None)
                return value, current_int is not None and current_int <= max_value
            elif mode == "min_int":
                min_value = check_params["min_value"]
                current_int = safe_int(value, None)
                return value, current_int is not None and current_int >= min_value
            elif mode == "range_int":
                min_value = check_params["min_value"]
                max_value = check_params["max_value"]
                current_int = safe_int(value, None)
                return value, current_int is not None and min_value <= current_int <= max_value
            elif check_params.get("validation_type") == "range":
                current_int = safe_int(value, None)
                expected_value = str(check_params.get("expected_value", "")).strip()
                if ".." in expected_value:
                    min_val, max_val = map(int, expected_value.split(".."))
                    return value, current_int is not None and min_val <= current_int <= max_val
                return value, False

            expected_value = check_params["expected_value"]
            return value, value == expected_value

        return Rule(
            cis_id, title, expected, check, evidence,
            remediate_fn=_make_remediate_fn(check_type, check_params, expected)
        )

    # ------------------------------------------------------------------ user_registry
    elif check_type == "user_registry":
        path, name = resolve_registry_target(check_params)

        if not path or not name:
            def check():
                return "INVALID_USER_REGISTRY_PARAMS", False
            return Rule(cis_id, title, expected, check, check_params.get("evidence", "user_registry"))

        evidence = check_params.get("evidence", f"{path}:{name}")

        def check():
            value = get_reg_dword(path, name)
            if value is None:
                sz_val = get_reg_sz(path, name)
                sz_int = safe_int(sz_val, None)
                if sz_int is not None:
                    value = sz_int
            if value is None and check_params.get("missing_is_compliant", False):
                return "Not configured (default)", True
            if "allowed_values" in check_params:
                allowed = tuple(check_params["allowed_values"])
                return value, value is not None and value in allowed
            mode = check_params.get("expected_mode")
            if mode == "max_int":
                max_value = check_params["max_value"]
                current_int = safe_int(value, None)
                return value, current_int is not None and current_int <= max_value
            elif mode == "min_int":
                min_value = check_params["min_value"]
                current_int = safe_int(value, None)
                return value, current_int is not None and current_int >= min_value
            elif mode == "range_int":
                min_value = check_params["min_value"]
                max_value = check_params["max_value"]
                current_int = safe_int(value, None)
                return value, current_int is not None and min_value <= current_int <= max_value
            elif check_params.get("validation_type") == "range":
                current_int = safe_int(value, None)
                expected_value = str(check_params.get("expected_value", "")).strip()
                if ".." in expected_value:
                    min_val, max_val = map(int, expected_value.split(".."))
                    return value, current_int is not None and min_val <= current_int <= max_val
                return value, False
            expected_value = check_params["expected_value"]
            return value, value == expected_value

        return Rule(
            cis_id, title, expected, check, evidence,
            remediate_fn=_make_remediate_fn(check_type, check_params, expected)
        )

    # ------------------------------------------------------------------ firewall
    elif check_type == "firewall":
        def check():
            value = get_firewall_profile_state(check_params["profile"])
            expected_value = check_params["expected_value"]
            return value, value == expected_value

        return Rule(
            cis_id, title, expected, check,
            f"Get-NetFirewallProfile {check_params['profile']}",
            remediate_fn=_make_remediate_fn(check_type, check_params, expected)
        )

    # ------------------------------------------------------------------ user_right
    elif check_type == "user_right":
        def check():
            value = get_user_right(check_params["right_name"])
            expected_value = check_params["expected_value"]
            if expected_value == "":
                passed = value == "" or value is None
                return value, passed
            current_sids  = set(sid.strip() for sid in value.split(',')) if value else set()
            expected_sids = set(sid.strip() for sid in expected_value.split(','))
            return value, current_sids == expected_sids

        return Rule(
            cis_id, title, expected, check, check_params["evidence"],
            remediate_fn=_make_remediate_fn(check_type, check_params, expected)
        )

    # ------------------------------------------------------------------ auditpol
    elif check_type == "auditpol":
        def check():
            value = get_auditpol_subcategory(check_params["subcategory_guid"])
            if "allowed_values" in check_params:
                allowed = tuple(check_params["allowed_values"])
                return value, value is not None and value in allowed
            expected_value = check_params["expected_value"]
            return value, value is not None and value == expected_value

        return Rule(
            cis_id, title, expected, check,
            check_params.get("evidence", "auditpol /get /subcategory"),
            remediate_fn=_make_remediate_fn(check_type, check_params, expected)
        )

    # ------------------------------------------------------------------ registry_range
    elif check_type == "registry_range":
        def check():
            value = get_reg_dword(check_params["path"], check_params["name"])
            min_val  = check_params.get("min_val")
            max_val  = check_params.get("max_val")
            disallow = check_params.get("disallow", [])
            if value is None:
                return value, False
            if value in disallow:
                return value, False
            passed = True
            if min_val is not None:
                passed = passed and (value >= min_val)
            if max_val is not None:
                passed = passed and (value <= max_val)
            return value, passed

        return Rule(
            cis_id, title, expected, check, check_params["evidence"],
            remediate_fn=_make_remediate_fn(check_type, check_params, expected)
        )

    # ------------------------------------------------------------------ security_option
    elif check_type == "security_option":
        def check():
            value = get_security_option(check_params["policy_name"])
            expected_value = check_params["expected_value"]
            if check_params.get("validation_type") == "regex":
                import re as _re
                if value is None:
                    return "Not configured", False
                value_str = str(value)
                pattern = check_params["expected_value"]
                return value_str, bool(_re.match(pattern, value_str, _re.IGNORECASE))
            value_str   = str(value) if value is not None else "Not configured"
            expected_str = str(expected_value)
            try:
                return value_str, int(value) == int(expected_value)
            except (ValueError, TypeError):
                return value_str, value_str.lower() == expected_str.lower()

        return Rule(
            cis_id, title, expected, check, check_params["evidence"],
            remediate_fn=_make_remediate_fn(check_type, check_params, expected)
        )

    # ------------------------------------------------------------------ registry_sz
    elif check_type == "registry_sz":
        def check():
            value = get_reg_sz(check_params["path"], check_params["name"])
            if value is None and check_params.get("missing_is_compliant", False):
                return "Not configured (default)", True
            mode = check_params.get("expected_mode", "exact_str")
            if mode == "exact_str":
                import re as _re
                expected_value = check_params["expected_value"]
                v_norm = _re.sub(r"\s+", "", (value or "").lower())
                e_norm = _re.sub(r"\s+", "", expected_value.lower())
                return value, v_norm == e_norm
            elif mode == "max_int":
                max_value = check_params["max_value"]
                current_int = safe_int(value, None)
                return value, current_int is not None and current_int <= max_value
            elif mode == "min_int":
                min_value = check_params["min_value"]
                current_int = safe_int(value, None)
                return value, current_int is not None and current_int >= min_value
            elif mode == "range_int":
                min_value = check_params["min_value"]
                max_value = check_params["max_value"]
                current_int = safe_int(value, None)
                return value, current_int is not None and min_value <= current_int <= max_value
            return f"expected_mode no soportado: {mode}", False

        return Rule(
            cis_id, title, expected, check, check_params["evidence"],
            remediate_fn=_make_remediate_fn(check_type, check_params, expected)
        )

    # ------------------------------------------------------------------ registry_multisz
    elif check_type == "registry_multisz":
        def check():
            value = get_reg_multisz(check_params["path"], check_params["name"])
            if value is None:
                return "Not configured (default)", True
            current = set(v.upper() for v in value)
            allowed_sets = check_params.get("allowed_sets", [])
            for allowed in allowed_sets:
                if current == set(a.upper() for a in allowed):
                    return value, True
            return value, False

        return Rule(
            cis_id, title, expected, check, check_params["evidence"],
            remediate_fn=_make_remediate_fn(check_type, check_params, expected)
        )

    # ------------------------------------------------------------------ guest_account_status
    elif check_type == "guest_account_status":
        def check():
            value = get_guest_account_status()
            return value, value == expected

        return Rule(
            cis_id, title, expected, check,
            "Guest account status via PowerShell",
            remediate_fn=_make_remediate_fn(check_type, check_params, expected)
        )

    # ------------------------------------------------------------------ manual
    elif check_type == "manual":
        def check():
            return "Manual review required", False
        return Rule(cis_id, title, expected, check, "MANUAL (verify in GPO)")

    # ------------------------------------------------------------------ unknown
    else:
        def check():
            return f"Tipo de chequeo no implementado: {check_type}", False
        return Rule(cis_id, title, expected, check, "ERROR: Tipo de chequeo no implementado")
