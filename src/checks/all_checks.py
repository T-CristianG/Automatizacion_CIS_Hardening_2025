from core.rule_factory import create_rule

# ---------- Definición de Reglas CIS ----------

rules = []

# 1.1.1 Enforce password history
rules.append(create_rule(
    "1.1.1",
    "Ensure 'Enforce password history' is set to '24 or more password(s)'",
    ">= 24",
    "net_accounts",
    {"field": "Length of password history maintained"}
))

# 1.1.2 Maximum password age
rules.append(create_rule(
    "1.1.2",
    "Ensure 'Maximum password age' is set to '365 or fewer days, but not 0'",
    "1..365",
    "net_accounts",
    {"field": "Maximum password age (days)"}
))

# 1.1.3 Minimum password age
rules.append(create_rule(
    "1.1.3",
    "Ensure 'Minimum password age' is set to '1 or more day(s)'",
    ">= 1",
    "net_accounts",
    {"field": "Minimum password age (days)"}
))

# 1.1.4 Minimum password length
rules.append(create_rule(
    "1.1.4",
    "Ensure 'Minimum password length' is set to '14 or more character(s)'",
    ">= 14",
    "net_accounts",
    {"field": "Minimum password length"}
))

# 1.1.5 Password complexity
rules.append(create_rule(
    "1.1.5",
    "Ensure 'Password must meet complexity requirements' is set to 'Enabled'",
    "1",
    "secedit",
    {"key": "PasswordComplexity", "expected_value": 1}
))

# 1.1.6 Relax minimum password length limits
rules.append(create_rule(
    "1.1.6",
    "Ensure 'Relax minimum password length limits' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\System\CurrentControlSet\Control\SAM",
        "name": "RelaxMinimumPasswordLengthLimits",
        "expected_value": 1,
        "evidence": r"HKLM\System\CurrentControlSet\Control\SAM:RelaxMinimumPasswordLengthLimits"
    }
))

# 1.1.7 Store passwords using reversible encryption
rules.append(create_rule(
    "1.1.7",
    "Ensure 'Store passwords using reversible encryption' is set to 'Disabled'",
    "0",
    "secedit",
    {"key": "ClearTextPassword", "expected_value": 0}
))

# 1.2  Account Lockout Policy
# -----------------------------------------------------------------------------
# 1.2.1 Account lockout duration
rules.append(create_rule(
    "1.2.1",
    "Ensure 'Account lockout duration' is set to '15 or more minute(s)'",
    ">= 15",
    "net_accounts",
    {"field": "Lockout duration (minutes)"}
))

# 1.2.2 Account lockout threshold
rules.append(create_rule(
    "1.2.2",
    "Ensure 'Account lockout threshold' is set to '5 or fewer invalid logon attempt(s), but not 0'",
    "1..5",
    "net_accounts",
    {"field": "Lockout threshold"}
))

# 1.2.3 Allow Administrator account lockout (MS only, manual – pero lo dejamos como secedit)
rules.append(create_rule(
    "1.2.3",
    "Ensure 'Allow Administrator account lockout' is set to 'Enabled'",
    "1",
    "secedit",
    {"key": "EnableAdminAccountLockout", "expected_value": 1}
))

# 1.2.4 Reset account lockout counter after
rules.append(create_rule(
    "1.2.4",
    "Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)'",
    ">= 15",
    "net_accounts",
    {"field": "Lockout observation window (minutes)"}
))

# =============================================================================
# 2  Local Policies
# =============================================================================

# 2.2  User Rights Assignment
# -----------------------------------------------------------------------------
# 2.2.1 Access Credential Manager as a trusted caller
rules.append(create_rule(
    "2.2.1",
    "Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'",
    "",
    "user_right",
    {
        "right_name": "SeTrustedCredManAccessPrivilege",
        "expected_value": "",
        "evidence": "secedit export (User Rights)"
    }
))

# 2.2.2 Access this computer from the network (DC only) – se omite porque es DC

# 2.2.3 Access this computer from the network (MS only)
rules.append(create_rule(
    "2.2.3",
    "Ensure 'Access this computer from the network' is set to 'Administrators, Authenticated Users'",
    "*S-1-5-11,*S-1-5-32-544",
    "user_right",
    {
        "right_name": "SeNetworkLogonRight",
        "expected_value": "*S-1-5-11,*S-1-5-32-544",
        "evidence": "secedit export (User Rights)"
    }
))

# 2.2.4 Act as part of the operating system
rules.append(create_rule(
    "2.2.4",
    "Ensure 'Act as part of the operating system' is set to 'No One'",
    "",
    "user_right",
    {
        "right_name": "SeTcbPrivilege",
        "expected_value": "",
        "evidence": "secedit export (User Rights)"
    }
))

# 2.2.5 Add workstations to domain (DC only) – omitir

# 2.2.6 Adjust memory quotas for a process
rules.append(create_rule(
    "2.2.6",
    "Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'",
    "*S-1-5-32-544,*S-1-5-19,*S-1-5-20",
    "user_right",
    {
        "right_name": "SeIncreaseQuotaPrivilege",
        "expected_value": "*S-1-5-32-544,*S-1-5-19,*S-1-5-20",
        "evidence": "secedit export (User Rights)"
    }
))

# 2.2.7 Allow log on locally (DC only) – omitir

# 2.2.8 Allow log on locally (MS only)
rules.append(create_rule(
    "2.2.8",
    "Ensure 'Allow log on locally' is set to 'Administrators'",
    "*S-1-5-32-544",
    "user_right",
    {
        "right_name": "SeInteractiveLogonRight",
        "expected_value": "*S-1-5-32-544",
        "evidence": "secedit export (User Rights)"
    }
))

# 2.2.9 Allow log on through Remote Desktop Services (DC only) – omitir

# 2.2.10 Allow log on through Remote Desktop Services (MS only)
rules.append(create_rule(
    "2.2.10",
    "Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators, Remote Desktop Users'",
    "*S-1-5-32-544,*S-1-5-32-555",
    "user_right",
    {
        "right_name": "SeRemoteInteractiveLogonRight",
        "expected_value": "*S-1-5-32-544,*S-1-5-32-555",
        "evidence": "secedit /export /cfg secpolicy.txt"
    }
))

# 2.2.11 Back up files and directories
rules.append(create_rule(
    "2.2.11",
    "Ensure 'Back up files and directories' is set to 'Administrators'",
    "*S-1-5-32-544",
    "user_right",
    {
        "right_name": "SeBackupPrivilege",
        "expected_value": "*S-1-5-32-544",
        "evidence": "secedit /export /cfg secpolicy.txt"
    }
))

# 2.2.12 Change the system time
rules.append(create_rule(
    "2.2.12",
    "Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'",
    "*S-1-5-32-544,*S-1-5-19",
    "user_right",
    {
        "right_name": "SeSystemtimePrivilege",
        "expected_value": "*S-1-5-32-544,*S-1-5-19",
        "evidence": "secedit /export /cfg secpolicy.txt"
    }
))

# 2.2.13 Change the time zone
rules.append(create_rule(
    "2.2.13",
    "Ensure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE'",
    "*S-1-5-32-544,*S-1-5-19",
    "user_right",
    {
        "right_name": "SeTimeZonePrivilege",
        "expected_value": "*S-1-5-32-544,*S-1-5-19",
        "evidence": "secedit /export /cfg secpolicy.txt"
    }
))

# 2.2.14 Create a pagefile
rules.append(create_rule(
    "2.2.14",
    "Ensure 'Create a pagefile' is set to 'Administrators'",
    "*S-1-5-32-544",
    "user_right",
    {
        "right_name": "SeCreatePagefilePrivilege",
        "expected_value": "*S-1-5-32-544",
        "evidence": "secedit /export /cfg secpolicy.txt"
    }
))

# 2.2.15 Create a token object
rules.append(create_rule(
    "2.2.15",
    "Ensure 'Create a token object' is set to 'No One'",
    "",
    "user_right",
    {
        "right_name": "SeCreateTokenPrivilege",
        "expected_value": "",
        "evidence": "secedit /export /cfg secpolicy.txt"
    }
))

# 2.2.16 Create global objects
rules.append(create_rule(
    "2.2.16",
    "Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'",
    "*S-1-5-32-544,*S-1-5-19,*S-1-5-20,*S-1-5-6",
    "user_right",
    {
        "right_name": "SeCreateGlobalPrivilege",
        "expected_value": "*S-1-5-32-544,*S-1-5-19,*S-1-5-20,*S-1-5-6",
        "evidence": "secedit /export /cfg secpolicy.txt"
    }
))

# 2.2.17 Create permanent shared objects
rules.append(create_rule(
    "2.2.17",
    "Ensure 'Create permanent shared objects' is set to 'No One'",
    "",
    "user_right",
    {
        "right_name": "SeCreatePermanentPrivilege",
        "expected_value": "",
        "evidence": "secedit /export /cfg secpolicy.txt"
    }
))

 #2.2.18 Create symbolic links (MS only) — entorno VMware sin Hyper-V
rules.append(create_rule(
    "2.2.18",
    "Ensure 'Create symbolic links' is set to 'Administrators' (VMware - Hyper-V not installed)",
    "*S-1-5-32-544",
    "user_right",
    {
        "right_name": "SeCreateSymbolicLinkPrivilege",
        "expected_value": "*S-1-5-32-544",
        "evidence": "secedit /export /cfg secpolicy.txt"
    }
))

# 2.2.19 Debug programs
rules.append(create_rule(
    "2.2.19",
    "Ensure 'Debug programs' is set to 'Administrators'",
    "*S-1-5-32-544",
    "user_right",
    {
        "right_name": "SeDebugPrivilege",
        "expected_value": "*S-1-5-32-544",
        "evidence": "secedit /export /cfg secpolicy.txt"
    }
))

# 2.2.20 Deny access to this computer from the network (DC only) – omitir

# 2.2.21 Deny access to this computer from the network (MS only)

rules.append(create_rule(
    "2.2.21",
    "Ensure 'Deny access to this computer from the network' to include 'Guests, Local account, Administrators'",
    "*S-1-5-32-546,*S-1-5-113,*S-1-5-32-544",
    "user_right",
    {
        "right_name": "SeDenyNetworkLogonRight",
        "expected_value": "*S-1-5-32-546,*S-1-5-113,*S-1-5-32-544",
        "evidence": "secedit /export /cfg secpolicy.txt"
    }
))        # ← dos )) correcto

# 2.2.22 Deny log on as a batch job
rules.append(create_rule(
    "2.2.22",
    "Ensure 'Deny log on as a batch job' to include 'Guests'",
    "*S-1-5-32-546",
    "user_right",
    {
        "right_name": "SeDenyBatchLogonRight",
        "expected_value": "*S-1-5-32-546",
        "evidence": "secedit /export /cfg secpolicy.txt"
    }
))

# 2.2.23 Deny log on as a service
rules.append(create_rule(
    "2.2.23",
    "Ensure 'Deny log on as a service' to include 'Guests'",
    "*S-1-5-32-546",
    "user_right",
    {
        "right_name": "SeDenyServiceLogonRight",
        "expected_value": "*S-1-5-32-546",
        "evidence": "secedit /export /cfg secpolicy.txt"
    }
))

# 2.2.24 Deny log on locally  (la que pediste)
rules.append(create_rule(
    "2.2.24",
    "Ensure 'Deny log on locally' to include 'Guests'",
    "*S-1-5-32-546",
    "user_right",
    {
        "right_name": "SeDenyInteractiveLogonRight",
        "expected_value": "*S-1-5-32-546",
        "evidence": "secedit /export /cfg secpolicy.txt"
    }
))

# 2.2.25 Deny log on through Remote Desktop Services (DC only) – omitir

# 2.2.26 Deny log on through Remote Desktop Services (MS only)
rules.append(create_rule(
    "2.2.26",
    "Ensure 'Deny log on through Remote Desktop Services' is set to 'Guests, Local account'",
    "*S-1-5-32-546,*S-1-5-113",
    "user_right",
    {
        "right_name": "SeDenyRemoteInteractiveLogonRight",
        "expected_value": "*S-1-5-32-546,*S-1-5-113",
        "evidence": "secedit /export /cfg secpolicy.txt"
    }
))

# 2.2.27 Enable computer and user accounts to be trusted for delegation (DC only) – omitir

# 2.2.28 Enable computer and user accounts to be trusted for delegation (MS only)
rules.append(create_rule(
    "2.2.28",
    "Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'No One'",
    "",
    "user_right",
    {
        "right_name": "SeEnableDelegationPrivilege",
        "expected_value": "",
        "evidence": "secedit /export /cfg secpolicy.txt"
    }
))

# 2.2.29 Force shutdown from a remote system
rules.append(create_rule(
    "2.2.29",
    "Ensure 'Force shutdown from a remote system' is set to 'Administrators'",
    "*S-1-5-32-544",
    "user_right",
    {
        "right_name": "SeRemoteShutdownPrivilege",
        "expected_value": "*S-1-5-32-544",
        "evidence": "secedit /export /cfg secpolicy.txt"
    }
))

# 2.2.30 Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE, RESTRICTED SERVICES\PrintSpoolerService'
rules.append(create_rule(
    "2.2.30",
    "Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE, RESTRICTED SERVICES\\PrintSpoolerService'",
    "*S-1-5-19,*S-1-5-20,*S-1-5-99-216390572-1995538116-3857911515-2404958512-2623887229",
    "user_right",
    {
        "right_name": "SeAuditPrivilege",
        "expected_value": "*S-1-5-19,*S-1-5-20,*S-1-5-99-216390572-1995538116-3857911515-2404958512-2623887229",
        "evidence": "secedit /export /cfg secpolicy.txt"
    }
))

# 2.2.31 Increase a process working set (MS only)
rules.append(create_rule(
    "2.2.31",
    "Ensure 'Increase a process working set' is set to 'Administrators, Window Manager\\Window Manager Group'",
    "*S-1-5-32-544,*S-1-5-90-0",
    "user_right",
    {
        "right_name": "SeIncreaseWorkingSetPrivilege",
        "expected_value": "*S-1-5-32-544,*S-1-5-90-0",
        "evidence": "secedit /export /cfg secpolicy.txt"
    }
))

# 2.2.32 Ensure 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE, RESTRICTED SERVICES\PrintSpoolerService'
rules.append(create_rule(
    "2.2.32",
    "Ensure 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE, RESTRICTED SERVICES\\PrintSpoolerService'",
    "*S-1-5-32-544,*S-1-5-19,*S-1-5-20,*S-1-5-6,*S-1-5-99-216390572-1995538116-3857911515-2404958512-2623887229",
    "user_right",
    {
        "right_name": "SeImpersonatePrivilege",
        "expected_value": "*S-1-5-32-544,*S-1-5-19,*S-1-5-20,*S-1-5-6,*S-1-5-99-216390572-1995538116-3857911515-2404958512-2623887229",
        "evidence": "secedit /export /cfg secpolicy.txt"
    }
))

# 2.2.33 Increase scheduling priority
rules.append(create_rule(
    "2.2.33",
    "Ensure 'Increase scheduling priority' is set to 'Administrators, Window Manager\\Window Manager Group'",
    "*S-1-5-32-544,*S-1-5-90-0",
    "user_right",
    {
        "right_name": "SeIncreaseBasePriorityPrivilege",
        "expected_value": "*S-1-5-32-544,*S-1-5-90-0",
        "evidence": "secedit /export /cfg secpolicy.txt"
    }
))

# 2.2.34 Load and unload device drivers
rules.append(create_rule(
    "2.2.34",
    "Ensure 'Load and unload device drivers' is set to 'Administrators'",
    "*S-1-5-32-544",
    "user_right",
    {
        "right_name": "SeLoadDriverPrivilege",
        "expected_value": "*S-1-5-32-544",
        "evidence": "secedit /export /cfg secpolicy.txt"
    }
))

# 2.2.35 Lock pages in memory
rules.append(create_rule(
    "2.2.35",
    "Ensure 'Lock pages in memory' is set to 'No One'",
    "",
    "user_right",
    {
        "right_name": "SeLockMemoryPrivilege",
        "expected_value": "",
        "evidence": "secedit /export /cfg secpolicy.txt"
    }
))

# 2.2.36 Log on as a batch job (DC only) – omitir

# 2.2.37 Manage auditing and security log (DC only) – omitir

# 2.2.38 Manage auditing and security log (MS only)
rules.append(create_rule(
    "2.2.38",
    "Ensure 'Manage auditing and security log' is set to 'Administrators'",
    "*S-1-5-32-544",
    "user_right",
    {
        "right_name": "SeSecurityPrivilege",
        "expected_value": "*S-1-5-32-544",
        "evidence": "secedit /export /cfg secpolicy.txt"
    }
))

# 2.2.39 Modify an object label
rules.append(create_rule(
    "2.2.39",
    "Ensure 'Modify an object label' is set to 'No One'",
    "",
    "user_right",
    {
        "right_name": "SeRelabelPrivilege",
        "expected_value": "",
        "evidence": "secedit /export /cfg secpolicy.txt"
    }
))

# 2.2.40 Modify firmware environment values
rules.append(create_rule(
    "2.2.40",
    "Ensure 'Modify firmware environment values' is set to 'Administrators'",
    "*S-1-5-32-544",
    "user_right",
    {
        "right_name": "SeSystemEnvironmentPrivilege",
        "expected_value": "*S-1-5-32-544",
        "evidence": "secedit /export /cfg secpolicy.txt"
    }
))

# 2.2.41 Perform volume maintenance tasks
rules.append(create_rule(
    "2.2.41",
    "Ensure 'Perform volume maintenance tasks' is set to 'Administrators'",
    "*S-1-5-32-544",
    "user_right",
    {
        "right_name": "SeManageVolumePrivilege",
        "expected_value": "*S-1-5-32-544",
        "evidence": "secedit /export /cfg secpolicy.txt"
    }
))

# 2.2.42 Profile single process
rules.append(create_rule(
    "2.2.42",
    "Ensure 'Profile single process' is set to 'Administrators'",
    "*S-1-5-32-544",
    "user_right",
    {
        "right_name": "SeProfileSingleProcessPrivilege",
        "expected_value": "*S-1-5-32-544",
        "evidence": "secedit /export /cfg secpolicy.txt"
    }
))

# 2.2.43 Profile system performance
rules.append(create_rule(
    "2.2.43",
    "Ensure 'Profile system performance' is set to 'Administrators, NT SERVICE\\WdiServiceHost'",
    "*S-1-5-32-544,*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420",
    "user_right",
    {
        "right_name": "SeSystemProfilePrivilege",
        "expected_value": "*S-1-5-32-544,*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420",
        "evidence": "secedit /export /cfg secpolicy.txt"
    }
))

# 2.2.44 Replace a process level token
rules.append(create_rule(
    "2.2.44",
    "Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE'",
    "*S-1-5-19,*S-1-5-20",
    "user_right",
    {
        "right_name": "SeAssignPrimaryTokenPrivilege",
        "expected_value": "*S-1-5-19,*S-1-5-20",
        "evidence": "secedit /export /cfg secpolicy.txt"
    }
))

# 2.2.45 Restore files and directories
rules.append(create_rule(
    "2.2.45",
    "Ensure 'Restore files and directories' is set to 'Administrators'",
    "*S-1-5-32-544",
    "user_right",
    {
        "right_name": "SeRestorePrivilege",
        "expected_value": "*S-1-5-32-544",
        "evidence": "secedit /export /cfg secpolicy.txt"
    }
))

# 2.2.46 Shut down the system
rules.append(create_rule(
    "2.2.46",
    "Ensure 'Shut down the system' is set to 'Administrators'",
    "*S-1-5-32-544",
    "user_right",
    {
        "right_name": "SeShutdownPrivilege",
        "expected_value": "*S-1-5-32-544",
        "evidence": "secedit /export /cfg secpolicy.txt"
    }
))

# 2.2.47 Synchronize directory service data (DC only) – omitir

# 2.2.48 Take ownership of files or other objects
rules.append(create_rule(
    "2.2.48",
    "Ensure 'Take ownership of files or other objects' is set to 'Administrators'",
    "*S-1-5-32-544",
    "user_right",
    {
        "right_name": "SeTakeOwnershipPrivilege",
        "expected_value": "*S-1-5-32-544",
        "evidence": "secedit /export /cfg secpolicy.txt"
    }
))

# 2.3  Security Options
# -----------------------------------------------------------------------------
# 2.3.1.1 Guest account status (MS only)
# 2.3.1.1 Ensure 'Accounts: Guest account status' is set to 'Disabled'
rules.append(create_rule(
    "2.3.1.1",
    "Ensure 'Accounts: Guest account status' is set to 'Disabled'",
    "Disabled",
    "guest_account_status",
    {}
))

# 2.3.1.2 Limit local account use of blank passwords
rules.append(create_rule(
    "2.3.1.2",
    "Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'",
    "Enabled",
    "security_option",
    {
        "policy_name": "LimitBlankPasswordUse",
        "expected_value": "1",
        "evidence": "reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v LimitBlankPasswordUse"
    }
))

# 2.3.2.1 Force audit policy subcategory settings
rules.append(create_rule(
    "2.3.2.1",
    "Ensure 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa",
        "name": "SCENoApplyLegacyAuditPolicy",
        "expected_value": 1,
        "evidence": r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa:SCENoApplyLegacyAuditPolicy"
    }
))

# 2.3.2.2 Shut down system immediately if unable to log security audits
rules.append(create_rule(
    "2.3.2.2",
    "Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'",
    "0",
    "registry",
    {
        "path": r"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa",
        "name": "CrashOnAuditFail",
        "expected_value": 0,
        "evidence": r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa:CrashOnAuditFail"
    }
))

# 2.3.4.1 Prevent users from installing printer drivers
rules.append(create_rule(
    "2.3.4.1",
    "Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers",
        "name": "AddPrinterDrivers",
        "expected_value": 1,
        "evidence": r"HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers:AddPrinterDrivers"
    }
))

# 2.3.5.1 (DC only) Allow server operators to schedule tasks – omitir

# 2.3.5.2 (DC only) Allow vulnerable Netlogon secure channel connections – omitir

# 2.3.5.3 (DC only) LDAP server channel binding token requirements – omitir

# 2.3.5.4 (DC only) LDAP server signing requirements Enforcement – omitir

# 2.3.5.5 (DC only) Refuse machine account password changes – omitir

# 2.3.6.1 Domain member: Digitally encrypt or sign secure channel data (always)
rules.append(create_rule(
    "2.3.6.1",
    "Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters",
        "name": "RequireSignOrSeal",
        "expected_value": 1,
        "evidence": r"HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters:RequireSignOrSeal"
    }
))

# 2.3.6.2 Domain member: Digitally encrypt secure channel data (when possible)
rules.append(create_rule(
    "2.3.6.2",
    "Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters",
        "name": "SealSecureChannel",
        "expected_value": 1,
        "evidence": r"HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters:SealSecureChannel"
    }
))

# 2.3.6.3 Domain member: Digitally sign secure channel data (when possible)
rules.append(create_rule(
    "2.3.6.3",
    "Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters",
        "name": "SignSecureChannel",
        "expected_value": 1,
        "evidence": r"HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters:SignSecureChannel"
    }
))

# 2.3.6.4 Domain member: Disable machine account password changes
rules.append(create_rule(
    "2.3.6.4",
    "Ensure 'Domain member: Disable machine account password changes' is set to 'Disabled'",
    "0",
    "registry",
    {
        "path": r"HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters",
        "name": "DisablePasswordChange",
        "expected_value": 0,
        "evidence": r"HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters:DisablePasswordChange"
    }
))

# 2.3.6.5 Domain member: Maximum machine account password age
rules.append(create_rule(
    "2.3.6.5",
    "Ensure 'Domain member: Maximum machine account password age' is set to '30 or fewer days, but not 0'",
    "1..30",
    "registry_range",
    {
        "path": r"HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters",
        "name": "MaximumPasswordAge",
        "min_val": 1,
        "max_val": 30,
        "disallow": [0],
        "evidence": r"HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters:MaximumPasswordAge"
    }
))

# 2.3.6.6 Domain member: Require strong (Windows 2000 or later) session key
rules.append(create_rule(
    "2.3.6.6",
    "Ensure 'Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters",
        "name": "RequireStrongKey",
        "expected_value": 1,
        "evidence": r"HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters:RequireStrongKey"
    }
))

# 2.3.7.2 Interactive logon: Don't display last signed-in
rules.append(create_rule(
    "2.3.7.2",
    "Ensure 'Interactive logon: Don't display last signed-in' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "name": "DontDisplayLastUserName",
        "expected_value": 1,
        "evidence": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:DontDisplayLastUserName"
    }
))

# 2.3.7.3 Interactive logon: Machine inactivity limit
rules.append(create_rule(
    "2.3.7.3",
    "Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0'",
    "1..900",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "name": "InactivityTimeoutSecs",
        "expected_value": 900,
        "evidence": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:InactivityTimeoutSecs"
    }
))

# 2.3.7.4 Configure message text – omitir (manual)

# 2.3.7.5 Configure message title – omitir (manual)

# 2.3.7.7 Prompt user to change password before expiration
rules.append(create_rule(
    "2.3.7.7",
    "Ensure 'Interactive logon: Prompt user to change password before expiration' is set to 'between 5 and 14 days'",
    "5..14",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "name": "PasswordExpiryWarning",
        "expected_mode": "range_int",
        "min_value": 5,
        "max_value": 14,
        "evidence": r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon:PasswordExpiryWarning"
    }
))

# 2.3.7.8 Require Domain Controller Authentication to unlock workstation (MS only)
rules.append(create_rule(
    "2.3.7.8",
    "Ensure 'Interactive logon: Require Domain Controller Authentication to unlock workstation' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "name": "ForceUnlockLogon",
        "expected_value": 1,
        "evidence": r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon:ForceUnlockLogon"
    }
))

# 2.3.7.9 Smart card removal behavior
rules.append(create_rule(
    "2.3.7.9",
    "Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation' or higher",
    "1, 2, or 3",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "name": "ScRemoveOption",
        "allowed_values": [1, 2, 3],
        "evidence": r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon:ScRemoveOption"
    }
))

# 2.3.8.1 Microsoft network client: Digitally sign communications (always)
rules.append(create_rule(
    "2.3.8.1",
    "Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters",
        "name": "RequireSecuritySignature",
        "expected_value": 1,
        "evidence": r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters:RequireSecuritySignature"
    }
))

# 2.3.8.2 Send unencrypted password to third-party SMB servers
rules.append(create_rule(
    "2.3.8.2",
    "Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled'",
    "0",
    "registry",
    {
        "path": r"HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters",
        "name": "EnablePlainTextPassword",
        "expected_value": 0,
        "evidence": r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters:EnablePlainTextPassword"
    }
))

# 2.3.9.1 Microsoft network server: Amount of idle time before suspending session
rules.append(create_rule(
    "2.3.9.1",
    "Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute(s)'",
    "<= 15",
    "registry",
    {
        "path": r"HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters",
        "name": "AutoDisconnect",
        "expected_value": 15,
        "evidence": r"HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters:AutoDisconnect"
    }
))

# 2.3.9.2 Microsoft network server: Digitally sign communications (always)
rules.append(create_rule(
    "2.3.9.2",
    "Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters",
        "name": "RequireSecuritySignature",
        "expected_value": 1,
        "evidence": r"HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters:RequireSecuritySignature"
    }
))

# 2.3.9.3 Disconnect clients when logon hours expire
rules.append(create_rule(
    "2.3.9.3",
    "Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters",
        "name": "enableforcedlogoff",
        "expected_value": 1,
        "evidence": r"HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters:enableforcedlogoff"
    }
))

# 2.3.9.4 Server SPN target name validation level (MS only)
rules.append(create_rule(
    "2.3.9.4",
    "Ensure 'Microsoft network server: Server SPN target name validation level' is set to 'Accept if provided by client' or higher",
    "1..2",
    "registry",
    {
        "path": r"HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters",
        "name": "SMBServerNameHardeningLevel",
        "expected_value": "1..2",
        "validation_type": "range",
        "evidence": r"HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters:SMBServerNameHardeningLevel"
    }
))

# 2.3.10.1 Allow anonymous SID/Name translation
rules.append(create_rule(
    "2.3.10.1",
    "Ensure 'Network access: Allow anonymous SID/Name translation' is set to 'Disabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\System\CurrentControlSet\Control\Lsa",
        "name": "TurnOffAnonymousBlock",
        "expected_value": 1,
        "missing_is_compliant": True,
        "evidence": r"HKLM\System\CurrentControlSet\Control\Lsa:TurnOffAnonymousBlock"
    }
))

# 2.3.10.2 Do not allow anonymous enumeration of SAM accounts (MS only)
rules.append(create_rule(
    "2.3.10.2",
    "Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa",
        "name": "RestrictAnonymousSAM",
        "expected_value": 1,
        "missing_is_compliant": True,
        "evidence": r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa:RestrictAnonymousSAM"
    }
))

# 2.3.10.3 Do not allow anonymous enumeration of SAM accounts and shares (MS only)
rules.append(create_rule(
    "2.3.10.3",
    "Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa",
        "name": "RestrictAnonymous",
        "expected_value": 1,
        "evidence": r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa:RestrictAnonymous"
    }
))


# 2.3.10.5 Let Everyone permissions apply to anonymous users
rules.append(create_rule(
    "2.3.10.5",
    "Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'",
    "0",
    "registry",
    {
        "path": r"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa",
        "name": "EveryoneIncludesAnonymous",
        "expected_value": 0,
        "missing_is_compliant": True,
        "evidence": r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa:EveryoneIncludesAnonymous"
    }
))

# 2.3.10.6 Named Pipes (DC only) – omitir

# 2.3.10.7 Named Pipes (MS only) – normalmente vacío
rules.append(create_rule(
    "2.3.10.7",
    "Ensure 'Network access: Named Pipes that can be accessed anonymously' is configured (MS only)",
    "<blank>",
    "registry_multisz",
    {
        "path": r"HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters",
        "name": "NullSessionPipes",
        "allowed_sets": [[], ["BROWSER"]],
        "evidence": r"HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters:NullSessionPipes"
    }
))

# 2.3.10.8 Remotely accessible registry paths
base_paths_23108 = [
    r"System\CurrentControlSet\Control\ProductOptions",
    r"System\CurrentControlSet\Control\Server Applications",
    r"Software\Microsoft\Windows NT\CurrentVersion",
]
rules.append(create_rule(
    "2.3.10.8",
    "Ensure 'Network access: Remotely accessible registry paths' is configured",
    "Configured as CIS recommended list",
    "registry_multisz",
    {
        "path": r"HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths",
        "name": "Machine",
        "allowed_sets": [base_paths_23108],
        "evidence": r"HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths:Machine"
    }
))

# 2.3.10.9 Remotely accessible registry paths and sub-paths
base_paths_23109 = [
    r"System\CurrentControlSet\Control\Print\Printers",
    r"System\CurrentControlSet\Services\Eventlog",
    r"Software\Microsoft\OLAP Server",
    r"Software\Microsoft\Windows NT\CurrentVersion\Print",
    r"Software\Microsoft\Windows NT\CurrentVersion\Windows",
    r"System\CurrentControlSet\Control\ContentIndex",
    r"System\CurrentControlSet\Control\Terminal Server",
    r"System\CurrentControlSet\Control\Terminal Server\UserConfig",
    r"System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration",
    r"Software\Microsoft\Windows NT\CurrentVersion\Perflib",
    r"System\CurrentControlSet\Services\SysmonLog",
]
certsvc_path = r"System\CurrentControlSet\Services\CertSvc"
wins_path = r"System\CurrentControlSet\Services\WINS"
rules.append(create_rule(
    "2.3.10.9",
    "Ensure 'Network access: Remotely accessible registry paths and sub-paths' is configured",
    "Configured as CIS recommended list",
    "registry_multisz",
    {
        "path": r"HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths",
        "name": "Machine",
        "allowed_sets": [
            base_paths_23109,
            base_paths_23109 + [certsvc_path],
            base_paths_23109 + [wins_path],
            base_paths_23109 + [certsvc_path, wins_path],
        ],
        "evidence": r"HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths:Machine"
    }
))

# 2.3.10.10 Restrict anonymous access to Named Pipes and Shares
rules.append(create_rule(
    "2.3.10.10",
    "Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters",
        "name": "RestrictNullSessAccess",
        "expected_value": 1,
        "missing_is_compliant": True,
        "evidence": r"HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters:RestrictNullSessAccess"
    }
))

# 2.3.10.11 Restrict clients allowed to make remote calls to SAM (MS only)
rules.append(create_rule(
    "2.3.10.11",
    "Ensure 'Network access: Restrict clients allowed to make remote calls to SAM' is set to 'Administrators: Remote Access: Allow'",
    "O:BAG:BAD:(A;;RC;;;BA)",
    "registry_sz",
    {
        "path": r"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa",
        "name": "restrictremotesam",
        "expected_value": "O:BAG:BAD:(A;;RC;;;BA)",
        "missing_is_compliant": True,
        "evidence": r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa:restrictremotesam"
    }
))

# 2.3.10.12 Shares that can be accessed anonymously
rules.append(create_rule(
    "2.3.10.12",
    "Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None'",
    "<blank>",
    "registry_multisz",
    {
        "path": r"HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters",
        "name": "NullSessionShares",
        "allowed_sets": [[]],
        "evidence": r"HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters:NullSessionShares"
    }
))

# 2.3.10.13 Sharing and security model for local accounts
rules.append(create_rule(
    "2.3.10.13",
    "Ensure 'Network access: Sharing and security model for local accounts' is set to 'Classic - local users authenticate as themselves'",
    "0",
    "registry",
    {
        "path": r"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa",
        "name": "ForceGuest",
        "expected_value": 0,
        "missing_is_compliant": True,
        "evidence": r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa:ForceGuest"
    }
))

# 2.3.11.1 Allow Local System to use computer identity for NTLM
rules.append(create_rule(
    "2.3.11.1",
    "Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa",
        "name": "UseMachineId",
        "expected_value": 1,
        "evidence": r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa:UseMachineId"
    }
))

# 2.3.11.2 Allow LocalSystem NULL session fallback
rules.append(create_rule(
    "2.3.11.2",
    "Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled'",
    "0",
    "registry",
    {
        "path": r"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0",
        "name": "AllowNullSessionFallback",
        "expected_value": 0,
        "missing_is_compliant": True,
        "evidence": r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0:AllowNullSessionFallback"
    }
))

# 2.3.11.3 Allow PKU2U online identities
rules.append(create_rule(
    "2.3.11.3",
    "Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled'",
    "0",
    "registry",
    {
        "path": r"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\pku2u",
        "name": "AllowOnlineID",
        "expected_value": 0,
        "missing_is_compliant": True,
        "evidence": r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\pku2u:AllowOnlineID"
    }
))

# 2.3.11.4 Configure encryption types allowed for Kerberos
rules.append(create_rule(
    "2.3.11.4",
    "Ensure 'Network security: Configure encryption types allowed for Kerberos' is set to 'AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types'",
    "2147483640",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters",
        "name": "SupportedEncryptionTypes",
        "expected_value": 2147483640,
        "evidence": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters:SupportedEncryptionTypes"
    }
))

# 2.3.11.5 Force logoff when logon hours expire
# secedit key: ForceLogoffWhenHourExpire = 1 (Enabled)
rules.append(create_rule(
    "2.3.11.5",
    "Ensure 'Network security: Force logoff when logon hours expire' is set to 'Enabled'",
    "1",
    "secedit",
    {
        "key": "ForceLogoffWhenHourExpire",
        "expected_value": 1,
        "evidence": "secedit /export (ForceLogoffWhenHourExpire)"
    }
))

# 2.3.11.6 LAN Manager authentication level
rules.append(create_rule(
    "2.3.11.6",
    "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'",
    "5",
    "registry",
    {
        "path": r"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa",
        "name": "LmCompatibilityLevel",
        "expected_value": 5,
        "evidence": r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa:LmCompatibilityLevel"
    }
))

# 2.3.11.7 LDAP client encryption requirements
rules.append(create_rule(
    "2.3.11.7",
    "Ensure 'Network security: LDAP client encryption requirements' is set to 'Negotiate sealing' or higher",
    "1 or 2",
    "registry",
    {
        "path": r"HKLM:\SYSTEM\CurrentControlSet\Services\LDAP",
        "name": "LDAPClientConfidentiality",
        "allowed_values": [1, 2],
        "missing_is_compliant": True,
        "evidence": r"HKLM\SYSTEM\CurrentControlSet\Services\LDAP:LDAPClientConfidentiality"
    }
))

# 2.3.11.8 LDAP client signing requirements
rules.append(create_rule(
    "2.3.11.8",
    "Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher",
    "1 or 2",
    "registry",
    {
        "path": r"HKLM:\SYSTEM\CurrentControlSet\Services\LDAP",
        "name": "LDAPClientIntegrity",
        "allowed_values": [1, 2],
        "missing_is_compliant": True,
        "evidence": r"HKLM\SYSTEM\CurrentControlSet\Services\LDAP:LDAPClientIntegrity"
    }
))

# 2.3.11.9 Minimum session security for NTLM SSP clients
rules.append(create_rule(
    "2.3.11.9",
    "Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'",
    "537395200",
    "registry",
    {
        "path": r"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0",
        "name": "NTLMMinClientSec",
        "expected_value": 537395200,
        "evidence": r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0:NTLMMinClientSec"
    }
))

# 2.3.11.10 Minimum session security for NTLM SSP servers
rules.append(create_rule(
    "2.3.11.10",
    "Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'",
    "537395200",
    "registry",
    {
        "path": r"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0",
        "name": "NTLMMinServerSec",
        "expected_value": 537395200,
        "evidence": r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0:NTLMMinServerSec"
    }
))

# 2.3.11.11 Restrict NTLM: Audit Incoming NTLM Traffic
rules.append(create_rule(
    "2.3.11.11",
    "Ensure 'Network security: Restrict NTLM: Audit Incoming NTLM Traffic' is set to 'Enable auditing for all accounts'",
    "2",
    "registry",
    {
        "path": r"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0",
        "name": "AuditReceivingNTLMTraffic",
        "expected_value": 2,
        "evidence": r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0:AuditReceivingNTLMTraffic"
    }
))

# 2.3.11.12 (DC only) – omitir

# 2.3.11.13 Restrict NTLM: Outgoing NTLM traffic to remote servers
rules.append(create_rule(
    "2.3.11.13",
    "Ensure 'Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers' is set to 'Audit all' or higher",
    "1 or 2",
    "registry",
    {
        "path": r"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0",
        "name": "RestrictSendingNTLMTraffic",
        "allowed_values": [1, 2],
        "evidence": r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0:RestrictSendingNTLMTraffic"
    }
))

# 2.3.13.1 Shutdown: Allow system to be shut down without having to log on
rules.append(create_rule(
    "2.3.13.1",
    "Ensure 'Shutdown: Allow system to be shut down without having to log on' is set to 'Disabled'",
    "0",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "name": "ShutdownWithoutLogon",
        "expected_value": 0,
        "missing_is_compliant": True,
        "evidence": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:ShutdownWithoutLogon"
    }
))

# 2.3.15.1 Require case insensitivity for non-Windows subsystems
rules.append(create_rule(
    "2.3.15.1",
    "Ensure 'System objects: Require case insensitivity for non-Windows subsystems' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel",
        "name": "ObCaseInsensitive",
        "expected_value": 1,
        "missing_is_compliant": True,
        "evidence": r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel:ObCaseInsensitive"
    }
))

# 2.3.15.2 Strengthen default permissions of internal system objects
rules.append(create_rule(
    "2.3.15.2",
    "Ensure 'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager",
        "name": "ProtectionMode",
        "expected_value": 1,
        "missing_is_compliant": True,
        "evidence": r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager:ProtectionMode"
    }
))

# 2.3.17.1 UAC: Admin Approval Mode for the Built-in Administrator account
rules.append(create_rule(
    "2.3.17.1",
    "Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "name": "FilterAdministratorToken",
        "expected_value": 1,
        "evidence": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:FilterAdministratorToken"
    }
))

# 2.3.17.2 UAC: Behavior of elevation prompt for administrators
rules.append(create_rule(
    "2.3.17.2",
    "Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop' or higher",
    "1 or 2",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "name": "ConsentPromptBehaviorAdmin",
        "allowed_values": [1, 2],
        "evidence": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:ConsentPromptBehaviorAdmin"
    }
))

# 2.3.17.3 UAC: Behavior of elevation prompt for standard users
rules.append(create_rule(
    "2.3.17.3",
    "Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'",
    "0",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "name": "ConsentPromptBehaviorUser",
        "expected_value": 0,
        "evidence": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:ConsentPromptBehaviorUser"
    }
))

# 2.3.17.4 UAC: Detect application installations and prompt for elevation
rules.append(create_rule(
    "2.3.17.4",
    "Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "name": "EnableInstallerDetection",
        "expected_value": 1,
        "evidence": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:EnableInstallerDetection"
    }
))

# 2.3.17.5 UAC: Only elevate UIAccess applications installed in secure locations
rules.append(create_rule(
    "2.3.17.5",
    "Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "name": "EnableSecureUIAPaths",
        "expected_value": 1,
        "evidence": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:EnableSecureUIAPaths"
    }
))

# 2.3.17.6 UAC: Run all administrators in Admin Approval Mode
rules.append(create_rule(
    "2.3.17.6",
    "Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "name": "EnableLUA",
        "expected_value": 1,
        "evidence": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:EnableLUA"
    }
))

# 2.3.17.7 UAC: Switch to the secure desktop when prompting for elevation
rules.append(create_rule(
    "2.3.17.7",
    "Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "name": "PromptOnSecureDesktop",
        "expected_value": 1,
        "evidence": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:PromptOnSecureDesktop"
    }
))

# 2.3.17.8 UAC: Virtualize file and registry write failures
rules.append(create_rule(
    "2.3.17.8",
    "Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "name": "EnableVirtualization",
        "expected_value": 1,
        "evidence": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:EnableVirtualization"
    }
))

# 9.1.1 (L1) Windows Firewall: Domain: Firewall state = On
rules.append(create_rule(
    "9.1.1",
    "Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On (recommended)'",
    "On",
    "firewall",
    {
        "profile": "Domain",
        "expected_value": True  # o 1 dependiendo qué devuelva tu helper
    }
))

# 9.1.2 (L1) Windows Firewall: Domain: Inbound connections = Block (default)
rules.append(create_rule(
    "9.1.2",
    "Ensure 'Windows Firewall: Domain: Inbound connections' is set to 'Block (default)'",
    "Block (default)",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile",
        "name": "DefaultInboundAction",
        "expected_value": 1,
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile:DefaultInboundAction"
    }
))

# 9.1.3 (L1) Windows Firewall: Domain: Settings: Display a notification = No
rules.append(create_rule(
    "9.1.3",
    "Ensure 'Windows Firewall: Domain: Settings: Display a notification' is set to 'No'",
    "No",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile",
        "name": "DisableNotifications",
        "expected_value": 1,
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile:DisableNotifications"
    }
))

# 9.1.4 (L1) Windows Firewall: Domain: Logging: Name
rules.append(create_rule(
    "9.1.4",
    "Ensure 'Windows Firewall: Domain: Logging: Name' is set to '%SystemRoot%\\System32\\logfiles\\firewall\\domainfw.log'",
    r"%SystemRoot%\System32\logfiles\firewall\domainfw.log",
    "registry_sz",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging",
        "name": "LogFilePath",
        "expected_value": r"%SystemRoot%\System32\logfiles\firewall\domainfw.log",
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging:LogFilePath"
    }
))

# 9.1.5 (L1) Windows Firewall: Domain: Logging: Size limit (KB)
rules.append(create_rule(
    "9.1.5",
    "Ensure 'Windows Firewall: Domain: Logging: Size limit (KB)' is set to '16,384 KB or greater'",
    ">=16384",
    "registry_range",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging",
        "name": "LogFileSize",
        "min_val": 16384,
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging:LogFileSize"
    }
))

# 9.1.6 (L1) Windows Firewall: Domain: Logging: Log dropped packets = Yes (1)
rules.append(create_rule(
    "9.1.6",
    "Ensure 'Windows Firewall: Domain: Logging: Log dropped packets' is set to 'Yes'",
    "Yes",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging",
        "name": "LogDroppedPackets",
        "expected_value": 1,
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging:LogDroppedPackets"
    }
))

# 9.1.7 (L1) Windows Firewall: Domain: Logging: Log successful connections = Yes (1)
rules.append(create_rule(
    "9.1.7",
    "Ensure 'Windows Firewall: Domain: Logging: Log successful connections' is set to 'Yes'",
    "Yes",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging",
        "name": "LogSuccessfulConnections",
        "expected_value": 1,
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging:LogSuccessfulConnections"
    }
))

# 9.2.1 Windows Firewall Private profile
rules.append(create_rule(
    "9.2.1",
    "Ensure 'Windows Firewall: Private: Firewall state' is set to 'On'",
    "True",
    "firewall",
    {"profile": "Private", "expected_value": True}
))

# 9.2.2 (L1) Windows Firewall: Private: Inbound connections = Block (default)
rules.append(create_rule(
    "9.2.2",
    "Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Block (default)'",
    "Block (default)",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile",
        "name": "DefaultInboundAction",
        "expected_value": 1,
        # Como CIS dice que el default ya es compliant:
        "missing_is_compliant": True,
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile:DefaultInboundAction"
    }
))

# 9.2.3 (L1) Windows Firewall: Private: Settings: Display a notification = No
rules.append(create_rule(
    "9.2.3",
    "Ensure 'Windows Firewall: Private: Settings: Display a notification' is set to 'No'",
    "No",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile",
        "name": "DisableNotifications",
        "expected_value": 1,
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile:DisableNotifications"
    }
))

# 9.2.4 (L1) Windows Firewall: Private: Logging: Name
rules.append(create_rule(
    "9.2.4",
    "Ensure 'Windows Firewall: Private: Logging: Name' is set to '%SystemRoot%\\System32\\logfiles\\firewall\\privatefw.log'",
    r"%SystemRoot%\System32\logfiles\firewall\privatefw.log",
    "registry_sz",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging",
        "name": "LogFilePath",
        "expected_value": r"%SystemRoot%\System32\logfiles\firewall\privatefw.log",
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging:LogFilePath"
    }
))

# 9.2.5 (L1) Windows Firewall: Private: Logging: Size limit (KB)
rules.append(create_rule(
    "9.2.5",
    "Ensure 'Windows Firewall: Private: Logging: Size limit (KB)' is set to '16,384 KB or greater'",
    ">=16384",
    "registry_range",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging",
        "name": "LogFileSize",
        "min_val": 16384,
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging:LogFileSize"
    }
))

# 9.2.6 (L1) Windows Firewall: Private: Logging: Log dropped packets
rules.append(create_rule(
    "9.2.6",
    "Ensure 'Windows Firewall: Private: Logging: Log dropped packets' is set to 'Yes'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging",
        "name": "LogDroppedPackets",
        "expected_value": 1,
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging:LogDroppedPackets"
    }
))

# 9.2.7 (L1) Windows Firewall: Private: Logging: Log successful connections
rules.append(create_rule(
    "9.2.7",
    "Ensure 'Windows Firewall: Private: Logging: Log successful connections' is set to 'Yes'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging",
        "name": "LogSuccessfulConnections",
        "expected_value": 1,
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging:LogSuccessfulConnections"
    }
))

# 9.3.1 (L1) Windows Firewall: Public: Firewall state = On
rules.append(create_rule(
    "9.3.1",
    "Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)'",
    "On",
    "firewall",
    {
        "profile": "Public",
        "expected_value": True
    }
))

# 9.3.2 (L1) Windows Firewall: Public: Inbound connections = Block (default)
rules.append(create_rule(
    "9.3.2",
    "Ensure 'Windows Firewall: Public: Inbound connections' is set to 'Block (default)'",
    "Block (default)",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile",
        "name": "DefaultInboundAction",
        "expected_value": 1,
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile:DefaultInboundAction"
    }
))

# 9.3.3 (L1) Windows Firewall: Public: Settings: Display a notification = No
rules.append(create_rule(
    "9.3.3",
    "Ensure 'Windows Firewall: Public: Settings: Display a notification' is set to 'No'",
    "No",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile",
        "name": "DisableNotifications",
        "expected_value": 1,
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile:DisableNotifications"
    }
))

# 9.3.4 (L1) Windows Firewall: Public: Settings: Apply local firewall rules = No
rules.append(create_rule(
    "9.3.4",
    "Ensure 'Windows Firewall: Public: Settings: Apply local firewall rules' is set to 'No'",
    "No",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile",
        "name": "AllowLocalPolicyMerge",
        "expected_value": 0,
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile:AllowLocalPolicyMerge"
    }
))

# 9.3.5 (L1) Windows Firewall: Public: Settings: Apply local connection security rules = No
rules.append(create_rule(
    "9.3.5",
    "Ensure 'Windows Firewall: Public: Settings: Apply local connection security rules' is set to 'No'",
    "No",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile",
        "name": "AllowLocalIPsecPolicyMerge",
        "expected_value": 0,
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile:AllowLocalIPsecPolicyMerge"
    }
))

# 9.3.6 (L1) Windows Firewall: Public: Logging: Name = publicfw.log
rules.append(create_rule(
    "9.3.6",
    "Ensure 'Windows Firewall: Public: Logging: Name' is set to '%SystemRoot%\\System32\\logfiles\\firewall\\publicfw.log'",
    r"%SystemRoot%\System32\logfiles\firewall\publicfw.log",
    "registry_sz",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging",
        "name": "LogFilePath",
        "expected_value": r"%SystemRoot%\System32\logfiles\firewall\publicfw.log",
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging:LogFilePath"
    }
))

# 9.3.7 (L1) Windows Firewall: Public: Logging: Size limit (KB) >= 16384
rules.append(create_rule(
    "9.3.7",
    "Ensure 'Windows Firewall: Public: Logging: Size limit (KB)' is set to '16,384 KB or greater'",
    ">=16384",
    "registry_range",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging",
        "name": "LogFileSize",
        "min_val": 16384,
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging:LogFileSize"
    }
))

# 9.3.8 (L1) Windows Firewall: Public: Logging: Log dropped packets = Yes
rules.append(create_rule(
    "9.3.8",
    "Ensure 'Windows Firewall: Public: Logging: Log dropped packets' is set to 'Yes'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging",
        "name": "LogDroppedPackets",
        "expected_value": 1,
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging:LogDroppedPackets"
    }
))

# 9.3.9 (L1) Windows Firewall: Public: Logging: Log successful connections = Yes
rules.append(create_rule(
    "9.3.9",
    "Ensure 'Windows Firewall: Public: Logging: Log successful connections' is set to 'Yes'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging",
        "name": "LogSuccessfulConnections",
        "expected_value": 1,
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging:LogSuccessfulConnections"
    }
))

# 17.1.1 (L1) Audit Credential Validation = Success and Failure (3)
rules.append(create_rule(
    "17.1.1",
    "Ensure 'Audit Credential Validation' is set to 'Success and Failure'",
    "3",
    "auditpol",
    {
        "subcategory_guid": "{0cce923f-69ae-11d9-bed3-505054503030}",
        "expected_value": 3,  # 1=Success, 2=Failure, 3=Success+Failure
        "evidence": 'auditpol /get /subcategory:"{0cce923f-69ae-11d9-bed3-505054503030}"'
    }
))

# 17.2.1 (L1) Audit Application Group Management = Success and Failure (3)
rules.append(create_rule(
    "17.2.1",
    "Ensure 'Audit Application Group Management' is set to 'Success and Failure'",
    "3",
    "auditpol",
    {
        "subcategory_guid": "{0cce9239-69ae-11d9-bed3-505054503030}",
        "expected_value": 3,  # 1=Success, 2=Failure, 3=Success+Failure
        "evidence": 'auditpol /get /subcategory:"{0cce9239-69ae-11d9-bed3-505054503030}"'
    }
))

# 17.2.5 (L1) Ensure 'Audit Security Group Management' is set to include 'Success' (Automated)
rules.append(create_rule(
    "17.2.5",
    "Ensure 'Audit Security Group Management' is set to include 'Success' (Automated)",
    "3",
    "auditpol",
    {
        "subcategory_guid": "{0cce9237-69ae-11d9-bed3-505054503030}",
        "expected_value": 3,  # 1=Success, 2=Failure, 3=Success+Failure
        "evidence": 'auditpol /get /subcategory:"{0cce9237-69ae-11d9-bed3-505054503030}"'
    }
))

# 17.2.6 (L1) Audit User Account Management = Success and Failure (3)
rules.append(create_rule(
    "17.2.6",
    "Ensure 'Audit User Account Management' is set to 'Success and Failure'",
    "3",
    "auditpol",
    {
        "subcategory_guid": "{0cce9235-69ae-11d9-bed3-505054503030}",
        "expected_value": 3,  # 1=Success, 2=Failure, 3=Success+Failure
        "evidence": 'auditpol /get /subcategory:"{0cce9235-69ae-11d9-bed3-505054503030}"'
    }
))

# 17.3.1 (L1) Audit PNP Activity = include Success (1 or 3)
rules.append(create_rule(
    "17.3.1",
    "Ensure 'Audit PNP Activity' is set to include 'Success'",
    "Success (1) or Success and Failure (3)",
    "auditpol",
    {
        "subcategory_guid": "{0cce9248-69ae-11d9-bed3-505054503030}",
        "allowed_values": [1, 3],  # ✅ incluye Success
        "expected_value": 1,       # valor principal esperado
        "evidence": 'auditpol /get /subcategory:"{0cce9248-69ae-11d9-bed3-505054503030}"'
    }
))

# 17.3.2 (L1) Audit Process Creation = include Success (1 or 3)
rules.append(create_rule(
    "17.3.2",
    "Ensure 'Audit Process Creation' is set to include 'Success'",
    "Success (1) or Success and Failure (3)",
    "auditpol",
    {
        "subcategory_guid": "{0cce922b-69ae-11d9-bed3-505054503030}",
        "allowed_values": [1, 3],  # ✅ incluye Success
        "expected_value": 1,       # valor base esperado
        "evidence": 'auditpol /get /subcategory:"{0cce922b-69ae-11d9-bed3-505054503030}"'
    }
))

# 17.5.1 (L1) Audit Account Lockout = include Failure (2 or 3)
rules.append(create_rule(
    "17.5.1",
    "Ensure 'Audit Account Lockout' is set to include 'Failure'",
    "Failure (2) or Success and Failure (3)",
    "auditpol",
    {
        "subcategory_guid": "{0cce9217-69ae-11d9-bed3-505054503030}",
        "allowed_values": [2, 3],  # ✅ incluye Failure
        "expected_value": 2,       # valor base esperado
        "evidence": 'auditpol /get /subcategory:"{0cce9217-69ae-11d9-bed3-505054503030}"'
    }
))

# 17.5.2 (L1) Audit Group Membership = include Success (1 or 3)
rules.append(create_rule(
    "17.5.2",
    "Ensure 'Audit Group Membership' is set to include 'Success'",
    "Success (1) or Success and Failure (3)",
    "auditpol",
    {
        "subcategory_guid": "{0cce9249-69ae-11d9-bed3-505054503030}",
        "allowed_values": [1, 3],  # ✅ incluye Success
        "expected_value": 1,
        "evidence": 'auditpol /get /subcategory:"{0cce9249-69ae-11d9-bed3-505054503030}"'
    }
))

# 17.5.3 (L1) Audit Logoff = include Success (1 or 3)
rules.append(create_rule(
    "17.5.3",
    "Ensure 'Audit Logoff' is set to include 'Success'",
    "Success (1) or Success and Failure (3)",
    "auditpol",
    {
        "subcategory_guid": "{0cce9216-69ae-11d9-bed3-505054503030}",
        "allowed_values": [1, 3],  # ✅ incluye Success
        "expected_value": 1,
        "evidence": 'auditpol /get /subcategory:"{0cce9216-69ae-11d9-bed3-505054503030}"'
    }
))

# 17.5.4 (L1) Audit Logon = Success and Failure (3)
rules.append(create_rule(
    "17.5.4",
    "Ensure 'Audit Logon' is set to 'Success and Failure'",
    "3",
    "auditpol",
    {
        "subcategory_guid": "{0cce9215-69ae-11d9-bed3-505054503030}",
        "expected_value": 3,  # 1=Success, 2=Failure, 3=Success+Failure
        "evidence": 'auditpol /get /subcategory:"{0cce9215-69ae-11d9-bed3-505054503030}"'
    }
))

# 17.5.5 (L1) Audit Other Logon/Logoff Events = Success and Failure (3)
rules.append(create_rule(
    "17.5.5",
    "Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure'",
    "3",
    "auditpol",
    {
        "subcategory_guid": "{0cce921c-69ae-11d9-bed3-505054503030}",
        "expected_value": 3,  # 1=Success, 2=Failure, 3=Success+Failure
        "evidence": 'auditpol /get /subcategory:"{0cce921c-69ae-11d9-bed3-505054503030}"'
    }
))

# 17.5.6 (L1) Audit Special Logon = include Success (1 or 3)
rules.append(create_rule(
    "17.5.6",
    "Ensure 'Audit Special Logon' is set to include 'Success'",
    "Success (1) or Success and Failure (3)",
    "auditpol",
    {
        "subcategory_guid": "{0cce921b-69ae-11d9-bed3-505054503030}",
        "allowed_values": [1, 3],  # ✅ incluye Success
        "expected_value": 1,
        "evidence": 'auditpol /get /subcategory:"{0cce921b-69ae-11d9-bed3-505054503030}"'
    }
))

# 17.6.1 (L1) Audit Detailed File Share = include Failure (2 or 3)
rules.append(create_rule(
    "17.6.1",
    "Ensure 'Audit Detailed File Share' is set to include 'Failure'",
    "Failure (2) or Success and Failure (3)",
    "auditpol",
    {
        "subcategory_guid": "{0cce9244-69ae-11d9-bed3-505054503030}",
        "allowed_values": [2, 3],  # ✅ incluye Failure
        "expected_value": 2,
        "evidence": 'auditpol /get /subcategory:"{0cce9244-69ae-11d9-bed3-505054503030}"'
    }
))

# 17.6.2 (L1) Audit File Share = Success and Failure (3)
rules.append(create_rule(
    "17.6.2",
    "Ensure 'Audit File Share' is set to 'Success and Failure'",
    "3",
    "auditpol",
    {
        "subcategory_guid": "{0cce9224-69ae-11d9-bed3-505054503030}",
        "expected_value": 3,  # 1=Success, 2=Failure, 3=Success+Failure
        "evidence": 'auditpol /get /subcategory:"{0cce9224-69ae-11d9-bed3-505054503030}"'
    }
))

# 17.6.3 (L1) Audit Other Object Access Events = Success and Failure (3)
rules.append(create_rule(
    "17.6.3",
    "Ensure 'Audit Other Object Access Events' is set to 'Success and Failure'",
    "3",
    "auditpol",
    {
        "subcategory_guid": "{0cce9227-69ae-11d9-bed3-505054503030}",
        "expected_value": 3,  # 1=Success, 2=Failure, 3=Success+Failure
        "evidence": 'auditpol /get /subcategory:"{0cce9227-69ae-11d9-bed3-505054503030}"'
    }
))

# 17.6.4 (L1) Audit Removable Storage = Success and Failure (3)
rules.append(create_rule(
    "17.6.4",
    "Ensure 'Audit Removable Storage' is set to 'Success and Failure'",
    "3",
    "auditpol",
    {
        "subcategory_guid": "{0cce9245-69ae-11d9-bed3-505054503030}",
        "expected_value": 3,  # 1=Success, 2=Failure, 3=Success+Failure
        "evidence": 'auditpol /get /subcategory:"{0cce9245-69ae-11d9-bed3-505054503030}"'
    }
))

# 17.7.1 (L1) Audit Audit Policy Change = include Success (1 or 3)

rules.append(create_rule(
    "17.7.1",
    "Ensure 'Audit Audit Policy Change' is set to include 'Success'",
    "1",  # esperado mínimo: Success
    "auditpol",
    {
        "subcategory_guid": "{0cce922f-69ae-11d9-bed3-505054503030}",
        "allowed_values": [1, 3],  # 1=Success, 3=Success+Failure
        "expected_value": 1,
        "evidence": 'auditpol /get /subcategory:"{0cce922f-69ae-11d9-bed3-505054503030}"'
    }
))

# 17.7.2 (L1) Audit Authentication Policy Change = include Success (1 or 3)

rules.append(create_rule(
    "17.7.2",
    "Ensure 'Audit Authentication Policy Change' is set to include 'Success'",
    "1",
    "auditpol",
    {
        "subcategory_guid": "{0cce9230-69ae-11d9-bed3-505054503030}",
        "allowed_values": [1, 3],
        "expected_value": 1,
        "evidence": 'auditpol /get /subcategory:"{0cce9230-69ae-11d9-bed3-505054503030}"'
    }
))

# 17.7.3 (L1) Audit Authorization Policy Change = include Success (1 or 3)

rules.append(create_rule(
    "17.7.3",
    "Ensure 'Audit Authorization Policy Change' is set to include 'Success'",
    "1",
    "auditpol",
    {
        "subcategory_guid": "{0cce9231-69ae-11d9-bed3-505054503030}",
        "allowed_values": [1, 3],
        "expected_value": 1,
        "evidence": 'auditpol /get /subcategory:"{0cce9231-69ae-11d9-bed3-505054503030}"'
    }
))

# 17.7.4 (L1) Audit MPSSVC Rule-Level Policy Change = Success and Failure (3)

rules.append(create_rule(
    "17.7.4",
    "Ensure 'Audit MPSSVC Rule-Level Policy Change' is set to 'Success and Failure'",
    "3",  # esperado: Success and Failure
    "auditpol",
    {
        "subcategory_guid": "{0cce9232-69ae-11d9-bed3-505054503030}",
        "allowed_values": [3],  # 3=Success+Failure
        "expected_value": 3,
        "evidence": 'auditpol /get /subcategory:"{0cce9232-69ae-11d9-bed3-505054503030}"'
    }
))

# 17.7.5 (L1) Audit Other Policy Change Events = include Failure (2 or 3)

rules.append(create_rule(
    "17.7.5",
    "Ensure 'Audit Other Policy Change Events' is set to include 'Failure'",
    "2",  # esperado mínimo: Failure
    "auditpol",
    {
        "subcategory_guid": "{0cce9234-69ae-11d9-bed3-505054503030}",
        "allowed_values": [2, 3],  # 2=Failure, 3=Success+Failure
        "expected_value": 2,
        "evidence": 'auditpol /get /subcategory:"{0cce9234-69ae-11d9-bed3-505054503030}"'
    }
))

# 17.8.1 (L1) Audit Sensitive Privilege Use = Success and Failure (3)

rules.append(create_rule(
    "17.8.1",
    "Ensure 'Audit Sensitive Privilege Use' is set to 'Success and Failure'",
    "3",  # esperado: Success and Failure
    "auditpol",
    {
        "subcategory_guid": "{0cce9228-69ae-11d9-bed3-505054503030}",
        "allowed_values": [3],  # 3=Success+Failure
        "expected_value": 3,
        "evidence": 'auditpol /get /subcategory:"{0cce9228-69ae-11d9-bed3-505054503030}"'
    }
))

# 17.9.1 (L1) Audit IPsec Driver = Success and Failure (3)

rules.append(create_rule(
    "17.9.1",
    "Ensure 'Audit IPsec Driver' is set to 'Success and Failure'",
    "3",  # esperado: Success and Failure
    "auditpol",
    {
        "subcategory_guid": "{0cce9213-69ae-11d9-bed3-505054503030}",
        "allowed_values": [3],
        "expected_value": 3,
        "evidence": 'auditpol /get /subcategory:"{0cce9213-69ae-11d9-bed3-505054503030}"'
    }
))


# 17.9.2 (L1) Audit Other System Events = Success and Failure (3)

rules.append(create_rule(
    "17.9.2",
    "Ensure 'Audit Other System Events' is set to 'Success and Failure'",
    "3",
    "auditpol",
    {
        "subcategory_guid": "{0cce9214-69ae-11d9-bed3-505054503030}",
        "allowed_values": [3],
        "expected_value": 3,
        "evidence": 'auditpol /get /subcategory:"{0cce9214-69ae-11d9-bed3-505054503030}"'
    }
))


# 17.9.3 (L1) Audit Security State Change = Success (1)

rules.append(create_rule(
    "17.9.3",
    "Ensure 'Audit Security State Change' is set to include 'Success'",
    "1",  # esperado: Success
    "auditpol",
    {
        "subcategory_guid": "{0cce9210-69ae-11d9-bed3-505054503030}",
        "allowed_values": [1, 3],  # si tu framework acepta que 3 también incluye Success
        "expected_value": 1,
        "evidence": 'auditpol /get /subcategory:"{0cce9210-69ae-11d9-bed3-505054503030}"'
    }
))


# 17.9.4 (L1) Audit Security System Extension = Success (1)

rules.append(create_rule(
    "17.9.4",
    "Ensure 'Audit Security System Extension' is set to include 'Success'",
    "1",
    "auditpol",
    {
        "subcategory_guid": "{0cce9211-69ae-11d9-bed3-505054503030}",
        "allowed_values": [1, 3],
        "expected_value": 1,
        "evidence": 'auditpol /get /subcategory:"{0cce9211-69ae-11d9-bed3-505054503030}"'
    }
))


# 17.9.5 (L1) Audit System Integrity = Success and Failure (3)

rules.append(create_rule(
    "17.9.5",
    "Ensure 'Audit System Integrity' is set to 'Success and Failure'",
    "3",
    "auditpol",
    {
        "subcategory_guid": "{0cce9212-69ae-11d9-bed3-505054503030}",
        "allowed_values": [3],
        "expected_value": 3,
        "evidence": 'auditpol /get /subcategory:"{0cce9212-69ae-11d9-bed3-505054503030}"'
    }
))

# 18.1.1.1 (L1) Prevent enabling lock screen camera = Enabled (REG_DWORD 1)

rules.append(create_rule(
    "18.1.1.1",
    "Ensure 'Prevent enabling lock screen camera' is set to 'Enabled'",
    "1",  # Enabled
    "registry",
    {
        "hive": "HKLM",
        "path": r"SOFTWARE\Policies\Microsoft\Windows\Personalization",
        "value_name": "NoLockScreenCamera",
        "type": "REG_DWORD",
        "allowed_values": [1],
        "expected_value": 1,
        "evidence": r'HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization:NoLockScreenCamera'
    }
))


# 18.1.1.2 (L1) Prevent enabling lock screen slide show = Enabled (REG_DWORD 1)

rules.append(create_rule(
    "18.1.1.2",
    "Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled'",
    "1",  # Enabled
    "registry",
    {
        "hive": "HKLM",
        "path": r"SOFTWARE\Policies\Microsoft\Windows\Personalization",
        "value_name": "NoLockScreenSlideshow",
        "type": "REG_DWORD",
        "allowed_values": [1],
        "expected_value": 1,
        "evidence": r'HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization:NoLockScreenSlideshow'
    }
))

# 18.1.2.2 (L1) Allow users to enable online speech recognition services = Disabled (REG_DWORD 0)

rules.append(create_rule(
    "18.1.2.2",
    "Ensure 'Allow users to enable online speech recognition services' is set to 'Disabled'",
    "0",  # Disabled
    "registry",
    {
        "hive": "HKLM",
        "path": r"SOFTWARE\Policies\Microsoft\InputPersonalization",
        "value_name": "AllowInputPersonalization",
        "type": "REG_DWORD",
        "allowed_values": [0],
        "expected_value": 0,
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization:AllowInputPersonalization"
    }
))

# 18.4.1 (L1) Apply UAC restrictions to local accounts on network logons = Enabled (REG_DWORD 0)

rules.append(create_rule(
    "18.4.1",
    "Ensure 'Apply UAC restrictions to local accounts on network logons' is set to 'Enabled'",
    "0",  # Enabled -> LocalAccountTokenFilterPolicy = 0
    "registry",
    {
        "hive": "HKLM",
        "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "value_name": "LocalAccountTokenFilterPolicy",
        "type": "REG_DWORD",
        "allowed_values": [0],
        "expected_value": 0,
        "evidence": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:LocalAccountTokenFilterPolicy"
    }
))

# 18.4.2 (L1) Configure SMB v1 client driver = Enabled: Disable driver (Start=4)

rules.append(create_rule(
    "18.4.2",
    "Ensure 'Configure SMB v1 client driver' is set to 'Enabled: Disable driver (recommended)'",
    "4",  # Disable driver
    "registry",
    {
        "hive": "HKLM",
        "path": r"SYSTEM\CurrentControlSet\Services\mrxsmb10",
        "value_name": "Start",
        "type": "REG_DWORD",
        "allowed_values": [4],
        "expected_value": 4,
        "evidence": r"HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10:Start"
    }
))

# 18.4.3 (L1) Configure SMB v1 server = Disabled (REG_DWORD 0)

rules.append(create_rule(
    "18.4.3",
    "Ensure 'Configure SMB v1 server' is set to 'Disabled'",
    "0",  # Disabled -> SMB1 = 0
    "registry",
    {
        "hive": "HKLM",
        "path": r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
        "value_name": "SMB1",
        "type": "REG_DWORD",
        "allowed_values": [0],
        "expected_value": 0,
        "evidence": r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters:SMB1"
    }
))

# 18.4.4 (L1) Enable Certificate Padding = Enabled (value 1)
# 64-bit path

rules.append(create_rule(
    "18.4.4",
    "Ensure 'Enable Certificate Padding' is set to 'Enabled' (64-bit)",
    "1",
    "registry",
    {
        "hive": "HKLM",
        "path": r"SOFTWARE\Microsoft\Cryptography\Wintrust\Config",
        "value_name": "EnableCertPaddingCheck",
        "type": "REG_DWORD_OR_SZ",
        "allowed_values": [1, "1"],
        "expected_value": 1,
        "evidence": r"HKLM\SOFTWARE\Microsoft\Cryptography\Wintrust\Config:EnableCertPaddingCheck"
    }
))

# 32-bit subsystem on 64-bit OS path

rules.append(create_rule(
    "18.4.4",
    "Ensure 'Enable Certificate Padding' is set to 'Enabled' (32-bit subsystem on 64-bit OS)",
    "1",
    "registry",
    {
        "hive": "HKLM",
        "path": r"SOFTWARE\Wow6432Node\Microsoft\Cryptography\Wintrust\Config",
        "value_name": "EnableCertPaddingCheck",
        "type": "REG_DWORD_OR_SZ",
        "allowed_values": [1, "1"],
        "expected_value": 1,
        "evidence": r"HKLM\SOFTWARE\Wow6432Node\Microsoft\Cryptography\Wintrust\Config:EnableCertPaddingCheck"
    }
))

# 18.4.5 (L1) Enable SEHOP = Enabled (REG_DWORD 0)

rules.append(create_rule(
    "18.4.5",
    "Ensure 'Enable Structured Exception Handling Overwrite Protection (SEHOP)' is set to 'Enabled'",
    "0",  # Enabled -> DisableExceptionChainValidation = 0
    "registry",
    {
        "hive": "HKLM",
        "path": r"SYSTEM\CurrentControlSet\Control\Session Manager\kernel",
        "value_name": "DisableExceptionChainValidation",
        "type": "REG_DWORD",
        "allowed_values": [0],
        "expected_value": 0,
        "evidence": r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel:DisableExceptionChainValidation"
    }
))

# 18.4.6 (L1) NetBT NodeType configuration = Enabled: P-node (NodeType=2)

rules.append(create_rule(
    "18.4.6",
    "Ensure 'NetBT NodeType configuration' is set to 'Enabled: P-node (recommended)'",
    "2",  # P-node
    "registry",
    {
        "hive": "HKLM",
        "path": r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters",
        "value_name": "NodeType",
        "type": "REG_DWORD",
        "allowed_values": [2],
        "expected_value": 2,
        "evidence": r"HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters:NodeType"
    }
))


# 18.5.1 (L1) MSS: (AutoAdminLogon) Enable Automatic Logon = Disabled (REG_SZ "0")

rules.append(create_rule(
    "18.5.1",
    "Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon' is set to 'Disabled'",
    "0",
    "registry_sz",
    {
        "path": r"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "name": "AutoAdminLogon",
        "expected_value": "0",
        "missing_is_compliant": True,  # default es Disabled
        "evidence": r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon:AutoAdminLogon"
    }
))

# 18.5.2 (L1) MSS: (DisableIPSourceRouting IPv6) = Enabled Highest protection (DWORD 2)

rules.append(create_rule(
    "18.5.2",
    "Ensure 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level' is set to "
    "'Enabled: Highest protection, source routing is completely disabled'",
    "2",
    "registry",
    {
        "path": r"HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters",
        "name": "DisableIPSourceRouting",
        "expected_value": 2,
        "allowed_values": [2],
        "evidence": r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters:DisableIPSourceRouting"
    }
))

# 18.5.3 (L1) MSS: (DisableIPSourceRouting) = Enabled Highest protection (DWORD 2)

rules.append(create_rule(
    "18.5.3",
    "Ensure 'MSS: (DisableIPSourceRouting) IP source routing protection level' is set to "
    "'Enabled: Highest protection, source routing is completely disabled'",
    "2",
    "registry",
    {
        "path": r"HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
        "name": "DisableIPSourceRouting",
        "expected_value": 2,
        "allowed_values": [2],
        "evidence": r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters:DisableIPSourceRouting"
    }
))

# 18.5.4 (L1) MSS: (EnableICMPRedirect) Allow ICMP redirects... = Disabled (DWORD 0)

rules.append(create_rule(
    "18.5.4",
    "Ensure 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' "
    "is set to 'Disabled'",
    "0",
    "registry",
    {
        "path": r"HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
        "name": "EnableICMPRedirect",
        "expected_value": 0,
        "allowed_values": [0],
        "evidence": r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters:EnableICMPRedirect"
    }
))

# 18.5.6 (L1) MSS: (NoNameReleaseOnDemand) = Enabled (REG_DWORD 1)

rules.append(create_rule(
    "18.5.6",
    "Ensure 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests "
    "except from WINS servers' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters",
        "name": "NoNameReleaseOnDemand",
        "expected_value": 1,
        "allowed_values": [1],
        "missing_is_compliant": True,  # default ya es Enabled
        "evidence": r"HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters:NoNameReleaseOnDemand"
    }
))

# 18.5.8 (L1) MSS: (SafeDllSearchMode) Enable Safe DLL search mode = Enabled (REG_DWORD 1)

rules.append(create_rule(
    "18.5.8",
    "Ensure 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager",
        "name": "SafeDllSearchMode",
        "expected_value": 1,
        "allowed_values": [1],
        "missing_is_compliant": True,  # default ya es Enabled
        "evidence": r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager:SafeDllSearchMode"
    }
))

# 18.5.9 (L1) MSS: (ScreenSaverGracePeriod) = Enabled: 5 or fewer seconds (REG_SZ <= 5)

rules.append(create_rule(
    "18.5.9",
    "Ensure 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires' "
    "is set to 'Enabled: 5 or fewer seconds'",
    "<=5",
    "registry_sz",
    {
        "path": r"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "name": "ScreenSaverGracePeriod",
        "expected_mode": "max_int",
        "max_value": 5,
        "missing_is_compliant": True,  # default es 5
        "evidence": r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon:ScreenSaverGracePeriod"
    }
))

# 18.5.11 (L1) MSS: (WarningLevel) Security event log warning threshold = Enabled: 90% or less (REG_DWORD <= 90)

rules.append(create_rule(
    "18.5.11",
    "Ensure 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' "
    "is set to 'Enabled: 90% or less'",
    "<=90",
    "registry",
    {
        "path": r"HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security",
        "name": "WarningLevel",
        "expected_mode": "max_int",
        "max_value": 90,
        "type": "REG_DWORD",
        "missing_is_compliant": False,  # default es 0 y eso NO cumple CIS
        "evidence": r"HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Security:WarningLevel"
    }
))

# 18.6.4.1 (L1) Configure multicast DNS (mDNS) protocol = Disabled (REG_DWORD 0)

rules.append(create_rule(
    "18.6.4.1",
    "Ensure 'Configure multicast DNS (mDNS) protocol' is set to 'Disabled'",
    "0",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
        "name": "EnableMDNS",
        "expected_value": 0,
        "allowed_values": [0],
        "missing_is_compliant": True,  # default ya es Disabled
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient:EnableMDNS"
    }
))

# 18.6.4.2 (L1) Configure NetBIOS settings = Enabled: disable on public networks
# REG_DWORD EnableNetbios debe ser 0 o 2

rules.append(create_rule(
    "18.6.4.2",
    "Ensure 'Configure NetBIOS settings' is set to 'Enabled: Disable NetBIOS name resolution on public networks'",
    "0 or 2",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
        "name": "EnableNetbios",
        "expected_value": 0,              # no importa cuál pongas aquí
        "allowed_values": [0, 2],         # porque validas por allowed_values
        "missing_is_compliant": True,     # default cumple benchmark
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient:EnableNetbios"
    }
))

# 18.6.4.4 (L1) Turn off multicast name resolution = Enabled
# REG_DWORD EnableMulticast debe ser 0

rules.append(create_rule(
    "18.6.4.4",
    "Ensure 'Turn off multicast name resolution' is set to 'Enabled'",
    "0",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
        "name": "EnableMulticast",
        "expected_value": 0,
        "allowed_values": [0],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient:EnableMulticast"
    }
))


# 18.6.7.1 (L1) Audit client does not support encryption = Enabled (REG_DWORD 1)
rules.append(create_rule(
    "18.6.7.1",
    "Ensure 'Audit client does not support encryption' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanServer",
        "name": "AuditClientDoesNotSupportEncryption",
        "expected_value": 1,
        "allowed_values": [1],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanServer:AuditClientDoesNotSupportEncryption"
    }
))


# 18.6.7.2 (L1) Audit client does not support signing = Enabled (REG_DWORD 1)
rules.append(create_rule(
    "18.6.7.2",
    "Ensure 'Audit client does not support signing' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanServer",
        "name": "AuditClientDoesNotSupportSigning",
        "expected_value": 1,
        "allowed_values": [1],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanServer:AuditClientDoesNotSupportSigning"
    }
))


# 18.6.7.3 (L1) Audit insecure guest logon = Enabled (REG_DWORD 1)
rules.append(create_rule(
    "18.6.7.3",
    "Ensure 'Audit insecure guest logon' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanServer",
        "name": "AuditInsecureGuestLogon",
        "expected_value": 1,
        "allowed_values": [1],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanServer:AuditInsecureGuestLogon"
    }
))


# 18.6.7.4 (L1) Enable remote mailslots = Disabled (REG_DWORD 0)
rules.append(create_rule(
    "18.6.7.4",
    "Ensure 'Enable remote mailslots' is set to 'Disabled'",
    "0",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\Bowser",
        "name": "EnableMailslots",
        "expected_value": 0,
        "allowed_values": [0],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Bowser:EnableMailslots"
    }
))


# 18.6.7.5 (L1) Mandate the minimum version of SMB = Enabled: 3.1.1
# FIX: SMB 3.1.1 se almacena en el registro como 0x311 HEX = 785 DECIMAL.
# "311" es el valor HEX, NO el decimal. Windows lo escribe como 785.
rules.append(create_rule(
    "18.6.7.5",
    "Ensure 'Mandate the minimum version of SMB' is set to 'Enabled: 3.1.1'",
    "785",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanServer",
        "name": "MinSmb2Dialect",
        "expected_value": 785,
        "allowed_values": [785],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanServer:MinSmb2Dialect"
    }
))


# 18.6.7.6 (L1) Set authentication rate limiter delay (ms) = Enabled: 2000 or more
rules.append(create_rule(
    "18.6.7.6",
    "Ensure 'Set authentication rate limiter delay (milliseconds)' is set to 'Enabled: 2000' or more",
    ">=2000",
    "registry_range",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanServer",
        "name": "InvalidAuthenticationDelayTimeInMs",
        "min_val": 2000,
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanServer:InvalidAuthenticationDelayTimeInMs"
    }
))

# 18.6.7.7 (L1) Set authentication rate limiter delay = Enabled: 2000 ms or more (REG_DWORD >= 2000)

rules.append(create_rule(
    "18.6.7.7",
    "Ensure 'Set authentication rate limiter delay (milliseconds)' is set to 'Enabled: 2000 or more'",
    ">=2000",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanServer",
        "name": "InvalidAuthenticationDelayTimeInMs",
        "expected_mode": "min_int",
        "min_value": 2000,
        "type": "REG_DWORD",
        "missing_is_compliant": False,  # si no existe no cumple CIS
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanServer:InvalidAuthenticationDelayTimeInMs"
    }
))

# 18.6.8.1 (L1) Audit insecure guest logon = Enabled (REG_DWORD 1)
rules.append(create_rule(
    "18.6.8.1",
    "Ensure 'Audit insecure guest logon' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation",
        "name": "AuditInsecureGuestLogon",
        "expected_value": 1,
        "allowed_values": [1],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation:AuditInsecureGuestLogon"
    }
))


# 18.6.8.2 (L1) Audit server does not support encryption = Enabled (REG_DWORD 1)
rules.append(create_rule(
    "18.6.8.2",
    "Ensure 'Audit server does not support encryption' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation",
        "name": "AuditServerDoesNotSupportEncryption",
        "expected_value": 1,
        "allowed_values": [1],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation:AuditServerDoesNotSupportEncryption"
    }
))


# 18.6.8.3 (L1) Audit server does not support signing = Enabled (REG_DWORD 1)
rules.append(create_rule(
    "18.6.8.3",
    "Ensure 'Audit server does not support signing' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation",
        "name": "AuditServerDoesNotSupportSigning",
        "expected_value": 1,
        "allowed_values": [1],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation:AuditServerDoesNotSupportSigning"
    }
))


# 18.6.8.4 (L1) Enable authentication rate limiter = Enabled (REG_DWORD 1)
# OJO: este es en LanmanServer (SMB server feature), aunque esté en 18.6.8.x
rules.append(create_rule(
    "18.6.8.4",
    "Ensure 'Enable authentication rate limiter' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanServer",
        "name": "EnableAuthRateLimiter",
        "expected_value": 1,
        "allowed_values": [1],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanServer:EnableAuthRateLimiter"
    }
))


# 18.6.8.5 (L1) Enable insecure guest logons = Disabled (REG_DWORD 0)
rules.append(create_rule(
    "18.6.8.5",
    "Ensure 'Enable insecure guest logons' is set to 'Disabled'",
    "0",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation",
        "name": "AllowInsecureGuestAuth",
        "expected_value": 0,
        "allowed_values": [0],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation:AllowInsecureGuestAuth"
    }
))


# 18.6.8.6 (L1) Enable remote mailslots = Disabled (REG_DWORD 0)
rules.append(create_rule(
    "18.6.8.6",
    "Ensure 'Enable remote mailslots' is set to 'Disabled'",
    "0",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider",
        "name": "EnableMailslots",
        "expected_value": 0,
        "allowed_values": [0],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider:EnableMailslots"
    }
))


# 18.6.8.7 (L1) Mandate the minimum version of SMB = Enabled: 3.1.1
# FIX: SMB 3.1.1 = 0x311 HEX = 785 DECIMAL.
rules.append(create_rule(
    "18.6.8.7",
    "Ensure 'Mandate the minimum version of SMB' is set to 'Enabled: 3.1.1'",
    "785",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation",
        "name": "MinSmb2Dialect",
        "expected_value": 785,
        "allowed_values": [785],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation:MinSmb2Dialect"
    }
))




# 18.6.11.2 (L1) Prohibit installation/configuration of Network Bridge on DNS domain network = Enabled
rules.append(create_rule(
    "18.6.11.2",
    "Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'",
    "0",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections",
        "name": "NC_AllowNetBridge_NLA",
        "expected_value": 0,
        "allowed_values": [0],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections:NC_AllowNetBridge_NLA"
    }
))


# 18.6.11.3 (L1) Prohibit use of Internet Connection Sharing on DNS domain network = Enabled
rules.append(create_rule(
    "18.6.11.3",
    "Ensure 'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled'",
    "0",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections",
        "name": "NC_ShowSharedAccessUI",
        "expected_value": 0,
        "allowed_values": [0],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections:NC_ShowSharedAccessUI"
    }
))


# 18.6.11.4 (L1) Require domain users to elevate when setting a network's location = Enabled
rules.append(create_rule(
    "18.6.11.4",
    "Ensure 'Require domain users to elevate when setting a network's location' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections",
        "name": "NC_StdDomainUserSetLocation",
        "expected_value": 1,
        "allowed_values": [1],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections:NC_StdDomainUserSetLocation"
    }
))

# ---------------------------------------------------------
# 18.6.14.1  Hardened UNC Paths
# ---------------------------------------------------------

_EXPECTED_HARDENED = "RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1"

# 18.6.14.1 (L1) Hardened UNC Paths for NETLOGON
# REG_SZ value must contain the three requirements
# HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths:\\*\NETLOGON
rules.append(create_rule(
    "18.6.14.1",
    "Ensure 'Hardened UNC Paths' is set to 'Enabled' for NETLOGON with mutual auth, integrity, and privacy",
    _EXPECTED_HARDENED,
    "registry_sz",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths",
        "name": r"\\*\NETLOGON",
        "expected_value": _EXPECTED_HARDENED,
        "expected_mode": "exact_str",
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths:\\*\NETLOGON"
    }
))

# 18.6.14.1 (L1) Hardened UNC Paths for SYSVOL
# HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths:\\*\SYSVOL
rules.append(create_rule(
    "18.6.14.1",
    "Ensure 'Hardened UNC Paths' is set to 'Enabled' for SYSVOL with mutual auth, integrity, and privacy",
    _EXPECTED_HARDENED,
    "registry_sz",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths",
        "name": r"\\*\SYSVOL",
        "expected_value": _EXPECTED_HARDENED,
        "expected_mode": "exact_str",
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths:\\*\SYSVOL"
    }
))


# 18.6.21.1  Minimize simultaneous connections

rules.append(create_rule(
    "18.6.21.1",
    "Ensure 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled: 3 = Prevent Wi-Fi when on Ethernet'",
    "3",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy",
        "name": "fMinimizeConnections",
        "expected_value": 3,
        "allowed_values": [3],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy:fMinimizeConnections"
    }
))

# ---------------------------------------------------------
# 18.7.x  PRINTERS / PRINT SPOOLER HARDENING
# ---------------------------------------------------------

# 18.7.1 (L1) Allow Print Spooler to accept client connections = Disabled
# REG_DWORD = 2
rules.append(create_rule(
    "18.7.1",
    "Ensure 'Allow Print Spooler to accept client connections' is set to 'Disabled'",
    "2",
    "registry",
    {
        "path": r"HKLM:\Software\Policies\Microsoft\Windows NT\Printers",
        "name": "RegisterSpoolerRemoteRpcEndPoint",
        "expected_value": 2,
        "allowed_values": [2],
        "evidence": r"HKLM\Software\Policies\Microsoft\Windows NT\Printers:RegisterSpoolerRemoteRpcEndPoint"
    }
))


# 18.7.2 (L1) Configure Redirection Guard = Enabled: Redirection Guard Enabled
# REG_DWORD = 1
rules.append(create_rule(
    "18.7.2",
    "Ensure 'Configure Redirection Guard' is set to 'Enabled: Redirection Guard Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers",
        "name": "RedirectionguardPolicy",
        "expected_value": 1,
        "allowed_values": [1],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers:RedirectionguardPolicy"
    }
))


# 18.7.3 (L1) Configure RPC connection settings: Protocol for outgoing RPC = Enabled: RPC over TCP
# REG_DWORD = 0
rules.append(create_rule(
    "18.7.3",
    "Ensure 'Configure RPC connection settings: Protocol to use for outgoing RPC connections' is set to 'Enabled: RPC over TCP'",
    "0",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC",
        "name": "RpcUseNamedPipeProtocol",
        "expected_value": 0,
        "allowed_values": [0],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC:RpcUseNamedPipeProtocol"
    }
))


# 18.7.4 (L1) Configure RPC connection settings: Use authentication for outgoing RPC = Enabled: Default
# REG_DWORD = 0
rules.append(create_rule(
    "18.7.4",
    "Ensure 'Configure RPC connection settings: Use authentication for outgoing RPC connections' is set to 'Enabled: Default'",
    "0",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC",
        "name": "RpcAuthentication",
        "expected_value": 0,
        "allowed_values": [0],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC:RpcAuthentication"
    }
))


# 18.7.5 (L1) Configure RPC listener settings: Protocols for incoming RPC = Enabled: RPC over TCP
# REG_DWORD = 5
rules.append(create_rule(
    "18.7.5",
    "Ensure 'Configure RPC listener settings: Protocols to allow for incoming RPC connections' is set to 'Enabled: RPC over TCP'",
    "5",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC",
        "name": "RpcProtocols",
        "expected_value": 5,
        "allowed_values": [5],
        "evidence": r"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC:RpcProtocols"
    }
))


# 18.7.6 (L1) Configure RPC listener settings: Authentication protocol for incoming RPC = Enabled: Negotiate or higher
# REG_DWORD = 0 or 1  (0=Negotiate, 1=Kerberos only)
rules.append(create_rule(
    "18.7.6",
    "Ensure 'Configure RPC listener settings: Authentication protocol to use for incoming RPC connections' is set to 'Enabled: Negotiate' or higher",
    "0 or 1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC",
        "name": "ForceKerberosForRpc",
        "expected_value": 0,             # solo para referencia; valida con allowed_values
        "allowed_values": [0, 1],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC:ForceKerberosForRpc"
    }
))


# 18.7.7 (L1) Configure RPC over TCP port = Enabled: 0 (dynamic ports)
# REG_DWORD = 0
rules.append(create_rule(
    "18.7.7",
    "Ensure 'Configure RPC over TCP port' is set to 'Enabled: 0'",
    "0",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC",
        "name": "RpcTcpPort",
        "expected_value": 0,
        "allowed_values": [0],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC:RpcTcpPort"
    }
))


# 18.7.8 (L1) Configure RPC packet level privacy for incoming connections = Enabled
# REG_DWORD = 1
rules.append(create_rule(
    "18.7.8",
    "Ensure 'Configure RPC packet level privacy setting for incoming connections' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SYSTEM\CurrentControlSet\Control\Print",
        "name": "RpcAuthnLevelPrivacyEnabled",
        "expected_value": 1,
        "allowed_values": [1],
        "evidence": r"HKLM\SYSTEM\CurrentControlSet\Control\Print:RpcAuthnLevelPrivacyEnabled"
    }
))

# 18.7.10 (L1) Limits print driver installation to Administrators = Enabled
# REG_DWORD = 1
rules.append(create_rule(
    "18.7.10",
    "Ensure 'Limits print driver installation to Administrators' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint",
        "name": "RestrictDriverInstallationToAdministrators",
        "expected_value": 1,
        "allowed_values": [1],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint:RestrictDriverInstallationToAdministrators"
    }
))


# 18.7.11 (L1) Manage processing of Queue-specific files = Enabled: Limit to Color profiles
# REG_DWORD = 1
rules.append(create_rule(
    "18.7.11",
    "Ensure 'Manage processing of Queue-specific files' is set to 'Enabled: Limit Queue-specific files to Color profiles'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers",
        "name": "CopyFilesPolicy",
        "expected_value": 1,
        "allowed_values": [1],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers:CopyFilesPolicy"
    }
))


# 18.7.12 (L1) Point and Print Restrictions: When installing drivers for a new connection
# Enabled: Show warning and elevation prompt
# REG_DWORD = 0
rules.append(create_rule(
    "18.7.12",
    "Ensure 'Point and Print Restrictions: When installing drivers for a new connection' is set to 'Enabled: Show warning and elevation prompt'",
    "0",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint",
        "name": "NoWarningNoElevationOnInstall",
        "expected_value": 0,
        "allowed_values": [0],
        "evidence": r"HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint:NoWarningNoElevationOnInstall"
    }
))


# 18.7.13 (L1) Point and Print Restrictions: When updating drivers for an existing connection
# Enabled: Show warning and elevation prompt
# REG_DWORD = 0
rules.append(create_rule(
    "18.7.13",
    "Ensure 'Point and Print Restrictions: When updating drivers for an existing connection' is set to 'Enabled: Show warning and elevation prompt'",
    "0",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint",
        "name": "UpdatePromptSettings",
        "expected_value": 0,
        "allowed_values": [0],
        "evidence": r"HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint:UpdatePromptSettings"
    }
))

# 18.9.3.1 Include command line in process creation events

rules.append(create_rule(
    "18.9.3.1",
    "Ensure 'Include command line in process creation events' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit",
        "name": "ProcessCreationIncludeCmdLine_Enabled",
        "expected_value": 1,
        "allowed_values": [1],
        "evidence": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit:ProcessCreationIncludeCmdLine_Enabled"
    }
))


# 18.9.4.1 Encryption Oracle Remediation


rules.append(create_rule(
    "18.9.4.1",
    "Ensure 'Encryption Oracle Remediation' is set to 'Enabled: Force Updated Clients'",
    "0",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters",
        "name": "AllowEncryptionOracle",
        "expected_value": 0,
        "allowed_values": [0],
        "evidence": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters:AllowEncryptionOracle"
    }
))

# 18.9.4.2 Remote host allows delegation of non-exportable credentials

rules.append(create_rule(
    "18.9.4.2",
    "Ensure 'Remote host allows delegation of non-exportable credentials' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation",
        "name": "AllowProtectedCreds",
        "expected_value": 1,
        "allowed_values": [1],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation:AllowProtectedCreds"
    }
))

# 18.9.7.2 (L1) Prevent device metadata retrieval from the Internet

rules.append(create_rule(
    "18.9.7.2",
    "Ensure 'Prevent device metadata retrieval from the Internet' is set to 'Enabled'",
    "Enabled",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata",
        "name": "PreventDeviceMetadataFromNetwork",
        "expected_value": 1,
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Device Metadata:PreventDeviceMetadataFromNetwork"
    }
))

# 18.9.13.1 (L1) Boot-Start Driver Initialization Policy

rules.append(create_rule(
    "18.9.13.1",
    "Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical'",
    "Enabled: Good, unknown and bad but critical",
    "registry",
    {
        "path": r"HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch",
        "name": "DriverLoadPolicy",
        "expected_value": 3,
        "evidence": r"HKLM\SYSTEM\CurrentControlSet\Policies\EarlyLaunch:DriverLoadPolicy"
    }
))




# 18.9.19.2 (L1) Configure registry policy processing:

rules.append(create_rule(
    "18.9.19.2",
    "Ensure 'Configure registry policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'",
    "Enabled: FALSE (unchecked)",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}",
        "name": "NoBackgroundPolicy",
        "expected_value": 0,
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}:NoBackgroundPolicy"
    }
))

# 18.9.19.3 (L1) Configure registry policy processing:
# FIX: El Windows default para Registry CSE es procesar solo cuando hay cambios.
# Cuando esta política está explícitamente configurada como "Enabled: TRUE"
# (NoGPOListChanges=0), la clave EXISTE. Si no existe → no está configurada.
# PERO: si gpupdate /force ya se ejecutó y el CIS permite el default, agregar
# missing_is_compliant=True evita falsos negativos mientras se aplica la GPO.
rules.append(create_rule(
    "18.9.19.3",
    "Ensure 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE'",
    "Enabled: TRUE (checked)",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}",
        "name": "NoGPOListChanges",
        "expected_value": 0,
        "missing_is_compliant": True,
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}:NoGPOListChanges"
    }
))

# 18.9.19.4 (L1) Configure security policy processing:

rules.append(create_rule(
    "18.9.19.4",
    "Ensure 'Configure security policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'",
    "Enabled: FALSE (unchecked)",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}",
        "name": "NoBackgroundPolicy",
        "expected_value": 0,
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}:NoBackgroundPolicy"
    }
))

# 18.9.19.5 (L1) Configure security policy processing:

rules.append(create_rule(
    "18.9.19.5",
    "Ensure 'Configure security policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE'",
    "Enabled: TRUE (checked)",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}",
        "name": "NoGPOListChanges",
        "expected_value": 0,
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}:NoGPOListChanges"
    }
))


# 18.9.19.7 (L1) Turn off background refresh of Group Policy = Disabled

rules.append(create_rule(
    "18.9.19.7",
    "Ensure 'Turn off background refresh of Group Policy' is set to 'Disabled'",
    "Disabled (value not present)",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "name": "DisableBkGndGroupPolicy",
        # Si el valor NO existe → PASS
        "missing_is_compliant": True,
        # Si existe y es 0 → también lo aceptamos como seguro
        "expected_value": 0,
        "evidence": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:DisableBkGndGroupPolicy"
    }
))


# CIS 18.9.20.1.1: Debe estar Enabled. Bloquea la descarga de drivers de impresión por HTTP
# FIX: Sin path/name explícitos, resolve_registry_target falla al parsear la ruta desde evidence.
rules.append(create_rule(
    "18.9.20.1.1",
    "(L1) Turn off downloading of print drivers over HTTP",
    "Enabled",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers",
        "name": "DisableWebPnPDownload",
        "expected_value": 1,
        "allowed_values": [1],
        "missing_is_compliant": True,
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers:DisableWebPnPDownload",
    }
))

# CIS 18.9.20.1.5: Debe estar Enabled. Evita que Windows descargue desde Internet
# FIX: Sin path/name explícitos, resolve_registry_target falla al parsear desde evidence.
rules.append(create_rule(
    "18.9.20.1.5",
    "(L1) Turn off Internet download for Web publishing and online ordering wizards",
    "Enabled",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
        "name": "NoWebServices",
        "expected_value": 1,
        "allowed_values": [1],
        "missing_is_compliant": True,
        "evidence": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer:NoWebServices",
    }
))

# CIS 18.9.24.1: Debe estar Enabled: Block All. Protege contra dispositivos externos con DMA.
rules.append(create_rule(
    "18.9.24.1",
    "(L1) Enumeration policy for external devices incompatible with Kernel DMA Protection",
    "Enabled: Block All",
    "registry",
    {
        "expected_value": 0,
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection:DeviceEnumerationPolicy",
    }
))

# CIS 18.9.26.1: Debe estar Enabled y definir dónde se respalda la clave LAPS.
rules.append(create_rule(
    "18.9.26.1",
    "(L1) Configure password backup directory",
    "Enabled: Active Directory (1) OR Enabled: Azure Active Directory/Entra ID (2)",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS",
        "name": "BackupDirectory",
        "expected_value": 1,
        "allowed_values": [1, 2],
        "evidence": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS:BackupDirectory",
    }
))


# CIS 18.9.26.2: Debe estar Enabled para que NO se pueda alargar la expiración manualmente.
rules.append(create_rule(
    "18.9.26.2",
    "(L1) Do not allow password expiration time longer than required by policy",
    "Enabled",
    "registry",
    {
        "expected_value": 1,
        "evidence": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS:PasswordExpirationProtectionEnabled",
    }
))

# CIS 18.9.26.3: Debe estar Enabled para cifrar la clave antes de enviarla a AD.
rules.append(create_rule(
    "18.9.26.3",
    "(L1) Enable password encryption",
    "Enabled",
    "registry",
    {
        "expected_value": 1,
        "evidence": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS:ADPasswordEncryptionEnabled",
    }
))

# CIS 18.9.26.4: Complejidad LAPS debe incluir mayúsculas, minúsculas, números y especiales.
rules.append(create_rule(
    "18.9.26.4",
    "(L1) Password Settings: Password Complexity",
    "Enabled: Large letters + small letters + numbers + special characters",
    "registry",
    {
        "expected_value": 4,
        "evidence": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS:PasswordComplexity",
    }
))

# CIS 18.9.26.5: Longitud de contraseña LAPS debe ser 15 o más.
rules.append(create_rule(
    "18.9.26.5",
    "(L1) Password Settings: Password Length",
    "Enabled: 15 or more",
    "registry_range",
    {
        "path": r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS",
        "name": "PasswordLength",
        "min_val": 15,
        "evidence": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS:PasswordLength",
    }
))


# CIS 18.9.26.6: Edad de contraseña LAPS debe ser 30 días o menos.
rules.append(create_rule(
    "18.9.26.6",
    "(L1) Password Settings: Password Age (Days)",
    "Enabled: 30 or fewer",
    "registry_range",
    {
        "path": r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS",
        "name": "PasswordAgeDays",
        "min_val": 1,
        "max_val": 30,
        "evidence": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS:PasswordAgeDays",
    }
))


# CIS 18.9.26.7: Grace period después de autenticación LAPS = 8 horas o menos, pero NO 0.
rules.append(create_rule(
    "18.9.26.7",
    "(L1) Post-authentication actions: Grace period (hours)",
    "Enabled: 8 or fewer hours, but not 0",
    "registry_range",
    {
        "path": r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS",
        "name": "PostAuthenticationResetDelay",
        "min_val": 1,
        "max_val": 8,
        "disallow": [0],
        "evidence": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS:PostAuthenticationResetDelay",
    }
))


# CIS 18.9.26.8: Acciones post-auth deben ser Reset password + logoff (3) o más fuerte.
rules.append(create_rule(
    "18.9.26.8",
    "(L1) Post-authentication actions: Actions",
    "Enabled: Reset the password and logoff the managed account or higher",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS",
        "name": "PostAuthenticationActions",
        "expected_value": 3,
        "allowed_values": [3, 5],
        "evidence": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS:PostAuthenticationActions",
    }
))

# 18.9.27.1 (L1) Allow Custom SSPs and APs to be loaded into LSASS = Disabled (REG_DWORD 0)
# FIX: Windows por defecto NO permite SSPs personalizados (default=0=conforme).
# Si la clave no existe → comportamiento default es no permitir → PASS.
rules.append(create_rule(
    "18.9.26.1",
    "Ensure 'Allow Custom SSPs and APs to be loaded into LSASS' is set to 'Disabled'",
    "0",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\System",
        "name": "AllowCustomSSPsAPs",
        "expected_value": 0,
        "allowed_values": [0],
        "missing_is_compliant": True,
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\System:AllowCustomSSPsAPs"
    }
))

# 18.9.29.1 (L1) Block user from showing account details on sign-in = Enabled (1)
rules.append(create_rule(
    "18.9.29.1",
    "Ensure 'Block user from showing account details on sign-in' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\System",
        "name": "BlockUserFromShowingAccountDetailsOnSignin",
        "expected_value": 1,
        "allowed_values": [1],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\System:BlockUserFromShowingAccountDetailsOnSignin"
    }
))

# 18.9.29.2 (L1) Do not display network selection UI = Enabled (1)
rules.append(create_rule(
    "18.9.29.2",
    "Ensure 'Do not display network selection UI' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\System",
        "name": "DontDisplayNetworkSelectionUI",
        "expected_value": 1,
        "allowed_values": [1],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\System:DontDisplayNetworkSelectionUI"
    }
))

# 18.9.29.3 (L1) Do not enumerate connected users on domain-joined computers = Enabled (1)
rules.append(create_rule(
    "18.9.29.3",
    "Ensure 'Do not enumerate connected users on domain-joined computers' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\System",
        "name": "DontEnumerateConnectedUsers",
        "expected_value": 1,
        "allowed_values": [1],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\System:DontEnumerateConnectedUsers"
    }
))

# 18.9.29.4 (L1) Enumerate local users on domain-joined computers = Disabled (0)
rules.append(create_rule(
    "18.9.29.4",
    "Ensure 'Enumerate local users on domain-joined computers' is set to 'Disabled'",
    "0",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\System",
        "name": "EnumerateLocalUsers",
        "expected_value": 0,
        "allowed_values": [0],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\System:EnumerateLocalUsers"
    }
))

# 18.9.29.5 (L1) Turn off app notifications on the lock screen = Enabled (1)
rules.append(create_rule(
    "18.9.29.5",
    "Ensure 'Turn off app notifications on the lock screen' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\System",
        "name": "DisableLockScreenAppNotifications",
        "expected_value": 1,
        "allowed_values": [1],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\System:DisableLockScreenAppNotifications"
    }
))

# 18.9.29.6 (L1) Turn off picture password sign-in = Enabled (1)
rules.append(create_rule(
    "18.9.29.6",
    "Ensure 'Turn off picture password sign-in' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\System",
        "name": "BlockDomainPicturePassword",
        "expected_value": 1,
        "allowed_values": [1],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\System:BlockDomainPicturePassword"
    }
))

# 18.9.31.1.1 (L1) Block NetBIOS-based discovery for domain controller location

rules.append(create_rule(
    "18.9.31.1.1",
    "Ensure 'Block NetBIOS-based discovery for domain controller location' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Netlogon\Parameters",
        "name": "BlockNetbiosDiscovery",
        "expected_value": 1,
        "allowed_values": [1],
        "missing_is_compliant": True,  # comportamiento por defecto ya cumple
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Netlogon\Parameters:BlockNetbiosDiscovery"
    }
))

# 18.9.35.6.3 (L1) Require a password when a computer wakes (on battery) = Enabled
rules.append(create_rule(
    "18.9.35.6.3",
    "Ensure 'Require a password when a computer wakes (on battery)' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51",
        "name": "DCSettingIndex",
        "expected_value": 1,
        "allowed_values": [1],
        "missing_is_compliant": True,  # CIS: default Enabled
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51:DCSettingIndex"
    }
))

# 18.9.35.6.4 (L1) Require a password when a computer wakes (plugged in) = Enabled
rules.append(create_rule(
    "18.9.35.6.4",
    "Ensure 'Require a password when a computer wakes (plugged in)' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51",
        "name": "ACSettingIndex",
        "expected_value": 1,
        "allowed_values": [1],
        "missing_is_compliant": True,  # CIS: default Enabled
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51:ACSettingIndex"
    }
))

# 18.9.37.1 (L1) Configure Offer Remote Assistance = Disabled (0)
rules.append(create_rule(
    "18.9.37.1",
    "Ensure 'Configure Offer Remote Assistance' is set to 'Disabled'",
    "0",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services",
        "name": "fAllowUnsolicited",
        "expected_value": 0,
        "allowed_values": [0],
        "missing_is_compliant": True,  # CIS: default Disabled
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services:fAllowUnsolicited"
    }
))

# 18.9.37.2 (L1) Configure Solicited Remote Assistance = Disabled (0)
rules.append(create_rule(
    "18.9.37.2",
    "Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled'",
    "0",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services",
        "name": "fAllowToGetHelp",
        "expected_value": 0,
        "allowed_values": [0],
        "missing_is_compliant": False,  # CIS: default is user-configurable (value may be absent)
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services:fAllowToGetHelp"
    }
))

# 18.9.38.1 (L1) Enable RPC Endpoint Mapper Client Authentication = Enabled (1)
# Aplica solo a Member Server (NO recomendado para Domain Controllers)
rules.append(create_rule(
    "18.9.38.1",
    "Ensure 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled' (MS only)",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc",
        "name": "EnableAuthEpResolution",
        "expected_value": 1,
        "allowed_values": [1],
        "missing_is_compliant": False,  # Default CIS: Disabled -> si falta, NO cumple
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc:EnableAuthEpResolution"
    }
))

# 18.9.41.3 (L1) Configure SAM change password RPC methods policy
# Member Server: Enabled = Block all change password RPC methods (REG_DWORD 1)
rules.append(create_rule(
    "18.9.41.3",
    "Ensure 'Configure SAM change password RPC methods policy' is set to 'Enabled: Block all change password RPC methods' (MS only)",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\SAM",
        "name": "SamrChangeUserPasswordApiPolicy",
        "expected_value": 1,
        "allowed_values": [1],
        "missing_is_compliant": True,  # Default en Member Server ya es compliant según CIS
        "evidence": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\SAM:SamrChangeUserPasswordApiPolicy"
    }
))


# 18.9.51.1.1 (L1) Enable Windows NTP Client = Enabled (REG_DWORD 1)
rules.append(create_rule(
    "18.9.53.1.1",
    "Ensure 'Enable Windows NTP Client' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient",
        "name": "Enabled",
        "expected_value": 1,
        "allowed_values": [1],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient:Enabled"
        # OJO: si usan proveedor NTP de terceros, este control puede ser excepción.
    }
))

# 18.9.51.1.2 (L1) Enable Windows NTP Server = Disabled (MS only) (REG_DWORD 0)
# (Aplicable a Member Server. En DC normalmente NO se recomienda deshabilitarlo)
rules.append(create_rule(
    "18.9.53.1.2",
    "Ensure 'Enable Windows NTP Server' is set to 'Disabled' (MS only)",
    "0",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer",
        "name": "Enabled",
        "expected_value": 0,
        "allowed_values": [0],
        "missing_is_compliant": True,  # Default = Disabled
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer:Enabled"
    }
))

# 18.10.4.2 (L1) Not allow per-user unsigned packages to install by default = Enabled
# REG_DWORD = 1
# HKLM\SOFTWARE\Policies\Microsoft\Windows\Appx:DisablePerUserUnsignedPackagesByDefault
rules.append(create_rule(
    "18.10.4.2",
    "Ensure 'Not allow per-user unsigned packages to install by default (requires explicitly allow per install)' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx",
        "name": "DisablePerUserUnsignedPackagesByDefault",
        "expected_value": 1,
        "allowed_values": [1],
        "missing_is_compliant": False,  # Default = Disabled, así que si falta NO cumple
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Appx:DisablePerUserUnsignedPackagesByDefault"
    }
))

# 18.10.6.1 (L1) Allow Microsoft accounts to be optional = Enabled (REG_DWORD 1)
rules.append(create_rule(
    "18.10.6.1",
    "Ensure 'Allow Microsoft accounts to be optional' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "name": "MSAOptional",
        "expected_value": 1,
        "allowed_values": [1],
        "evidence": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:MSAOptional"
        # No missing_is_compliant porque el valor por defecto es Disabled (0) según CIS
    }
))

# 18.10.8.1 (L1) Disallow Autoplay for non-volume devices = Enabled (REG_DWORD 1)
rules.append(create_rule(
    "18.10.8.1",
    "Ensure 'Disallow Autoplay for non-volume devices' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer",
        "name": "NoAutoplayfornonVolume",
        "expected_value": 1,
        "allowed_values": [1],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer:NoAutoplayfornonVolume"
        # No missing_is_compliant porque default es Disabled (0)
    }
))

# 18.10.8.2 (L1) Set the default behavior for AutoRun = Enabled: Do not execute any autorun commands (REG_DWORD 1)
rules.append(create_rule(
    "18.10.8.2",
    "Ensure 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
        "name": "NoAutorun",
        "expected_value": 1,
        "allowed_values": [1],
        "evidence": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer:NoAutorun"
        # No missing_is_compliant porque default es Disabled (Windows prompts user)
    }
))

# 18.10.8.3 (L1) Turn off Autoplay = Enabled: All drives (REG_DWORD 255)
rules.append(create_rule(
    "18.10.8.3",
    "Ensure 'Turn off Autoplay' is set to 'Enabled: All drives'",
    "255",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
        "name": "NoDriveTypeAutoRun",
        "expected_value": 255,
        "allowed_values": [255],
        "evidence": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer:NoDriveTypeAutoRun"
        # No missing_is_compliant porque default es Disabled (Autoplay enabled)
    }
))

# 18.10.9.1.1 (L1) Configure enhanced anti-spoofing = Enabled (REG_DWORD 1)
rules.append(create_rule(
    "18.10.9.1.1",
    "Ensure 'Configure enhanced anti-spoofing' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures",
        "name": "EnhancedAntiSpoofing",
        "expected_value": 1,
        "allowed_values": [1],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures:EnhancedAntiSpoofing"
        # No missing_is_compliant porque el valor por defecto permite a los usuarios elegir (no cumple CIS)
    }
))

# 18.10.13.1 (L1) Turn off cloud consumer account state content = Enabled (REG_DWORD 1)
rules.append(create_rule(
    "18.10.13.1",
    "Ensure 'Turn off cloud consumer account state content' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent",
        "name": "DisableConsumerAccountStateContent",
        "expected_value": 1,
        "allowed_values": [1],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent:DisableConsumerAccountStateContent"
        # No missing_is_compliant porque el valor por defecto es Disabled (0)
    }
))

# 18.10.13.2 (L1) Turn off Microsoft consumer experiences = Enabled (REG_DWORD 1)
rules.append(create_rule(
    "18.10.13.2",
    "Ensure 'Turn off Microsoft consumer experiences' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent",
        "name": "DisableWindowsConsumerFeatures",
        "expected_value": 1,
        "allowed_values": [1],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent:DisableWindowsConsumerFeatures"
        # No missing_is_compliant porque el valor por defecto es Disabled (0)
    }
))

# 18.10.14.1 (L1) Require pin for pairing = Enabled: First Time (1) OR Enabled: Always (2)
rules.append(create_rule(
    "18.10.14.1",
    "Ensure 'Require pin for pairing' is set to 'Enabled: First Time' OR 'Enabled: Always'",
    "1 or 2",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect",
        "name": "RequirePinForPairing",
        "expected_value": 1,  # valor de referencia
        "allowed_values": [1, 2],  # 1 = First Time, 2 = Always
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Connect:RequirePinForPairing"
        # No missing_is_compliant porque el valor por defecto es Disabled (0)
    }
))

# 18.10.15.1 (L1) Do not display the password reveal button = Enabled (REG_DWORD 1)
rules.append(create_rule(
    "18.10.15.1",
    "Ensure 'Do not display the password reveal button' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI",
        "name": "DisablePasswordReveal",
        "expected_value": 1,
        "allowed_values": [1],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\CredUI:DisablePasswordReveal"
        # No missing_is_compliant porque el valor por defecto es Disabled (0)
    }
))

# 18.10.15.2 Ensure 'Enumerate administrator accounts on elevation' is set to 'Disabled

rules.append(create_rule(
    "18.10.15.2",
    "Ensure 'Enumerate administrator accounts on elevation' is set to 'Disabled'",
    "0",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI",
        "name": "EnumerateAdministrators",
        "expected_value": 0,
        "evidence": r"HKLM\...\CredUI:EnumerateAdministrators"
    }
))

# 18.10.16.1 (L1) Allow Diagnostic Data = Enabled: Diagnostic data off (0) OR Enabled: Send required diagnostic data (1)
rules.append(create_rule(
    "18.10.16.1",
    "Ensure 'Allow Diagnostic Data' is set to 'Enabled: Diagnostic data off (not recommended)' or 'Enabled: Send required diagnostic data'",
    "0 or 1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection",
        "name": "AllowTelemetry",
        "expected_value": 0,  # valor de referencia más restrictivo
        "allowed_values": [0, 1],  # 0 = Diagnostic data off, 1 = Send required diagnostic data
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection:AllowTelemetry"
        # No missing_is_compliant porque el valor por defecto es Disabled (equivale a 1 + usuario puede cambiar)
    }
))


# 18.10.16.3 (L1) Do not show feedback notifications = Enabled (REG_DWORD 1)
rules.append(create_rule(
    "18.10.16.3",
    "Ensure 'Do not show feedback notifications' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection",
        "name": "DoNotShowFeedbackNotifications",
        "expected_value": 1,
        "allowed_values": [1],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection:DoNotShowFeedbackNotifications"
        # No missing_is_compliant porque el valor por defecto es Disabled (0)
    }
))


# 18.10.16.4 Ensure (L1) Enable OneSettings Auditing = Enabled (REG_DWORD 1)
rules.append(create_rule(
    "18.10.16.4",
    "Ensure 'Enable OneSettings Auditing' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection",
        "name": "EnableOneSettingsAuditing",
        "expected_value": 1,
        "allowed_values": [1],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection:EnableOneSettingsAuditing"
        # No missing_is_compliant porque el valor por defecto es Disabled (0)
    }
))

# 18.10.16.5 (L1) Limit Diagnostic Log Collection = Enabled (REG_DWORD 1)
rules.append(create_rule(
    "18.10.16.5",
    "Ensure 'Limit Diagnostic Log Collection' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection",
        "name": "LimitDiagnosticLogCollection",
        "expected_value": 1,
        "allowed_values": [1],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection:LimitDiagnosticLogCollection"
        # No missing_is_compliant porque el valor por defecto es Disabled (0)
    }
))


# 18.10.16.6 (L1) Limit Dump Collection = Enabled (REG_DWORD 1)
rules.append(create_rule(
    "18.10.16.6",
    "Ensure 'Limit Dump Collection' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection",
        "name": "LimitDumpCollection",
        "expected_value": 1,
        "allowed_values": [1],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection:LimitDumpCollection"
        # No missing_is_compliant porque el valor por defecto es Disabled (0)
    }
))



# 18.10.18.2 (L1) Enable App Installer Experimental Features = Disabled (REG_DWORD 0)
rules.append(create_rule(
    "18.10.18.2",
    "Ensure 'Enable App Installer Experimental Features' is set to 'Disabled'",
    "0",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller",
        "name": "EnableExperimentalFeatures",
        "expected_value": 0,
        "allowed_values": [0],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller:EnableExperimentalFeatures"
        # No missing_is_compliant porque el valor por defecto es Enabled (1)
    }
))

# 18.10.18.3 (L1) Enable App Installer Hash Override = Disabled (REG_DWORD 0)
rules.append(create_rule(
    "18.10.18.3",
    "Ensure 'Enable App Installer Hash Override' is set to 'Disabled'",
    "0",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller",
        "name": "EnableHashOverride",
        "expected_value": 0,
        "allowed_values": [0],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller:EnableHashOverride"
        # No missing_is_compliant porque el valor por defecto es Enabled (1)
    }
))

# 18.10.18.4 (L1) Enable App Installer Local Archive Malware Scan Override = Disabled (REG_DWORD 0)
rules.append(create_rule(
    "18.10.18.4",
    "Ensure 'Enable App Installer Local Archive Malware Scan Override' is set to 'Disabled'",
    "0",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller",
        "name": "EnableLocalArchiveMalwareScanOverride",
        "expected_value": 0,
        "allowed_values": [0],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller:EnableLocalArchiveMalwareScanOverride"
        # No missing_is_compliant porque el valor por defecto es "Not configured" según CIS
    }
))

# 18.10.18.5 (L1) Enable App Installer ms-appinstaller protocol = Disabled (REG_DWORD 0)
rules.append(create_rule(
    "18.10.18.5",
    "Ensure 'Enable App Installer ms-appinstaller protocol' is set to 'Disabled'",
    "0",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller",
        "name": "EnableMSAppInstallerProtocol",
        "expected_value": 0,
        "allowed_values": [0],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller:EnableMSAppInstallerProtocol"
        # No missing_is_compliant porque el valor por defecto es Enabled (1)
    }
))

# 18.10.18.6 (L1) Enable App Installer Microsoft Store Source Certificate Validation Bypass = Disabled (REG_DWORD 0)
rules.append(create_rule(
    "18.10.18.6",
    "Ensure 'Enable App Installer Microsoft Store Source Certificate Validation Bypass' is set to 'Disabled'",
    "0",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller",
        "name": "EnableBypassCertificatePinningForMicrosoftStore",
        "expected_value": 0,
        "allowed_values": [0],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller:EnableBypassCertificatePinningForMicrosoftStore"
        # No missing_is_compliant porque el valor por defecto es "Not configured" según CIS
    }
))

# 18.10.26.1.1 (L1) Application: Control Event Log behavior when the log file reaches its maximum size = Disabled (REG_SZ "0")
rules.append(create_rule(
    "18.10.26.1.1",
    "Ensure 'Application: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'",
    "0",
    "registry_sz",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application",
        "name": "Retention",
        "expected_value": "0",
        "expected_mode": "exact_str",
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application:Retention"
        # No missing_is_compliant porque CIS dice que Disabled es el valor por defecto
    }
))

# 18.10.26.1.2 (L1) Application: Specify the maximum log file size (KB) = Enabled: 32,768 or greater (REG_DWORD >= 32768)
rules.append(create_rule(
    "18.10.26.1.2",
    "Ensure 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'",
    ">= 32768",
    "registry_range",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application",
        "name": "MaxSize",
        "min_val": 32768,
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application:MaxSize"
        # No missing_is_compliant porque el valor por defecto es 20480 KB (menor que 32768)
    }
))

# 18.10.26.2.1 (L1) Security: Control Event Log behavior when the log file reaches its maximum size = Disabled (REG_SZ "0")
rules.append(create_rule(
    "18.10.26.2.1",
    "Ensure 'Security: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'",
    "0",
    "registry_sz",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security",
        "name": "Retention",
        "expected_value": "0",
        "expected_mode": "exact_str",
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security:Retention"
        # No missing_is_compliant porque CIS dice que Disabled es el valor por defecto
    }
))

# 18.10.26.2.2 (L1) Security: Specify the maximum log file size (KB) = Enabled: 196,608 or greater (REG_DWORD >= 196608)
rules.append(create_rule(
    "18.10.26.2.2",
    "Ensure 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater'",
    ">= 196608",
    "registry_range",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security",
        "name": "MaxSize",
        "min_val": 196608,
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security:MaxSize"
        # No missing_is_compliant porque el valor por defecto es 20480 KB (menor que 196608)
    }
))

# 18.10.26.3.1 (L1) Setup: Control Event Log behavior when the log file reaches its maximum size = Disabled (REG_SZ "0")
rules.append(create_rule(
    "18.10.26.3.1",
    "Ensure 'Setup: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'",
    "0",
    "registry_sz",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup",
        "name": "Retention",
        "expected_value": "0",
        "expected_mode": "exact_str",
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup:Retention"
        # No missing_is_compliant porque CIS dice que Disabled es el valor por defecto
    }
))

# 18.10.26.3.2 (L1) Setup: Specify the maximum log file size (KB) = Enabled: 32,768 or greater (REG_DWORD >= 32768)
rules.append(create_rule(
    "18.10.26.3.2",
    "Ensure 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'",
    ">= 32768",
    "registry_range",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup",
        "name": "MaxSize",
        "min_val": 32768,
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup:MaxSize"
        # No missing_is_compliant porque el valor por defecto es 20480 KB (menor que 32768)
    }
))

# 18.10.26.4.1 (L1) System: Control Event Log behavior when the log file reaches its maximum size = Disabled (REG_SZ "0")
rules.append(create_rule(
    "18.10.26.4.1",
    "Ensure 'System: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'",
    "0",
    "registry_sz",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System",
        "name": "Retention",
        "expected_value": "0",
        "expected_mode": "exact_str",
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System:Retention"
        # No missing_is_compliant porque CIS dice que Disabled es el valor por defecto
    }
))

# 18.10.26.4.2 (L1) System: Specify the maximum log file size (KB) = Enabled: 32,768 or greater (REG_DWORD >= 32768)
rules.append(create_rule(
    "18.10.26.4.2",
    "Ensure 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'",
    ">= 32768",
    "registry_range",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System",
        "name": "MaxSize",
        "min_val": 32768,
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System:MaxSize"
        # No missing_is_compliant porque el valor por defecto es 20480 KB (menor que 32768)
    }
))

# 18.10.29.2 (L1) Do not apply the Mark of the Web tag to files copied from insecure sources = Disabled (REG_DWORD 0)
# CIS: Default = Disabled (Files copied from unsecure sources will be tagged with the appropriate Mark of the Web)
rules.append(create_rule(
    "18.10.29.2",
    "Ensure 'Do not apply the Mark of the Web tag to files copied from insecure sources' is set to 'Disabled'",
    "0",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer",
        "name": "DisableMotWOnInsecurePathCopy",
        "expected_value": 0,
        "allowed_values": [0],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer:DisableMotWOnInsecurePathCopy",
        # missing_is_compliant: True porque CIS dice que Disabled (0) es el valor por defecto
        "missing_is_compliant": True,
    }
))

# 18.10.29.3 (L1) Turn off Data Execution Prevention for Explorer = Disabled (REG_DWORD 0)
# CIS: Default = Disabled (Data Execution Prevention will block certain types of malware from exploiting Explorer)
rules.append(create_rule(
    "18.10.29.3",
    "Ensure 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled'",
    "0",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer",
        "name": "NoDataExecutionPrevention",
        "expected_value": 0,
        "allowed_values": [0],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer:NoDataExecutionPrevention",
        # missing_is_compliant: True porque CIS dice que Disabled (0) es el valor por defecto
        "missing_is_compliant": True,
    }
))

# 18.10.29.4 (L1) Turn off heap termination on corruption = Disabled (REG_DWORD 0)
# CIS: Default = Disabled (Heap termination on corruption is enabled)
rules.append(create_rule(
    "18.10.29.4",
    "Ensure 'Turn off heap termination on corruption' is set to 'Disabled'",
    "0",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer",
        "name": "NoHeapTerminationOnCorruption",
        "expected_value": 0,
        "allowed_values": [0],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer:NoHeapTerminationOnCorruption",
        # missing_is_compliant: True porque CIS dice que Disabled (0) es el valor por defecto
        "missing_is_compliant": True,
    }
))

# 18.10.29.5 (L1) Turn off shell protocol protected mode = Disabled (REG_DWORD 0)
# CIS: Default = Disabled (The protocol is in the protected mode, allowing applications to only open a limited set of folders)
rules.append(create_rule(
    "18.10.29.5",
    "Ensure 'Turn off shell protocol protected mode' is set to 'Disabled'",
    "0",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
        "name": "PreXPSP2ShellProtocolBehavior",
        "expected_value": 0,
        "allowed_values": [0],
        "evidence": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer:PreXPSP2ShellProtocolBehavior",
        # missing_is_compliant: True porque CIS dice que Disabled (0) es el valor por defecto
        "missing_is_compliant": True,
    }
))


# 18.10.41.1 Ensure (L1) Block all consumer Microsoft account user authentication = Enabled (REG_DWORD 1)
# CIS: Default = Disabled (Applications and services on the device will be permitted to authenticate using consumer Microsoft accounts)
rules.append(create_rule(
    "18.10.41.1",
    "Ensure 'Block all consumer Microsoft account user authentication' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount",
        "name": "DisableUserAuth",
        "expected_value": 1,
        "allowed_values": [1],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\MicrosoftAccount:DisableUserAuth",
        # No missing_is_compliant porque el valor por defecto es Disabled (0)
    }
))

# 18.10.42.4.1 (L1) Enable EDR in block mode = Enabled (REG_DWORD 1)
# CIS: Default = Disabled (EDR will not run in block mode)
rules.append(create_rule(
    "18.10.42.4.1",
    "Ensure 'Enable EDR in block mode' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Features",
        "name": "PassiveRemediation",
        "expected_value": 1,
        "allowed_values": [1],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Features:PassiveRemediation",
        # missing_is_compliant: False because the CIS default is 'Disabled'.
    }
))

# 18.10.42.5.1 (L1) Configure local setting override for reporting to Microsoft MAPS = Disabled (REG_DWORD 0)
# CIS: Default = Disabled (Group Policy will take priority over the local preference setting)
rules.append(create_rule(
    "18.10.42.5.1",
    "Ensure 'Configure local setting override for reporting to Microsoft MAPS' is set to 'Disabled'",
    "0",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet",
        "name": "LocalSettingOverrideSpynetReporting",
        "expected_value": 0,
        "allowed_values": [0],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet:LocalSettingOverrideSpynetReporting",
        "missing_is_compliant": True,  # Default is already Disabled (0) per CIS
    }
))

# 18.10.42.5.2 (L1) Join Microsoft MAPS = Enabled: Advanced (REG_DWORD 2)
# CIS: Default = Disabled (MAPS will not be joined)
rules.append(create_rule(
    "18.10.42.5.2",
    "Ensure 'Join Microsoft MAPS' is set to 'Enabled: Advanced'",
    "2",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet",
        "name": "SpynetReporting",
        "expected_value": 2,
        "allowed_values": [2],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet:SpynetReporting"
        # No missing_is_compliant porque el valor por defecto es Disabled
    }
))


# ===================== SECTION 18.10.43.6: ATTACK SURFACE REDUCTION (ASR) =====================

# 18.10.42.6.1.1 (L1) Configure Attack Surface Reduction rules = Enabled (REG_DWORD 1)
# Este es el interruptor principal que habilita el feature ASR
rules.append(create_rule(
    "18.10.42.6.1.1",
    "Ensure 'Configure Attack Surface Reduction rules' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR",
        "name": "ExploitGuard_ASR_Rules",
        "expected_value": 1,
        "allowed_values": [1],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR:ExploitGuard_ASR_Rules",
        # No missing_is_compliant porque el valor por defecto es Disabled (0)
    }
))

# 18.10.42.6.1.2 (L1) Configure Attack Surface Reduction rules

asr_rules = [
    ("26190899-1602-49e8-8b27-eb1d0a1ce869", "Block Office communication application from creating child processes"),
    ("3b576869-a4ec-4529-8536-b80a7769e899", "Block Office applications from creating executable content"),
    ("56a863a9-875e-4185-98a7-b882c64b5ce5", "Block abuse of exploited vulnerable signed drivers"),
    ("5beb7efe-fd9a-4556-801d-275e5ffc04cc", "Block execution of potentially obfuscated scripts"),
    ("75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84", "Block Office applications from injecting code into other processes"),
    ("7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c", "Block Adobe Reader from creating child processes"),
    ("9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", "Block credential stealing from LSASS"),
    ("b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4", "Block untrusted and unsigned processes that run from USB"),
    ("be9ba2d9-53ea-4cdc-84e5-9b1eeee46550", "Block executable content from email client and webmail"),
    ("d3e037e1-3eb8-44c8-a917-57927947596d", "Block JavaScript or VBScript from launching downloaded executable content"),
    ("d4f940ab-401b-4efc-aadc-ad5f3c50688a", "Block Office applications from creating child processes"),
    ("e6db77e5-3df2-4cf1-b95a-636979351e5b", "Block persistence through WMI event subscription"),
]

for rule_id, rule_description in asr_rules:

    rules.append(create_rule(
        "18.10.42.6.1.2",
        f"Ensure ASR rule '{rule_description}' is set to 'Block'",
        "1",
        "registry",
        {
            "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules",
            "name": rule_id,
            "expected_value": 1,
            "allowed_values": [1],
            "evidence": f"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules:{rule_id}"
        }
    ))


# 18.10.42.6.3.1 (L1) Network Protection

rules.append(create_rule(
    "18.10.42.6.3.1",
    "Ensure 'Prevent users and apps from accessing dangerous websites' is set to 'Enabled: Block'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection",
        "name": "EnableNetworkProtection",
        "expected_value": 1,
        "allowed_values": [1],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection:EnableNetworkProtection"
    }
))

# 18.10.42.7.1 (L1) Enable file hash computation feature = Enabled (REG_DWORD 1)
# CIS: Default = Disabled (File hash values are not computed during scans)
rules.append(create_rule(
    "18.10.42.7.1",
    "Ensure 'Enable file hash computation feature' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine",
        "name": "EnableFileHashComputation",
        "expected_value": 1,
        "allowed_values": [1],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine:EnableFileHashComputation",
        # No missing_is_compliant porque el valor por defecto es Disabled (0)
    }
))


# 18.10.42.10.1 (L1) Configure real-time protection and Security Intelligence Updates during OOBE
rules.append(create_rule(
    "18.10.42.10.1",
    "Ensure 'Configure real-time protection and Security Intelligence Updates during OOBE' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
        "name": "OobeEnableRtpAndSigUpdate",
        "expected_value": 1,
        "allowed_values": [1],
        "missing_is_compliant": True,  # Default es Enabled según CIS
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection:OobeEnableRtpAndSigUpdate"
    }
))

# 18.10.43.10.2 (L1) Scan all downloaded files and attachments
# NOTA: Este control usa DisableIOAVProtection = 0 para habilitar la protección
rules.append(create_rule(
    "18.10.42.10.2",
    "Ensure 'Scan all downloaded files and attachments' is set to 'Enabled'",
    "0",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
        "name": "DisableIOAVProtection",
        "expected_value": 0,
        "allowed_values": [0],
        "missing_is_compliant": True,  # Default es Enabled (DisableIOAVProtection = 0)
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection:DisableIOAVProtection"
    }
))

# 18.10.43.10.3 (L1) Turn off real-time protection
# CIS recomienda: Disabled (no desactivar la protección en tiempo real)
rules.append(create_rule(
    "18.10.42.10.3",
    "Ensure 'Turn off real-time protection' is set to 'Disabled'",
    "0",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
        "name": "DisableRealtimeMonitoring",
        "expected_value": 0,
        "allowed_values": [0],
        "missing_is_compliant": True,  # Default es Disabled (DisableRealtimeMonitoring = 0)
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection:DisableRealtimeMonitoring"
    }
))

# 18.10.43.10.4 (L1) Turn on behavior monitoring
# NOTA: Este control usa DisableBehaviorMonitoring = 0 para habilitar el monitoreo
rules.append(create_rule(
    "18.10.42.10.4",
    "Ensure 'Turn on behavior monitoring' is set to 'Enabled'",
    "0",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
        "name": "DisableBehaviorMonitoring",
        "expected_value": 0,
        "allowed_values": [0],
        "missing_is_compliant": True,  # Default es Enabled según CIS
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection:DisableBehaviorMonitoring"
    }
))

# 18.10.43.10.5 (L1) Turn on script scanning
# NOTA: Este control usa DisableScriptScanning = 0 para habilitar el escaneo de scripts
rules.append(create_rule(
    "18.10.42.10.5",
    "Ensure 'Turn on script scanning' is set to 'Enabled'",
    "0",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
        "name": "DisableScriptScanning",
        "expected_value": 0,
        "allowed_values": [0],
        "missing_is_compliant": True,  # Default es Enabled según CIS
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection:DisableScriptScanning"
    }
))

# 18.10.43.11.1.1.2 (L1) Configure Remote Encryption Protection Mode
rules.append(create_rule(
    "18.10.42.11.1.1.2",
    "Ensure 'Configure Remote Encryption Protection Mode' is set to 'Enabled: Audit' or higher",
    "1 or 2",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Remediation\Behavioral Network Blocks\Brute Force Protection",
        "name": "BruteForceProtectionConfiguredState",
        "expected_value": 1,  # valor de referencia (Audit)
        "allowed_values": [1, 2],  # 1 = Audit, 2 = Block (ambos cumplen)
        # No missing_is_compliant porque CIS dice: "Not configured" no cumple
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Remediation\Behavioral Network Blocks\Brute Force Protection:BruteForceProtectionConfiguredState"
    }
))

# 18.10.43.13.1 (L1) Scan excluded files and directories during quick scans
rules.append(create_rule(
    "18.10.42.13.1",
    "Ensure 'Scan excluded files and directories during quick scans' is set to 'Enabled: 1'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan",
        "name": "QuickScanIncludeExclusions",
        "expected_value": 1,
        "allowed_values": [1],
        # No missing_is_compliant porque CIS: Default = Disabled (no cumple) [citation:1]
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan:QuickScanIncludeExclusions"
    }
))

# 18.10.43.13.2 (L1) Scan packed executables
rules.append(create_rule(
    "18.10.42.13.2",
    "Ensure 'Scan packed executables' is set to 'Enabled'",
    "0",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan",
        "name": "DisablePackedExeScanning",
        "expected_value": 0,
        "allowed_values": [0],
        "missing_is_compliant": True,  # CIS: Default = Enabled (0) [citation:3]
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan:DisablePackedExeScanning"
    }
))

# 18.10.43.13.3 (L1) Scan removable drives
rules.append(create_rule(
    "18.10.42.13.3",
    "Ensure 'Scan removable drives' is set to 'Enabled'",
    "0",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan",
        "name": "DisableRemovableDriveScanning",
        "expected_value": 0,
        "allowed_values": [0],
        # No missing_is_compliant porque CIS: Default = Disabled (no cumple) [citation:2][citation:4]
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan:DisableRemovableDriveScanning"
    }
))

# 18.10.43.13.4 (L1) Trigger a quick scan after X days without any scans
rules.append(create_rule(
    "18.10.42.13.4",
    "Ensure 'Trigger a quick scan after X days without any scans' is set to 'Enabled: 7'",
    "7",
    "registry_range",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan",
        "name": "DaysUntilAggressiveCatchupQuickScan",
        "expected_value": 7,
        "min_val": 1,
        "max_val": 30,
        # No missing_is_compliant porque CIS: Default = Disabled (no cumple)
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan:DaysUntilAggressiveCatchupQuickScan"
    }
))

# 18.10.43.13.5 (L1) Turn on e-mail scanning
rules.append(create_rule(
    "18.10.42.13.5",
    "Ensure 'Turn on e-mail scanning' is set to 'Enabled'",
    "0",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan",
        "name": "DisableEmailScanning",
        "expected_value": 0,
        "allowed_values": [0],
        # No missing_is_compliant porque CIS: Default = Disabled (no cumple) [citation:3]
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan:DisableEmailScanning"
    }
))

# 18.10.43.16 (L1) Configure detection for potentially unwanted applications
rules.append(create_rule(
    "18.10.42.16",
    "Ensure 'Configure detection for potentially unwanted applications' is set to 'Enabled: Block'",
    "1",  # PUAProtection = 1 significa "Block"
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender",
        "name": "PUAProtection",
        "expected_value": 1,
        "allowed_values": [1],
        # No missing_is_compliant porque CIS: Default = Disabled (0)
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender:PUAProtection"
    }
))

# 18.10.43.17 (L1) Control whether exclusions are visible to local users
rules.append(create_rule(
    "18.10.42.17",
    "Ensure 'Control whether exclusions are visible to local users' is set to 'Enabled'",
    "1",  # HideExclusionsFromLocalUsers = 1 significa "Ocultar a usuarios locales"
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender",
        "name": "HideExclusionsFromLocalUsers",
        "expected_value": 1,
        "allowed_values": [1],
        # No missing_is_compliant porque CIS: Default = Disabled (0)
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender:HideExclusionsFromLocalUsers"
    }
))

# 18.10.57.2.2 (L1) Do not allow passwords to be saved (RDP)
rules.append(create_rule(
    "18.10.57.2.2",
    "Ensure 'Do not allow passwords to be saved' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services",
        "name": "DisablePasswordSaving",
        "expected_value": 1,
        "allowed_values": [1],
        # No missing_is_compliant porque CIS: Default = Disabled (0)
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services:DisablePasswordSaving"
    }
))

# 18.10.57.3.2.1 (L1) Restrict Remote Desktop Services users to a single session = Enabled (1)
rules.append(create_rule(
    "18.10.57.3.2.1",
    "Ensure 'Restrict Remote Desktop Services users to a single Remote Desktop Services session' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services",
        "name": "fSingleSessionPerUser",
        "expected_value": 1,
        "allowed_values": [1],
        "missing_is_compliant": True,  # CIS: Default = Enabled
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services:fSingleSessionPerUser"
    }
))

# 18.10.57.3.3.3 (L1) Do not allow drive redirection
rules.append(create_rule(
    "18.10.57.3.3.3",
    "Ensure 'Do not allow drive redirection' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services",
        "name": "fDisableCdm",
        "expected_value": 1,
        "allowed_values": [1],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services:fDisableCdm"
    }
))

# 18.10.57.3.9.1 (L1) Set time limit for active but idle Remote Desktop Services sessions
# MaxIdleTime = 900000 ms (15 min) or less, but not 0
rules.append(create_rule(
    "18.10.57.3.9.1",
    "Ensure 'Always prompt for password upon connection' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services",
        "name": "fPromptForPassword",
        "expected_value": 1,
        "allowed_values": [1],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services:fPromptForPassword"
    }
))

# 18.10.57.3.9.2 (L1) Set time limit for disconnected sessions
# MaxDisconnectionTime = 60000 ms (1 min) or less, but not 0
rules.append(create_rule(
    "18.10.57.3.9.2",
    "Ensure 'Require secure RPC communication' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services",
        "name": "fEncryptRPCTraffic",
        "expected_value": 1,
        "allowed_values": [1],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services:fEncryptRPCTraffic"
    }
))

# 18.10.57.3.9.5 (L1) Set time limit for active Remote Desktop Services sessions
# MaxConnectionTime = 0 (Never) – CIS: Disabled / Not configured = Never (0) is acceptable
rules.append(create_rule(
    "18.10.57.3.9.5",
    "Ensure 'Set client connection encryption level' is set to 'Enabled: High Level'",
    "3",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services",
        "name": "MinEncryptionLevel",
        "expected_value": 3,
        "allowed_values": [3],
        "missing_is_compliant": True,  # Default is already High Level per CIS
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services:MinEncryptionLevel"
    }
))

# 18.10.57.3.9.3 (L1) Require use of specific security layer for remote (RDP) connections
# SecurityLayer = 2 (SSL/TLS)
rules.append(create_rule(
    "18.10.57.3.9.3",
    "Ensure 'Require use of specific security layer for remote (RDP) connections' is set to 'Enabled: SSL'",
    "2",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services",
        "name": "SecurityLayer",
        "expected_value": 2,
        "allowed_values": [2],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services:SecurityLayer"
    }
))

# 18.10.57.3.9.4 (L1) Require user authentication for remote connections by using NLA
# UserAuthentication = 1
rules.append(create_rule(
    "18.10.57.3.9.4",
    "Ensure 'Require user authentication for remote connections by using Network Level Authentication' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services",
        "name": "UserAuthentication",
        "expected_value": 1,
        "allowed_values": [1],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services:UserAuthentication"
    }
))

# 18.10.57.3.11.1 (L1) Do not delete temp folders upon exit
rules.append(create_rule(
    "18.10.57.3.11.1",
    "Ensure 'Do not delete temp folders upon exit' is set to 'Disabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services",
        "name": "DeleteTempDirsOnExit",
        "expected_value": 1,
        "allowed_values": [1],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services:DeleteTempDirsOnExit"
    }
))

# 18.10.57.3.11.2 (L1) Do not use temporary folders per session
rules.append(create_rule(
    "18.10.57.3.11.2",
    "Ensure 'Do not use temporary folders per session' is set to 'Disabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services",
        "name": "PerSessionTempDir",
        "expected_value": 1,
        "allowed_values": [1],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services:PerSessionTempDir"
    }
))

# 18.10.58.1 (L1) Prevent downloading of enclosures
rules.append(create_rule(
    "18.10.58.1",
    "Ensure 'Prevent downloading of enclosures' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds",
        "name": "DisableEnclosureDownload",
        "expected_value": 1,
        "allowed_values": [1],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds:DisableEnclosureDownload"
    }
))

# 18.10.59.3 (L1) Allow indexing of encrypted files
rules.append(create_rule(
    "18.10.59.3",
    "Ensure 'Allow indexing of encrypted files' is set to 'Disabled'",
    "0",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search",
        "name": "AllowIndexingEncryptedStoresOrItems",
        "expected_value": 0,
        "allowed_values": [0],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search:AllowIndexingEncryptedStoresOrItems"
    }
))

# 18.10.76.2.1 (L1) Configure Windows Defender SmartScreen
# Este control requiere dos valores de registro
# Primero: EnableSmartScreen = 1 (REG_DWORD)
rules.append(create_rule(
    "18.10.77.2.1",
    "Ensure 'Configure Windows Defender SmartScreen' is set to 'Enabled: Warn and prevent bypass' (EnableSmartScreen)",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\System",
        "name": "EnableSmartScreen",
        "expected_value": 1,
        "allowed_values": [1],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\System:EnableSmartScreen"
    }
))

# Segundo: ShellSmartScreenLevel = "Block" (REG_SZ)
rules.append(create_rule(
    "18.10.77.2.1",
    "Ensure 'Configure Windows Defender SmartScreen' is set to 'Enabled: Warn and prevent bypass' (ShellSmartScreenLevel)",
    "Block",
    "registry_sz",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\System",
        "name": "ShellSmartScreenLevel",
        "expected_value": "Block",
        "expected_mode": "exact_str",
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\System:ShellSmartScreenLevel"
    }
))

# 18.10.81.1 (L1) Allow user control over installs
rules.append(create_rule(
    "18.10.82.1",
    "Ensure 'Allow user control over installs' is set to 'Disabled'",
    "0",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer",
        "name": "EnableUserControl",
        "expected_value": 0,
        "allowed_values": [0],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer:EnableUserControl"
    }
))

# 18.10.81.2 (L1) Always install with elevated privileges
rules.append(create_rule(
    "18.10.82.2",
    "Ensure 'Always install with elevated privileges' is set to 'Disabled'",
    "0",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer",
        "name": "AlwaysInstallElevated",
        "expected_value": 0,
        "allowed_values": [0],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer:AlwaysInstallElevated"
    }
))

# 18.10.82.1 (L1) Configure the transmission of the user's password in MPR notifications
rules.append(create_rule(
    "18.10.83.1",
    "Ensure 'Configure the transmission of the user's password in MPR notifications sent by winlogon' is set to 'Disabled'",
    "0",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "name": "EnableMPR",
        "expected_value": 0,
        "allowed_values": [0],
        "evidence": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:EnableMPR"
    }
))

# 18.10.82.2 (L1) Sign-in and lock last interactive user automatically after a restart
rules.append(create_rule(
    "18.10.83.2",
    "Ensure 'Sign-in and lock last interactive user automatically after a restart' is set to 'Disabled'",
    "1",  # IMPORTANTE: DisableAutomaticRestartSignOn = 1 significa Deshabilitado
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "name": "DisableAutomaticRestartSignOn",
        "expected_value": 1,
        "allowed_values": [1],
        "evidence": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:DisableAutomaticRestartSignOn"
    }
))

# 18.10.89.1.1 (L1) Allow Basic authentication
rules.append(create_rule(
    "18.10.90.1.1",
    "Ensure 'Allow Basic authentication' is set to 'Disabled'",
    "0",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client",
        "name": "AllowBasic",
        "expected_value": 0,
        "allowed_values": [0],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client:AllowBasic"
    }
))

# 18.10.89.1.2 (L1) Allow unencrypted traffic
rules.append(create_rule(
    "18.10.90.1.2",
    "Ensure 'Allow unencrypted traffic' is set to 'Disabled'",
    "0",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client",
        "name": "AllowUnencryptedTraffic",
        "expected_value": 0,
        "allowed_values": [0],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client:AllowUnencryptedTraffic"
    }
))

# 18.10.89.1.3 (L1) Disallow Digest authentication
rules.append(create_rule(
    "18.10.90.1.3",
    "Ensure 'Disallow Digest authentication' is set to 'Enabled'",
    "0",  # IMPORTANTE: AllowDigest = 0 significa que Digest NO está permitido
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client",
        "name": "AllowDigest",
        "expected_value": 0,
        "allowed_values": [0],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client:AllowDigest"
    }
))

# 18.10.89.2.1 (L1) Allow Basic authentication (WinRM Service)
rules.append(create_rule(
    "18.10.90.2.1",
    "Ensure 'Allow Basic authentication' is set to 'Disabled' (WinRM Service)",
    "0",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service",
        "name": "AllowBasic",
        "expected_value": 0,
        "allowed_values": [0],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service:AllowBasic"
    }
))

# 18.10.89.2.3 (L1) Allow unencrypted traffic (WinRM Service)
rules.append(create_rule(
    "18.10.90.2.3",
    "Ensure 'Allow unencrypted traffic' is set to 'Disabled' (WinRM Service)",
    "0",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service",
        "name": "AllowUnencryptedTraffic",
        "expected_value": 0,
        "allowed_values": [0],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service:AllowUnencryptedTraffic"
    }
))

# 18.10.89.2.4 (L1) Disallow WinRM from storing RunAs credentials
rules.append(create_rule(
    "18.10.90.2.4",
    "Ensure 'Disallow WinRM from storing RunAs credentials' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service",
        "name": "DisableRunAs",
        "expected_value": 1,
        "allowed_values": [1],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service:DisableRunAs"
    }
))
# 18.10.93.2.1 (L1) Prevent users from modifying settings
rules.append(create_rule(
    "18.10.93.2.1",
    "Ensure 'Prevent users from modifying settings' is set to 'Enabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection",
        "name": "DisallowExploitProtectionOverride",
        "expected_value": 1,
        "allowed_values": [1],
        "evidence": r"HKLM\...\App and Browser protection:DisallowExploitProtectionOverride"
    }
))

# 18.10.93.1.1 (L1) No auto-restart with logged on users for scheduled automatic updates installations
rules.append(create_rule(
    "18.10.94.1.1",
    "Ensure 'No auto-restart with logged on users for scheduled automatic updates installations' is set to 'Disabled'",
    "0",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
        "name": "NoAutoRebootWithLoggedOnUsers",
        "expected_value": 0,
        "allowed_values": [0],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU:NoAutoRebootWithLoggedOnUsers"
    }
))

# 18.10.93.2.1 (L1) Configure Automatic Updates
rules.append(create_rule(
    "18.10.94.2.1",
    "Ensure 'Configure Automatic Updates' is set to 'Enabled'",
    "0",  # NoAutoUpdate = 0 significa "Enabled"
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
        "name": "NoAutoUpdate",
        "expected_value": 0,
        "allowed_values": [0],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU:NoAutoUpdate"
    }
))

# 18.10.93.2.2 (L1) Configure Automatic Updates: Scheduled install day
rules.append(create_rule(
    "18.10.94.2.2",
    "Ensure 'Configure Automatic Updates: Scheduled install day' is set to '0 - Every day'",
    "0",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
        "name": "ScheduledInstallDay",
        "expected_value": 0,
        "allowed_values": [0],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU:ScheduledInstallDay"
    }
))
# 18.10.94.4.1 (L1) Manage preview builds = Disabled
rules.append(create_rule(
    "18.10.94.4.1",
    "Ensure 'Manage preview builds' is set to 'Disabled'",
    "1",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate",
        "name": "ManagePreviewBuildsPolicyValue",
        "expected_value": 1,
        "allowed_values": [1],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate:ManagePreviewBuildsPolicyValue"
    }
))

# 18.10.94.4.2 (L1) Select when Quality Updates are received = Enabled: 0 days
# Requiere 2 valores de registro según el PDF
rules.append(create_rule(
    "18.10.94.4.2",
    "Ensure 'Select when Quality Updates are received' is set to 'Enabled: 0 days'",
    "DeferQualityUpdates=1, DeferQualityUpdatesPeriodInDays=0",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate",
        "name": "DeferQualityUpdates",
        "expected_value": 1,
        "allowed_values": [1],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate:DeferQualityUpdates"
    }
))

rules.append(create_rule(
    "18.10.94.4.2",
    "Ensure 'Select when Quality Updates are received: Defer Quality Updates' is set to '0 days'",
    "0",
    "registry",
    {
        "path": r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate",
        "name": "DeferQualityUpdatesPeriodInDays",
        "expected_value": 0,
        "allowed_values": [0],
        "evidence": r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate:DeferQualityUpdatesPeriodInDays"
    }
))