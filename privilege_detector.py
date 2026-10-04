import os
import sys
import ctypes
import subprocess
import winreg
from pathlib import Path
from datetime import datetime


# ============================================================
# Utility Functions
# ============================================================

def print_header(title):
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def run_command(command):
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            shell=True,
            errors="ignore"
        )
        return result.stdout.strip()
    except Exception as e:
        return f"Error: {e}"


# ============================================================
# 1. USER PRIVILEGE ANALYSIS
# ============================================================

def analyze_user_privileges():
    print_header("1. USER PRIVILEGE ANALYSIS")

    username = os.environ.get("USERNAME", "Unknown")
    computer = os.environ.get("COMPUTERNAME", "Unknown")

    print(f"Current User     : {username}")
    print(f"Computer Name    : {computer}")

    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        is_admin = False

    if is_admin:
        print("Administrator    : YES")
        print("Status           : Elevated privileges detected")
    else:
        print("Administrator    : NO")
        print("Status           : Standard user context")

    print("\nCurrent user information:")
    print(run_command("whoami /all"))


# ============================================================
# 2. FILE AND DIRECTORY PERMISSION ANALYSIS
# ============================================================

def check_permissions(path):
    print(f"\nChecking: {path}")

    if not os.path.exists(path):
        print("Status: Path does not exist")
        return

    try:
        output = run_command(f'icacls "{path}"')

        print(output[:2500])

        lower_output = output.lower()

        risky_terms = [
            "everyone:(f)",
            "everyone:(m)",
            "users:(f)",
            "users:(m)",
            "authenticated users:(f)",
            "authenticated users:(m)"
        ]

        found = False

        for term in risky_terms:
            if term in lower_output:
                found = True
                print(f"[WARNING] Potentially broad permission detected: {term}")

        if not found:
            print("[OK] No obvious broad full/modify permission detected.")

    except Exception as e:
        print(f"Error checking permissions: {e}")


def analyze_file_permissions():
    print_header("2. FILE AND DIRECTORY PERMISSION ANALYSIS")

    paths = [
        os.environ.get("WINDIR", r"C:\Windows"),
        os.environ.get(
            "PROGRAMDATA",
            r"C:\ProgramData"
        ),
        os.environ.get(
            "TEMP",
            r"C:\Windows\Temp"
        )
    ]

    for path in paths:
        check_permissions(path)


# ============================================================
# 3. PROCESS ANALYSIS
# ============================================================

def analyze_processes():
    print_header("3. PROCESS ANALYSIS")

    print("Collecting running processes...\n")

    command = (
        'powershell -NoProfile -Command '
        '"Get-CimInstance Win32_Process | '
        'Select-Object ProcessId,Name,ExecutablePath | '
        'Format-Table -AutoSize"'
    )

    output = run_command(command)

    if output:
        print(output[:8000])
    else:
        print("Unable to retrieve process information.")

    print("\n[INFO] Review processes with unusual names or executable paths.")
    print("[INFO] This tool does not automatically label a process as malicious.")


# ============================================================
# 4. REGISTRY ANALYSIS
# ============================================================

def check_registry_value(root, path, value_name):
    try:
        with winreg.OpenKey(root, path, 0, winreg.KEY_READ) as key:
            value, value_type = winreg.QueryValueEx(key, value_name)

            print(f"\nRegistry Path : {path}")
            print(f"Value Name    : {value_name}")
            print(f"Value         : {value}")

            return value

    except FileNotFoundError:
        return None

    except PermissionError:
        print(f"\n[WARNING] Access denied: {path}")
        return None

    except Exception as e:
        print(f"\nError reading registry: {e}")
        return None


def analyze_registry():
    print_header("4. REGISTRY ANALYSIS")

    print("Checking selected security-related registry settings...")

    # UAC EnableLUA
    enable_lua = check_registry_value(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "EnableLUA"
    )

    if enable_lua == 0:
        print("[WARNING] UAC appears to be disabled.")
    elif enable_lua == 1:
        print("[OK] UAC EnableLUA is enabled.")

    # UAC ConsentPromptBehaviorAdmin
    consent = check_registry_value(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "ConsentPromptBehaviorAdmin"
    )

    if consent is not None:
        print(
            "[INFO] ConsentPromptBehaviorAdmin value is "
            f"{consent}"
        )

    # AlwaysInstallElevated
    hklm_value = check_registry_value(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Policies\Microsoft\Windows\Installer",
        "AlwaysInstallElevated"
    )

    hkcu_value = check_registry_value(
        winreg.HKEY_CURRENT_USER,
        r"SOFTWARE\Policies\Microsoft\Windows\Installer",
        "AlwaysInstallElevated"
    )

    if hklm_value == 1 and hkcu_value == 1:
        print(
            "[WARNING] AlwaysInstallElevated is enabled "
            "in both HKLM and HKCU."
        )
    else:
        print(
            "[OK] AlwaysInstallElevated does not appear "
            "enabled in both locations."
        )


# ============================================================
# 5. LOG ANALYSIS
# ============================================================

def analyze_logs():
    print_header("5. WINDOWS LOG ANALYSIS")

    print("Checking recent Windows Security events...\n")

    command = (
        'powershell -NoProfile -Command '
        '"Get-WinEvent -FilterHashtable '
        '@{LogName=''Security''; Id=4672,4624,4625} -MaxEvents 20 | '
        'Select-Object TimeCreated,Id,ProviderName,Message | '
        'Format-List"'
    )

    output = run_command(command)

    if output:
        print(output[:10000])
    else:
        print("No events returned or access to Security log is unavailable.")

    print("\nEvent IDs checked:")
    print("4624 - Successful logon")
    print("4625 - Failed logon")
    print("4672 - Special privileges assigned to new logon")


# ============================================================
# MAIN
# ============================================================

def main():

    print_header("LOCAL PRIVILEGE ESCALATION DETECTION TOOL")

    print("Purpose:")
    print(
        "Detect potential privilege escalation indicators "
        "and insecure local configurations."
    )

    print(f"\nScan started: {datetime.now()}")

    analyze_user_privileges()
    analyze_file_permissions()
    analyze_processes()
    analyze_registry()
    analyze_logs()

    print_header("SCAN COMPLETED")

    print("Review the warnings and informational findings above.")
    print("This tool performs detection/auditing only.")
    print(f"Scan completed: {datetime.now()}")


if __name__ == "__main__":
    main()