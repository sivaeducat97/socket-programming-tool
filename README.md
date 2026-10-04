# Local Privilege Escalation Detection Tool

## 1. Project Description

This project is a Python-based Windows security auditing tool.

The purpose of this tool is to detect potential indicators of local privilege escalation and insecure system configurations.

The tool performs security checks without exploiting or modifying the system.

## 2. Features

The tool performs the following five security checks:

### 1. User Privilege Analysis

The tool checks:

* Current username
* Computer name
* Whether the current user has administrator privileges
* Windows user security information

### 2. File and Directory Permission Analysis

The tool checks selected Windows directories and examines their access permissions.

It looks for potentially broad permissions such as:

* Everyone Full Control
* Everyone Modify
* Users Full Control
* Users Modify

### 3. Process Analysis

The tool collects information about currently running processes.

It displays:

* Process name
* Process ID
* Executable path

The information can be reviewed for unusual or unexpected processes.

### 4. Registry Analysis

The tool checks selected Windows Registry settings related to security and privilege control.

It checks settings such as:

* UAC EnableLUA
* ConsentPromptBehaviorAdmin
* AlwaysInstallElevated

Potentially insecure configurations are reported as warnings.

### 5. Windows Log Analysis

The tool checks recent Windows Security events.

The following event IDs are reviewed:

* 4624 - Successful logon
* 4625 - Failed logon
* 4672 - Special privileges assigned to a new logon

## 3. Requirements

The project requires:

* Windows 10 or Windows 11
* Python 3.x
* PowerShell

No external Python packages are required.

## 4. Installation

Download or clone this repository.

Open PowerShell or the VS Code terminal inside the project directory.

Check Python:

```powershell
python --version
```

## 5. Running the Tool

Run the following command:

```powershell
python privilege_detector.py
```

For better access to Windows security logs, running PowerShell as Administrator is recommended.

## 6. Expected Output

The program performs five main checks:

```text
1. USER PRIVILEGE ANALYSIS
2. FILE AND DIRECTORY PERMISSION ANALYSIS
3. PROCESS ANALYSIS
4. REGISTRY ANALYSIS
5. WINDOWS LOG ANALYSIS
```

After completing all checks, the program displays:

```text
SCAN COMPLETED
```

## 7. Project Structure

```text
Privilege-Escalation-Detection/
│
├── privilege_detector.py
├── requirements.txt
├── README.md
└── report.txt
```

## 8. Limitations

This tool is a basic security auditing tool.

A warning does not automatically mean that a vulnerability exists.

Security findings should be manually verified by a security administrator.

The tool does not exploit vulnerabilities or modify system security settings.

## 9. Security Purpose

This project is intended for educational and defensive security auditing purposes.

It demonstrates how Python can be used to inspect Windows security settings and identify potential indicators related to local privilege escalation.
