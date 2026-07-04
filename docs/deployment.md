# TAALA-2KEN Deployment and Contributor Guide

This document describes how to compile, install, register, and configure the TAALA-2KEN security suite on a target Windows machine.

---

## 1. Prerequisites

- **Python**: v3.10 or later (with `pip` and `pythonw.exe`).
- **Visual Studio Build Tools**: VS 2022 (with "Desktop development with C++" workload installed).
- **CMake**: v3.20 or later.
- **Hardware Drivers**: PKCS#11 middleware drivers installed (e.g. Feitian ePass2003, YubiKey Minidriver).

---

## 2. Python Setup and Configuration

1. Install package dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Run the interactive setup wizard to register your target USB device:
   ```bash
   python -m taala2ken --setup
   ```
3. Test daemon monitoring manually in debug mode:
   ```bash
   python -m taala2ken --debug
   ```

---

## 3. Compiling the C++ Credential Provider

1. Open a **Visual Studio Developer Command Prompt**.
2. Navigate to the `credential_provider` folder:
   ```cmd
   cd credential_provider
   ```
3. Run the automated compiler script:
   ```cmd
   build.bat
   ```
   This generates `Taala2KenCredentialProvider.dll` inside `credential_provider\build\bin\Release\`.

---

## 4. Code-Signing & System Registration

Windows Logon UI requires all custom credential provider DLLs to be registered with COM and located in `%windir%\System32`. It is also recommended to sign the DLL with a trusted root certificate for security.

1. Open an **Administrator PowerShell** console.
2. Navigate to the `credential_provider` folder.
3. Run the PowerShell helper to create a self-signed certificate, sign the binary, copy it to System32, and register it:
   ```powershell
   Set-ExecutionPolicy Bypass -Scope Process
   .\sign_and_register.ps1 -Action deploy
   ```

To unregister and clean up the DLL registration:
```powershell
.\sign_and_register.ps1 -Action clean
```

---

## 5. Automatic Startup Daemon Registration

To ensure the daemon runs reliably with high privileges upon user logon:

1. Generate the Task Scheduler XML configuration:
   ```bash
   python -m taala2ken.autostart
   ```
2. Import the task inside an **Administrator PowerShell** window:
   ```powershell
   Register-ScheduledTask -Xml (Get-Content "Taala2KenAutostart.xml" -Raw) -TaskName "Taala2KenAuthGuard"
   ```
3. Clean up the temporary XML file after registration:
   ```powershell
   Remove-Item "Taala2KenAutostart.xml"
   ```
