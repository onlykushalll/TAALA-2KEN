# TAALA-2KEN: Production-Grade USB Session Guard for Windows

A modular, multi-source USB detection and lock management system integrated with Windows Credential Provider (C++) and PKCS#11 challenge-response for hardware security keys (ePass2003, YubiKey).

## Architecture Overview

```
                                  +------------------------------+
                                  |       Winlogon Session       |
                                  |  (runs as SYSTEM user on     |
                                  |       Secure Desktop)        |
                                  +--------------+---------------+
                                                 | (Named Pipe IPC)
                                                 v
+-----------------------------+   +--------------+---------------+
|     Windows Lock Screen     |   |   C++ COM Credential Provider |
|  [ LogonUI.exe tile UI ]    |<--+   (Taala2KenCredentialProvider) |
+-----------------------------+   +------------------------------+
                                                 ^
                                                 | (Named Pipe IPC)
                                                 v
+-----------------------------+   +--------------+---------------+
|     Tray Notification UI    |<--+   Python Background Daemon   |
|     (tray_app.py / pystray) |   |   (taala2ken WMI/SetupAPI)   |
+-----------------------------+   +--------------+---------------+
                                                 |
                                                 v (PKCS#11 / USB)
                                  +--------------+---------------+
                                  |   ePass2003 / Hardware Key   |
                                  +------------------------------+
```

## Folder Structure

```
TAALA-2KEN/
├── taala2ken/                 # Core modular package
│   ├── __init__.py            # Package root metadata
│   ├── __main__.py            # Unified package CLI entry point
│   ├── constants.py           # Device filters, WMI queries, GUIDs
│   ├── log.py                 # Structured console + file logger
│   ├── models.py              # USBDevice / GenericUSBDevice / SmartCardDevice
│   ├── config.py              # Persistent JSON configuration & PKCS#11 DER storage
│   ├── lock.py                # Session lock wrapper (rundll32 / win32ts)
│   ├── monitor.py             # Event-driven and polling presence watcher
│   ├── cli.py                 # CLI commands, setup wizard, admin checks
│   ├── pipe_server.py         # Named Pipe server running in Python background
│   ├── pkcs11_auth.py         # PKCS#11 module loading & challenge-response
│   ├── tray_app.py            # System tray application
│   ├── autostart.py           # Auto-start Task Scheduler XML generator
│   └── detection/             # Multi-stage detection engine
│       ├── __init__.py
│       ├── helpers.py         # Win32 WMI and SetupAPI ctypes wrappers
│       └── pipeline.py        # 6-stage priority deduplicated scan
├── credential_provider/       # C++ COM DLL Credential Provider source
│   ├── CMakeLists.txt         # Compilation configurations
│   ├── build.bat              # Setup build environment
│   ├── guid.h                 # Class and credential interface GUIDs
│   ├── dllmain.cpp            # COM exports & ClassFactory Registration
│   ├── Taala2KenProvider.h/cpp # ICredentialProvider implementation
│   ├── Taala2KenCredential.h/cpp # ICredentialProviderCredential UI/Logon
│   ├── PipeServer.h/cpp       # Named Pipe Client connector to daemon
│   ├── SecureDesktopHelper.h/cpp # SetupAPI presence polling for Winlogon
│   ├── provider.def           # COM Export definitions
│   └── register.reg/unregister.reg # Windows registry profiles
├── tests/                     # Unit test suite
│   ├── __init__.py
│   ├── conftest.py
│   └── test_all.py            # Unified test suite
├── run.pyw                    # Windowless tray launcher
├── requirements.txt           # Python library dependencies
└── pyproject.toml             # Python package build specifications
```

## Installation & Setup

1. **Python dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **First Run Setup Wizard**:
   Register your USB or cryptographic key:
   ```bash
   python -m taala2ken --setup
   ```

3. **Start Monitoring**:
   To run manually with verbose logging:
   ```bash
   python -m taala2ken --debug
   ```

4. **Task Scheduler Registration**:
   Execute the provisioner to generate the XML task profile:
   ```bash
   python -m taala2ken.autostart
   ```
   Follow the printed PowerShell instruction to register the scheduled task with high privileges.

## C++ Credential Provider Compiling

To build the Credential Provider, open a Developer Command Prompt for Visual Studio and run:
```cmd
cd credential_provider
build.bat
```
This generates `Taala2KenCredentialProvider.dll`. Register it safely using `sign_and_register.ps1`.
