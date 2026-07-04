# TAALA-2KEN Architecture Design Document

This document outlines the architecture, data flows, and security boundaries of the TAALA-2KEN Windows USB Session Guard.

---

## 1. System Topology

TAALA-2KEN uses a dual-process security model split across Windows user sessions and privilege boundaries:

```
+---------------------------------------------------------------------------------+
|                                 SECURE DESKTOP                                  |
|                                                                                 |
|   +------------------------------------+                                        |
|   |            LogonUI.exe             |                                        |
|   |  (Loads Credential Provider DLL)   |                                        |
|   +-----------------+------------------+                                        |
|                     |                                                           |
|                     | IPC (Named Pipe: \\.\pipe\Taala2KenAuth)                  |
+---------------------|-----------------------------------------------------------+
                      |
+---------------------v-----------------------------------------------------------+
|                              SYSTEM SESSION (0)                                 |
|                                                                                 |
|   +------------------------------------+                                        |
|   |       Python Background Daemon     |                                        |
|   |  - USB Monitor (WMI + SetupAPI)    | <=========>  ePass2003 / YubiKey       |
|   |  - Named Pipe IPC Server           |                  (PKCS#11)             |
|   |  - Session Locker Controller       |                                        |
|   +------------------------------------+                                        |
+---------------------------------------------------------------------------------+
```

---

## 2. Component Design

### 2.1 C++ COM Credential Provider (`credential_provider/`)
The C++ Logon UI component implements Microsoft's `ICredentialProvider` and `ICredentialProviderCredential` interfaces. It runs within the isolated Winlogon environment on the **Secure Desktop**.
- **Role**: Blocks workstation unlock/logon tiles if the registered USB security key is absent.
- **Local Scan Fallback**: If the background Python daemon is stopped or unresponsive, the provider falls back to a direct Windows SetupAPI device enumeration to verify key presence locally, ensuring users do not get permanently locked out of their system.
- **Serialization**: Upon verification, packages standard credentials into a `KERB_INTERACTIVE_LOGON` structure for submittal to the Local Security Authority (LSA) authentication packages.

### 2.2 Python Background Daemon (`taala2ken/`)
The daemon runs as a background service/scheduled task under `SYSTEM` or elevated Administrator context.
- **USB Monitor**: Keeps track of the device's connection status.
- **Named Pipe Server**: Opens a thread-safe named pipe client connection `\\.\pipe\Taala2KenAuth` to handle status checks and challenges from LogonUI.
- **Session Locker**: Issues Win32 Terminal Services (`LockWorkStation`) calls when the token is disconnected.

---

## 3. Cryptographic Challenge-Response Protocol

When enrolled with PKCS#11 hardware authentication:
1. **Nonce Generation**: The C++ credential provider generates a random 32-byte hex nonce via `CryptGenRandom`.
2. **Challenge Request**: The provider sends the nonce via Named Pipe to the Python daemon.
3. **Hardware Signature**: The Python daemon loads the registered PKCS#11 middleware DLL (e.g., `eps2003.dll`), logs into the token, and signs the challenge with the device's private RSA key using the SHA-256 PKCS#1 mechanism.
4. **Signature Verification**: The signature is returned to the provider, which verifies it using the DER-encoded public key stored in the system registry configurations.
