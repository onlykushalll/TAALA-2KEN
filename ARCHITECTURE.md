# TAALA-2KEN Architecture Overview

> Detailed protocol specs and deployment procedures live in [`docs/architecture.md`](docs/architecture.md), [`docs/protocol.md`](docs/protocol.md), and [`docs/deployment.md`](docs/deployment.md).

## Component Boundaries

1. **Secure Desktop (`credential_provider/`):** Native C++ COM DLL loaded inside `LogonUI.exe`. Enforces physical hardware key presence before assembling Windows `KERB_INTERACTIVE_LOGON` tiles, querying `\\.\pipe\Taala2KenAuth` with direct SetupAPI fallback if the Python daemon is unavailable.
2. **Privileged Daemon (`taala2ken/monitor.py`, `pipe_server.py`):** Runs under `SYSTEM` / elevated Administrator via Windows Task Scheduler (`Taala2KenAutostart.xml`). Executes the 6-stage SetupAPI / USB / WMI deduplicated hardware pipeline (`taala2ken/detection/pipeline.py`) and enforces auto-lock when the authorized token disconnects past the grace threshold.
3. **Asymmetric PKCS#11 Challenge Engine (`taala2ken/pkcs11_auth.py`):** Uses stored X.509/DER public key material during enrollment (`--setup`) and challenges the token secure element with a 32-byte nonce (`CKM_SHA256_RSA_PKCS`) on every unlock verification.

## Security Boundaries & Audit

See [`audit.md`](audit.md) for the complete systems security audit and [`PRIVACY.md`](PRIVACY.md) for local data guarantees.
