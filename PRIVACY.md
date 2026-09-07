# Privacy Policy — TAALA-2KEN

**Last Updated:** September 7, 2026

TAALA-2KEN ("we", "our", or "the software") is an open-source, local hardware security system for Microsoft Windows.

---

## 1. Zero Cloud Telemetry & Offline Operation

- **100% Offline:** TAALA-2KEN does not connect to the internet, make remote network requests, or transmit any telemetry.
- **Hardware-Bound Authentication:** Cryptographic challenge-response verification occurs strictly between your workstation's Windows Winlogon subsystem and your physical security key (e.g. ePass2003, YubiKey).
- **Private Keys Stay on Hardware:** Hardware security key private keys are generated inside the tamper-resistant secure element of your physical token and never enter system RAM or disk storage.

---

## 2. Local Data Handled

- **Device Serial Numbers:** Token serial numbers and USB device instance paths are read solely to distinguish authorized keys from unauthorized peripherals.
- **Local Logs:** Insertion and removal events are recorded locally on your workstation in `usb_auth_guard.log` for administrative auditing. These logs never leave your device.

---

## 3. Contact

For security questions regarding TAALA-2KEN, please open an issue on our GitHub repository:
https://github.com/onlykushalll/TAALA-2KEN
