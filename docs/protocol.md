# TAALA-2KEN IPC Pipe Protocol Specification

TAALA-2KEN uses a local Named Pipe for IPC communication: `\\.\pipe\Taala2KenAuth`.
The server is hosted by the Python daemon; the client is the C++ COM DLL loaded in `LogonUI.exe`.

All messages are JSON objects terminated by standard system null bytes.

---

## 1. Action: `query_status`

Sent by the Credential Provider to retrieve the current USB connection state.

### Request Payload
```json
{
  "action": "query_status"
}
```

### Response Payload
```json
{
  "status": "PRESENT",
  "remaining_seconds": 0.0,
  "is_configured": true,
  "device_type": "TOKEN",
  "requires_challenge": true
}
```

### Response Properties
- `status`: Current monitor state (`PRESENT`, `ABSENT`, `GRACE`, `LOCKED`).
- `remaining_seconds`: Grace period time left before lock trigger.
- `is_configured`: Boolean indicating if a security key is registered.
- `device_type`: Type of key registered (`STORAGE` or `TOKEN`).
- `requires_challenge`: True if the registered token has cryptographic PKCS#11 key verification enabled.

---

## 2. Action: `pkcs11_challenge`

Sent by the Credential Provider to request a cryptographic signature on a random nonce.

### Request Payload
```json
{
  "action": "pkcs11_challenge",
  "nonce": "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899"
}
```
*Note: `nonce` must be a 64-character (32-byte) hex-encoded string.*

### Successful Response Payload
```json
{
  "status": "success",
  "signature": "3A8B9C0E2D... (Hex signature string)"
}
```

### Failed Response Payload
```json
{
  "status": "failed",
  "reason": "token not present"
}
```
*Possible values for `reason`: `middleware missing`, `token not present`, `private key missing`, or exception details.*
