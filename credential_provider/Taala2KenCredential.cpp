#include "Taala2KenCredential.h"
#include "PipeServer.h"
#include "SecureDesktopHelper.h"
#include "guid.h"
#include <shlwapi.h>
#include <ntsecapi.h>
#include <wincrypt.h>

extern long g_cRefModule;

// Local debug helper dummy
namespace t2k_local {
    void debug_log(const char* msg) {
        OutputDebugStringA(msg);
    }
}

CTaala2KenCredential::CTaala2KenCredential() :
    _cRef(1),
    _cpus(CPUS_LOGON)
{
    _username[0] = L'\0';
    _password[0] = L'\0';
    wcscpy_s(_statusText, L"Checking security key presence...");
    InterlockedIncrement(&g_cRefModule);
}

CTaala2KenCredential::~CTaala2KenCredential()
{
    InterlockedDecrement(&g_cRefModule);
}

void CTaala2KenCredential::Initialize(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus)
{
    _cpus = cpus;
}

IFACEMETHODIMP CTaala2KenCredential::GetFieldState(
    DWORD dwFieldID, 
    CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs, 
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis)
{
    *pcpfis = CPFIS_NONE;

    switch (dwFieldID)
    {
    case T2K_FID_LOGO:
        *pcpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
        break;
    case T2K_FID_LABEL:
        *pcpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
        break;
    case T2K_FID_STATUS:
        *pcpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
        break;
    case T2K_FID_USERNAME:
        *pcpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
        *pcpfis = CPFIS_FOCUSED;
        break;
    case T2K_FID_PASSWORD:
        *pcpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
        break;
    case T2K_FID_SUBMIT:
        *pcpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
        break;
    default:
        *pcpfs = CPFS_HIDDEN;
        break;
    }

    return S_OK;
}

IFACEMETHODIMP CTaala2KenCredential::GetStringValue(DWORD dwFieldID, LPWSTR* ppsz)
{
    *ppsz = NULL;
    HRESULT hr = S_OK;

    switch (dwFieldID)
    {
    case T2K_FID_LABEL:
        hr = SHStrDupW(L"TAALA-2KEN USB Lock Guard", ppsz);
        break;
    case T2K_FID_STATUS:
        hr = SHStrDupW(_statusText, ppsz);
        break;
    case T2K_FID_USERNAME:
        hr = SHStrDupW(_username, ppsz);
        break;
    case T2K_FID_PASSWORD:
        hr = SHStrDupW(L"", ppsz); // Masked by UI
        break;
    default:
        hr = E_INVALIDARG;
        break;
    }

    return hr;
}

IFACEMETHODIMP CTaala2KenCredential::GetBitmapValue(DWORD dwFieldID, HBITMAP* phbmp)
{
    *phbmp = NULL;
    return E_NOTIMPL; // System default tile icon
}

IFACEMETHODIMP CTaala2KenCredential::GetSubmitButtonValue(DWORD dwFieldID, DWORD* pdwAdjacentTo)
{
    if (dwFieldID == T2K_FID_SUBMIT)
    {
        *pdwAdjacentTo = T2K_FID_PASSWORD;
        return S_OK;
    }
    return E_INVALIDARG;
}

IFACEMETHODIMP CTaala2KenCredential::SetStringValue(DWORD dwFieldID, LPCWSTR psz)
{
    switch (dwFieldID)
    {
    case T2K_FID_USERNAME:
        wcscpy_s(_username, psz);
        return S_OK;
    case T2K_FID_PASSWORD:
        wcscpy_s(_password, psz);
        return S_OK;
    }
    return E_INVALIDARG;
}

bool CTaala2KenCredential::CheckUSBStatus()
{
    CPipeClient client;
    std::wstring status;
    std::wstring devType;
    bool reqChallenge = false;

    // Contact background monitor daemon
    if (client.QueryDaemonStatus(status, devType, reqChallenge))
    {
        if (status == L"PRESENT")
        {
            wcscpy_s(_statusText, L"Security Key Verified. Enter credentials to unlock.");
            return true;
        }
        else if (status == L"GRACE")
        {
            wcscpy_s(_statusText, L"Security Key Absent! Grace period active.");
            return false;
        }
    }

    // Secure desktop local fallback check (in case Python service is unreachable)
    // Checks using registry configuration (can be loaded or fallback to default PnP prefixes)
    if (IsRegisteredUSBConnected(L"USB\\VID_096E"))
    {
        wcscpy_s(_statusText, L"Security Key Detected (Local Scan).");
        return true;
    }

    wcscpy_s(_statusText, L"Please insert your registered Security Key.");
    return false;
}

bool CTaala2KenCredential::PerformCryptographicChallenge()
{
    CPipeClient client;
    std::wstring status, devType;
    bool reqChallenge = false;

    if (client.QueryDaemonStatus(status, devType, reqChallenge))
    {
        if (reqChallenge)
        {
            // Generate random 32-byte nonce via CryptGenRandom
            BYTE nonceBuf[32];
            HCRYPTPROV hProv = 0;
            if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
            {
                t2k_local::debug_log("CryptAcquireContext failed for nonce generation.");
                return false;
            }
            if (!CryptGenRandom(hProv, sizeof(nonceBuf), nonceBuf))
            {
                CryptReleaseContext(hProv, 0);
                t2k_local::debug_log("CryptGenRandom failed.");
                return false;
            }
            CryptReleaseContext(hProv, 0);

            // Convert to hex string
            wchar_t hexBuf[65];
            for (int i = 0; i < 32; i++)
            {
                wsprintfW(hexBuf + i * 2, L"%02X", nonceBuf[i]);
            }
            hexBuf[64] = L'\0';

            std::wstring challengeNonce(hexBuf);
            std::wstring signature;
            if (client.RequestChallengeSignature(challengeNonce, signature))
            {
                t2k_local::debug_log("Cryptographic PKCS11 signature verified by daemon pipe client.");
                return true;
            }
            return false;
        }
    }
    return true; // Bypassed if no challenge required
}

IFACEMETHODIMP CTaala2KenCredential::GetSerialization(
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
    PWSTR* ppszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsi)
{
    *pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED;
    *ppszOptionalStatusText = NULL;
    *pcpsi = CPSI_NONE;

    if (!CheckUSBStatus())
    {
        SHStrDupW(L"Logon blocked: Security Key is missing.", ppszOptionalStatusText);
        *pcpsi = CPSI_ERROR;
        return S_OK;
    }

    if (!PerformCryptographicChallenge())
    {
        SHStrDupW(L"Logon blocked: Cryptographic verification failed.", ppszOptionalStatusText);
        *pcpsi = CPSI_ERROR;
        return S_OK;
    }

    // Package standard username/password serialization structure (KERB_INTERACTIVE_LOGON)
    DWORD cbAuthBuffer = 0;
    BYTE* rgbAuthBuffer = NULL;

    DWORD userLen = (DWORD)wcslen(_username);
    DWORD passLen = (DWORD)wcslen(_password);
    
    // Account for LogonDomainName (empty string = local machine)
    cbAuthBuffer = sizeof(KERB_INTERACTIVE_LOGON) + ((userLen + passLen + 1 + 2) * sizeof(wchar_t));
    rgbAuthBuffer = (BYTE*)CoTaskMemAlloc(cbAuthBuffer);
    if (!rgbAuthBuffer)
    {
        return E_OUTOFMEMORY;
    }
    ZeroMemory(rgbAuthBuffer, cbAuthBuffer);

    KERB_INTERACTIVE_LOGON* pLogon = (KERB_INTERACTIVE_LOGON*)rgbAuthBuffer;
    pLogon->MessageType = KerbInteractiveLogon;
    
    wchar_t* pBuffer = (wchar_t*)(rgbAuthBuffer + sizeof(KERB_INTERACTIVE_LOGON));

    // LogonDomainName — empty = local machine domain
    pLogon->LogonDomainName.Buffer = pBuffer;
    pLogon->LogonDomainName.Length = 0;
    pLogon->LogonDomainName.MaximumLength = sizeof(wchar_t);
    *pBuffer = L'\0';
    pBuffer += 1;

    // Copy Username
    pLogon->UserName.Buffer = pBuffer;
    pLogon->UserName.Length = (USHORT)(userLen * sizeof(wchar_t));
    pLogon->UserName.MaximumLength = (USHORT)((userLen + 1) * sizeof(wchar_t));
    wcscpy_s(pBuffer, userLen + 1, _username);
    pBuffer += userLen + 1;

    // Copy Password
    pLogon->Password.Buffer = pBuffer;
    pLogon->Password.Length = (USHORT)(passLen * sizeof(wchar_t));
    pLogon->Password.MaximumLength = (USHORT)((passLen + 1) * sizeof(wchar_t));
    wcscpy_s(pBuffer, passLen + 1, _password);

    // Get LSA Package ID
    DWORD dwPackageId = 0;
    HANDLE hLsa;
    NTSTATUS status = LsaConnectUntrusted(&hLsa);
    if (status == 0)
    {
        LSA_STRING pkgName;
        pkgName.Buffer = (char*)MICROSOFT_KERBEROS_NAME_A;
        pkgName.Length = (USHORT)strlen(MICROSOFT_KERBEROS_NAME_A);
        pkgName.MaximumLength = pkgName.Length;
        LsaLookupAuthenticationPackage(hLsa, &pkgName, &dwPackageId);
        LsaDeregisterLogonProcess(hLsa);
    }

    pcpcs->clsidCredentialProvider = CLSID_Taala2KenProvider;
    pcpcs->cbSerialization = cbAuthBuffer;
    pcpcs->rgbSerialization = rgbAuthBuffer;
    pcpcs->ulAuthenticationPackage = dwPackageId;
    *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;

    return S_OK;
}

IFACEMETHODIMP CTaala2KenCredential::ReportResult(
    NTSTATUS status, 
    NTSTATUS substatus, 
    PWSTR* ppszOptionalStatusText, 
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsi)
{
    *ppszOptionalStatusText = NULL;
    *pcpsi = CPSI_NONE;
    
    if (status != 0) // Failure
    {
        SHStrDupW(L"Unlock failed. Invalid credentials.", ppszOptionalStatusText);
        *pcpsi = CPSI_ERROR;
    }
    return S_OK;
}
