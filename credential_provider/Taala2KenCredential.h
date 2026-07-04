#pragma once
#include <windows.h>
#include <credentialprovider.h>
#include <shlwapi.h>
#include <string>

// Field IDs for our Credential UI
enum TAALA2KEN_FIELD_ID
{
    T2K_FID_LOGO             = 0,
    T2K_FID_LABEL            = 1,
    T2K_FID_STATUS           = 2,
    T2K_FID_USERNAME         = 3,
    T2K_FID_PASSWORD         = 4,
    T2K_FID_SUBMIT           = 5,
    T2K_FID_NUM_FIELDS       = 6
};

class CTaala2KenCredential : public ICredentialProviderCredential
{
public:
    CTaala2KenCredential();
    virtual ~CTaala2KenCredential();

    // IUnknown
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv)
    {
        if (riid == IID_IUnknown || riid == IID_ICredentialProviderCredential)
        {
            *ppv = static_cast<ICredentialProviderCredential*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = NULL;
        return E_NOINTERFACE;
    }

    IFACEMETHODIMP_(ULONG) AddRef()
    {
        return InterlockedIncrement(&_cRef);
    }

    IFACEMETHODIMP_(ULONG) Release()
    {
        long cRef = InterlockedDecrement(&_cRef);
        if (cRef == 0)
        {
            delete this;
        }
        return cRef;
    }

    // ICredentialProviderCredential
    IFACEMETHODIMP GetFieldState(DWORD dwFieldID, CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis);
    IFACEMETHODIMP GetStringValue(DWORD dwFieldID, LPWSTR* ppsz);
    IFACEMETHODIMP GetBitmapValue(DWORD dwFieldID, HBITMAP* phbmp);
    IFACEMETHODIMP GetCheckboxValue(DWORD dwFieldID, BOOL* pfChecked, LPWSTR* ppszLabel) { return E_NOTIMPL; }
    IFACEMETHODIMP GetSubmitButtonValue(DWORD dwFieldID, DWORD* pdwAdjacentTo);
    IFACEMETHODIMP GetComboBoxValueCount(DWORD dwFieldID, DWORD* pcItems, DWORD* pdwSelectedItem) { return E_NOTIMPL; }
    IFACEMETHODIMP GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, LPWSTR* ppszItem) { return E_NOTIMPL; }
    
    IFACEMETHODIMP SetStringValue(DWORD dwFieldID, LPCWSTR psz);
    IFACEMETHODIMP SetCheckboxValue(DWORD dwFieldID, BOOL fChecked) { return E_NOTIMPL; }
    IFACEMETHODIMP SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem) { return E_NOTIMPL; }
    
    IFACEMETHODIMP CommandLinkClicked(DWORD dwFieldID) { return E_NOTIMPL; }
    
    IFACEMETHODIMP GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr, CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs, PWSTR* ppszOptionalStatusText, CREDENTIAL_PROVIDER_STATUS_ICON* pcpsi);
    
    IFACEMETHODIMP ReportResult(NTSTATUS status, NTSTATUS substatus, PWSTR* ppszOptionalStatusText, CREDENTIAL_PROVIDER_STATUS_ICON* pcpsi);

    // Initializer
    void Initialize(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus);

private:
    long _cRef;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO _cpus;
    
    wchar_t _username[256];
    wchar_t _password[256];
    wchar_t _statusText[512];

    bool CheckUSBStatus();
    bool PerformCryptographicChallenge();
};
