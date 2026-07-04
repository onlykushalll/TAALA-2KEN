#pragma once
#include <windows.h>
#include <credentialprovider.h>
#include <shlwapi.h>
#include "Taala2KenCredential.h"

class CTaala2KenProvider : public ICredentialProvider
{
public:
    CTaala2KenProvider();
    virtual ~CTaala2KenProvider();

    // IUnknown
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv)
    {
        if (riid == IID_IUnknown || riid == IID_ICredentialProvider)
        {
            *ppv = static_cast<ICredentialProvider*>(this);
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

    // ICredentialProvider
    IFACEMETHODIMP SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags);
    IFACEMETHODIMP SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs);
    IFACEMETHODIMP GetCredentialCount(DWORD* pdwCount, DWORD* pdwDefault, BOOL* pfAutoSubmitWithStatus);
    IFACEMETHODIMP GetCredentialAt(DWORD dwIndex, ICredentialProviderCredential** ppcpc);
    IFACEMETHODIMP Advise(ICredentialProviderEvents* pcpe, UINT_PTR upAdviseContext);
    IFACEMETHODIMP UnAdvise();

    friend HRESULT CTaala2KenProvider_CreateInstance(REFIID riid, void** ppv);

private:
    long _cRef;
    CTaala2KenCredential* _pCredential;
    ICredentialProviderEvents* _pcpe;
    UINT_PTR _upAdviseContext;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO _cpus;
};
