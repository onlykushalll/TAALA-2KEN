#include "Taala2KenProvider.h"
#include <shlwapi.h>

extern long g_cRefModule;

CTaala2KenProvider::CTaala2KenProvider() :
    _cRef(1),
    _pCredential(NULL),
    _pcpe(NULL),
    _upAdviseContext(0),
    _cpus(CPUS_LOGON)
{
    InterlockedIncrement(&g_cRefModule);
}

CTaala2KenProvider::~CTaala2KenProvider()
{
    if (_pCredential != NULL)
    {
        _pCredential->Release();
        _pCredential = NULL;
    }
    if (_pcpe != NULL)
    {
        _pcpe->Release();
        _pcpe = NULL;
    }
    InterlockedDecrement(&g_cRefModule);
}

IFACEMETHODIMP CTaala2KenProvider::SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags)
{
    _cpus = cpus;
    switch (cpus)
    {
    case CPUS_LOGON:
    case CPUS_UNLOCK_WORKSTATION:
    case CPUS_CREDUI:
        return S_OK;
    default:
        return E_NOTIMPL;
    }
}

IFACEMETHODIMP CTaala2KenProvider::SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs)
{
    return E_NOTIMPL;
}

IFACEMETHODIMP CTaala2KenProvider::GetCredentialCount(DWORD* pdwCount, DWORD* pdwDefault, BOOL* pfAutoSubmitWithStatus)
{
    *pdwCount = 1;
    *pdwDefault = 0;
    *pfAutoSubmitWithStatus = FALSE;
    return S_OK;
}

IFACEMETHODIMP CTaala2KenProvider::GetCredentialAt(DWORD dwIndex, ICredentialProviderCredential** ppcpc)
{
    if (dwIndex >= 1)
    {
        return E_INVALIDARG;
    }

    if (_pCredential == NULL)
    {
        _pCredential = new CTaala2KenCredential();
        if (_pCredential == NULL)
        {
            return E_OUTOFMEMORY;
        }
        _pCredential->Initialize(_cpus);
    }

    return _pCredential->QueryInterface(IID_PPV_ARGS(ppcpc));
}

IFACEMETHODIMP CTaala2KenProvider::Advise(ICredentialProviderEvents* pcpe, UINT_PTR upAdviseContext)
{
    if (_pcpe != NULL)
    {
        _pcpe->Release();
    }
    _pcpe = pcpe;
    if (_pcpe != NULL)
    {
        _pcpe->AddRef();
    }
    _upAdviseContext = upAdviseContext;
    return S_OK;
}

IFACEMETHODIMP CTaala2KenProvider::UnAdvise()
{
    if (_pcpe != NULL)
    {
        _pcpe->Release();
        _pcpe = NULL;
    }
    _upAdviseContext = 0;
    return S_OK;
}

HRESULT CTaala2KenProvider_CreateInstance(REFIID riid, void** ppv)
{
    HRESULT hr = E_OUTOFMEMORY;
    CTaala2KenProvider* pProvider = new CTaala2KenProvider();
    if (pProvider != NULL)
    {
        hr = pProvider->QueryInterface(riid, ppv);
        pProvider->Release();
    }
    return hr;
}
