#include <windows.h>
#include <unknwn.h>
#include <olectl.h>
#include <shlwapi.h>
#include "guid.h"

// Forward declare module reference count
extern long g_cRefModule;

// Forward declaration of class factory implementation
class CClassFactory : public IClassFactory
{
public:
    CClassFactory(REFCLSID clsid) : _cRef(1), _clsid(clsid) {}

    // IUnknown
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv)
    {
        static const QITAB qit[] = {
            QIT_INTERFACE_ENTRY(IClassFactory),
            { 0 },
        };
        return QISearch(this, qit, riid, ppv);
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

    // IClassFactory
    IFACEMETHODIMP CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppv);
    IFACEMETHODIMP LockServer(BOOL fLock)
    {
        if (fLock)
        {
            InterlockedIncrement(&g_cRefModule);
        }
        else
        {
            InterlockedDecrement(&g_cRefModule);
        }
        return S_OK;
    }

private:
    long _cRef;
    CLSID _clsid;
};

// Global variables
long g_cRefModule = 0;
HINSTANCE g_hInst = NULL;

// In Provider.cpp
extern HRESULT CTaala2KenProvider_CreateInstance(REFIID riid, void** ppv);

IFACEMETHODIMP CClassFactory::CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppv)
{
    *ppv = NULL;
    HRESULT hr = E_OUTOFMEMORY;
    if (pUnkOuter != NULL)
    {
        hr = CLASS_E_NOAGGREGATION;
    }
    else if (_clsid == CLSID_Taala2KenProvider)
    {
        hr = CTaala2KenProvider_CreateInstance(riid, ppv);
    }
    else
    {
        hr = CLASS_E_CLASSNOTAVAILABLE;
    }
    return hr;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        g_hInst = hModule;
        DisableThreadLibraryCalls(hModule);
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

STDAPI DllCanUnloadNow()
{
    return (g_cRefModule == 0) ? S_OK : S_FALSE;
}

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv)
{
    *ppv = NULL;
    HRESULT hr = CLASS_E_CLASSNOTAVAILABLE;
    if (rclsid == CLSID_Taala2KenProvider)
    {
        CClassFactory* pClassFactory = new CClassFactory(rclsid);
        if (pClassFactory != NULL)
        {
            hr = pClassFactory->QueryInterface(riid, ppv);
            pClassFactory->Release();
        }
        else
        {
            hr = E_OUTOFMEMORY;
        }
    }
    return hr;
}

// Registry Helper Function
HRESULT CreateRegistryKey(HKEY hKeyParent, LPCWSTR subKey, LPCWSTR valueName, LPCWSTR data)
{
    HKEY hKey;
    LONG result = RegCreateKeyExW(hKeyParent, subKey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
    if (result != ERROR_SUCCESS)
    {
        return HRESULT_FROM_WIN32(result);
    }

    if (data != NULL)
    {
        result = RegSetValueExW(hKey, valueName, 0, REG_SZ, (const BYTE*)data, (DWORD)((wcslen(data) + 1) * sizeof(wchar_t)));
    }
    
    RegCloseKey(hKey);
    return HRESULT_FROM_WIN32(result);
}

STDAPI DllRegisterServer()
{
    wchar_t szModule[MAX_PATH];
    if (GetModuleFileNameW(g_hInst, szModule, ARRAYSIZE(szModule)) == 0)
    {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    // Register CLSID in CLSID root
    wchar_t clsidSubKey[128];
    // Guid string formatting
    const wchar_t* guidStr = L"{C1C0D7B6-8C3D-4A59-8669-70E2F0BF9B43}";
    wsprintfW(clsidSubKey, L"CLSID\\%s", guidStr);

    HRESULT hr = CreateRegistryKey(HKEY_CLASSES_ROOT, clsidSubKey, NULL, L"TAALA-2KEN USB Credential Provider");
    if (SUCCEEDED(hr))
    {
        wchar_t inprocSubKey[256];
        wsprintfW(inprocSubKey, L"%s\\InprocServer32", clsidSubKey);
        hr = CreateRegistryKey(HKEY_CLASSES_ROOT, inprocSubKey, NULL, szModule);
        if (SUCCEEDED(hr))
        {
            hr = CreateRegistryKey(HKEY_CLASSES_ROOT, inprocSubKey, L"ThreadingModel", L"Apartment");
        }
    }

    // Register with Windows Credential Providers list
    if (SUCCEEDED(hr))
    {
        wchar_t cpSubKey[256];
        wsprintfW(cpSubKey, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\%s", guidStr);
        hr = CreateRegistryKey(HKEY_LOCAL_MACHINE, cpSubKey, NULL, L"Taala2KenProvider");
    }

    return hr;
}

STDAPI DllUnregisterServer()
{
    const wchar_t* guidStr = L"{C1C0D7B6-8C3D-4A59-8669-70E2F0BF9B43}";
    
    wchar_t clsidSubKey[128];
    wsprintfW(clsidSubKey, L"CLSID\\%s", guidStr);
    
    // Delete InprocServer32 first
    wchar_t inprocSubKey[256];
    wsprintfW(inprocSubKey, L"%s\\InprocServer32", clsidSubKey);
    RegDeleteKeyW(HKEY_CLASSES_ROOT, inprocSubKey);
    RegDeleteKeyW(HKEY_CLASSES_ROOT, clsidSubKey);

    wchar_t cpSubKey[256];
    wsprintfW(cpSubKey, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\%s", guidStr);
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, cpSubKey);

    return S_OK;
}
