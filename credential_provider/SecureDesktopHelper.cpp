#include "SecureDesktopHelper.h"
#include <setupapi.h>
#include <cfgmgr32.h>
#include <tchar.h>

#pragma comment(lib, "setupapi.lib")

bool IsRegisteredUSBConnected(const std::wstring& pnpIdPrefix)
{
    if (pnpIdPrefix.empty())
    {
        return false;
    }

    HDEVINFO hDevInfo = SetupDiGetClassDevsW(NULL, L"USB", NULL, DIGCF_ALLCLASSES | DIGCF_PRESENT);
    if (hDevInfo == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    SP_DEVINFO_DATA devInfoData;
    devInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
    DWORD deviceIndex = 0;
    bool found = false;

    while (SetupDiEnumDeviceInfo(hDevInfo, deviceIndex, &devInfoData))
    {
        deviceIndex++;
        wchar_t szInstanceId[MAX_DEVICE_ID_LEN];
        if (CM_Get_Device_IDW(devInfoData.DevInst, szInstanceId, MAX_DEVICE_ID_LEN, 0) == CR_SUCCESS)
        {
            std::wstring instanceId(szInstanceId);
            // Check if prefix matches
            if (instanceId.find(pnpIdPrefix) == 0)
            {
                found = true;
                break;
            }
        }
    }

    SetupDiDestroyDeviceInfoList(hDevInfo);
    return found;
}
