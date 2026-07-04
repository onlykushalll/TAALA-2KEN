#pragma once
#include <windows.h>
#include <string>

class CPipeClient
{
public:
    CPipeClient();
    ~CPipeClient();

    // Query status from Python daemon
    // Populates outStatus, outDeviceType, outRequiresChallenge
    bool QueryDaemonStatus(std::wstring& outStatus, std::wstring& outDeviceType, bool& outRequiresChallenge);

    // Sends challenge nonce to Python to sign with token's private key
    // Returns hex signature on success
    bool RequestChallengeSignature(const std::wstring& nonceHex, std::wstring& outSignatureHex);

private:
    HANDLE _hPipe;
    bool Connect();
    void Disconnect();
    bool SendReceive(const std::string& requestJson, std::string& outResponseJson);
};
