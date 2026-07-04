#include "PipeServer.h"
#include <sstream>

#define PIPE_NAME L"\\\\.\\pipe\\Taala2KenAuth"
#define BUFFER_SIZE 4096

CPipeClient::CPipeClient() : _hPipe(INVALID_HANDLE_VALUE) {}

CPipeClient::~CPipeClient()
{
    Disconnect();
}

bool CPipeClient::Connect()
{
    if (_hPipe != INVALID_HANDLE_VALUE)
    {
        return true;
    }

    // Try opening named pipe
    _hPipe = CreateFileW(
        PIPE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, 0, NULL
    );

    if (_hPipe == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    // Set read mode to MESSAGE
    DWORD dwMode = PIPE_READMODE_MESSAGE;
    if (!SetNamedPipeHandleState(_hPipe, &dwMode, NULL, NULL))
    {
        Disconnect();
        return false;
    }

    return true;
}

void CPipeClient::Disconnect()
{
    if (_hPipe != INVALID_HANDLE_VALUE)
    {
        CloseHandle(_hPipe);
        _hPipe = INVALID_HANDLE_VALUE;
    }
}

bool CPipeClient::SendReceive(const std::string& requestJson, std::string& outResponseJson)
{
    if (!Connect())
    {
        return false;
    }

    DWORD dwWritten = 0;
    BOOL bSuccess = WriteFile(
        _hPipe,
        requestJson.c_str(),
        (DWORD)requestJson.length(),
        &dwWritten,
        NULL
    );

    if (!bSuccess || dwWritten != requestJson.length())
    {
        Disconnect();
        return false;
    }

    char chBuffer[BUFFER_SIZE];
    DWORD dwRead = 0;
    bSuccess = ReadFile(
        _hPipe,
        chBuffer,
        BUFFER_SIZE - 1,
        &dwRead,
        NULL
    );

    if (!bSuccess || dwRead == 0)
    {
        Disconnect();
        return false;
    }

    chBuffer[dwRead] = '\0';
    outResponseJson = std::string(chBuffer);
    return true;
}

// Simple JSON extraction helper
std::wstring ExtractJSONValue(const std::string& json, const std::string& key)
{
    std::string searchKey = "\"" + key + "\":";
    size_t pos = json.find(searchKey);
    if (pos == std::string::npos)
    {
        return L"";
    }

    pos += searchKey.length();
    // Skip spaces
    while (pos < json.length() && (json[pos] == ' ' || json[pos] == '\t'))
    {
        pos++;
    }

    if (pos >= json.length()) return L"";

    if (json[pos] == '"')
    {
        // String value
        pos++;
        size_t endPos = json.find("\"", pos);
        if (endPos == std::string::npos) return L"";
        std::string rawVal = json.substr(pos, endPos - pos);
        
        // Convert to wstring
        std::wstring wVal(rawVal.begin(), rawVal.end());
        return wVal;
    }
    else
    {
        // Primitive value (bool, int)
        size_t endPos = json.find_first_of(",}", pos);
        if (endPos == std::string::npos) return L"";
        std::string rawVal = json.substr(pos, endPos - pos);
        // Trim spaces
        while (!rawVal.empty() && rawVal.back() == ' ') rawVal.pop_back();
        std::wstring wVal(rawVal.begin(), rawVal.end());
        return wVal;
    }
}

bool CPipeClient::QueryDaemonStatus(std::wstring& outStatus, std::wstring& outDeviceType, bool& outRequiresChallenge)
{
    std::string req = "{\"action\": \"query_status\"}";
    std::string res;
    if (!SendReceive(req, res))
    {
        return false;
    }

    outStatus = ExtractJSONValue(res, "status");
    outDeviceType = ExtractJSONValue(res, "device_type");
    std::wstring reqChallenge = ExtractJSONValue(res, "requires_challenge");
    outRequiresChallenge = (reqChallenge == L"true");

    return !outStatus.empty();
}

bool CPipeClient::RequestChallengeSignature(const std::wstring& nonceHex, std::wstring& outSignatureHex)
{
    std::string nonce(nonceHex.begin(), nonceHex.end());
    std::string req = "{\"action\": \"pkcs11_challenge\", \"nonce\": \"" + nonce + "\"}";
    std::string res;
    if (!SendReceive(req, res))
    {
        return false;
    }

    std::wstring status = ExtractJSONValue(res, "status");
    if (status != L"success")
    {
        return false;
    }

    outSignatureHex = ExtractJSONValue(res, "signature");
    return !outSignatureHex.empty();
}
