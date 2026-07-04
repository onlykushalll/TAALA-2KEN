#pragma once
#include <windows.h>
#include <string>

// Checks if a USB device matching the registered PnP ID prefix is connected.
// Uses SetupAPI directly, making it fully functional on the Secure Desktop.
bool IsRegisteredUSBConnected(const std::wstring& pnpIdPrefix);
