#pragma once

#include "stdafx.h"

#include <nlohmann/json.hpp>

#define MSG_LEN 0x500

BOOL ntCreateDbgObjectCalled = FALSE;
DWORD_PTR memWatchAddress{};
BOOL memWatch = FALSE;

HMODULE ntdllCopyModule = nullptr;
HMODULE kernelBaseCopyModule = nullptr;
MODULEINFO currentModuleInfo{};
nlohmann::json jsObject{};

std::string AddressToHexString(DWORD_PTR address);
std::wstring GenRandStr(size_t size);
TCHAR* NormalizeRegPath(LPCTSTR regPath);
