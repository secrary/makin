// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files:
#include <windows.h>

#include <stdio.h>
#include <tchar.h>

// TODO: reference additional headers your program requires here

#include <Psapi.h>
#include <Shlwapi.h>
#include <TlHelp32.h>
#include <vector>
#include "Header.h"
#include <memory>
#include <ctime>
#include <Strsafe.h>
#include <intrin.h>

#include <zydis/Zydis.h>
#include <nlohmann/json.hpp>

#pragma comment(lib, "Shlwapi.lib")
