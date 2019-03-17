#pragma once

#include "stdafx.h"

#include <Zydis/Zydis.h>
#include <nlohmann/json.hpp>
#include "hookFunctions.h"

class Hook
{
	HMODULE NtdllModule{};
	HMODULE KernelBaseModule{};
	ZydisDecoder decoder;

	void HookFunction(std::string targetFunction, DWORD_PTR hookFunc, std::string libModule) const;

public:
	Hook();
	bool HookFuncs() const;
};

inline void Hook::HookFunction(const std::string targetFunction, const DWORD_PTR hookFunc,
                               const std::string libModule) const
{
	HMODULE lib;
	if (libModule == "ntdll")
	{
		lib = NtdllModule;
	}
	else
	{
		lib = KernelBaseModule;
	}
	if (!lib)
	{
		return;
	}
	auto targetFuncAddress = static_cast<LPVOID>(GetProcAddress(lib, targetFunction.c_str()));

	const ZyanUSize length = 0x10; // MAX INSTR size
	ZydisDecodedInstruction instruction;
	if (!		ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, targetFuncAddress, length,
		&instruction)))
		return;

	auto nextInstruction = reinterpret_cast<DWORD_PTR>(targetFuncAddress);
	if (instruction.mnemonic == ZYDIS_MNEMONIC_MOV)
	{
		nextInstruction = reinterpret_cast<DWORD_PTR>(targetFuncAddress) + instruction.length;
	}


#if defined(_WIN64)
	byte jmp[] = {0x48, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xFF, 0xE0};
	DWORD old;
	VirtualProtectEx(GetCurrentProcess(), reinterpret_cast<LPVOID>(nextInstruction), 100, PAGE_EXECUTE_READWRITE, &old);
	memcpy_s(reinterpret_cast<PVOID>(nextInstruction), 2, jmp, 2);
	*reinterpret_cast<DWORD_PTR*>(reinterpret_cast<byte*>(nextInstruction) + 2) = static_cast<DWORD_PTR>(hookFunc);
	memcpy_s(reinterpret_cast<byte*>(nextInstruction) + 10, 2, jmp + 10, 2);
	VirtualProtectEx(GetCurrentProcess(), reinterpret_cast<LPVOID>(nextInstruction), 100, old, &old);
#else
	byte jmp[] = { 0x68, 0xCC, 0xCC, 0xCC, 0xCC, 0xC3 };
	DWORD old;
	VirtualProtectEx(GetCurrentProcess(), reinterpret_cast<LPVOID>(nextInstruction), 100, PAGE_EXECUTE_READWRITE, &old);
	memcpy_s(reinterpret_cast<PVOID>(nextInstruction), 1, jmp, 1);
	*reinterpret_cast<DWORD32*>(reinterpret_cast<byte*>(nextInstruction) + 1) = static_cast<DWORD32>(hookFunc);
	memcpy_s(reinterpret_cast<byte*>(nextInstruction) + 5, 1, jmp + 5, 1);
	VirtualProtectEx(GetCurrentProcess(), reinterpret_cast<LPVOID>(nextInstruction), 100, old, &old);
#endif
}


inline Hook::Hook()
{
	TCHAR tmp[MAX_PATH + 2]{};
	GetTempPath(MAX_PATH + 2, tmp);
	TCHAR sys[MAX_PATH + 2]{};
	GetSystemDirectory(sys, MAX_PATH + 2);

	auto randomNtdllPath = std::wstring{tmp} + GenRandStr(4) + L".dll";
	auto ntdllPath = std::wstring{sys} + L"\\ntdll.dll";
	CopyFile(ntdllPath.c_str(), randomNtdllPath.c_str(), FALSE);
	ntdllCopyModule = LoadLibrary(randomNtdllPath.c_str()); // for us ;)
	NtdllModule = LoadLibrary(L"ntdll");
	if (!ntdllCopyModule || !NtdllModule)
	{
		OutputDebugString(L"Failed loading ntdll module");
		RaiseException(1, 0, 0, nullptr); // TODO: better exception
	}


	auto randomKernelBasePath = std::wstring{tmp} + GenRandStr(5) + L".dll";
	auto kernelBasePath = std::wstring{sys} + L"\\kernelbase.dll";
	CopyFile(kernelBasePath.c_str(), randomKernelBasePath.c_str(), FALSE);
	kernelBaseCopyModule = LoadLibrary(randomKernelBasePath.c_str()); // for us ;)
	KernelBaseModule = LoadLibrary(L"kernelbase");
	if (!kernelBaseCopyModule || !KernelBaseModule)
	{
		OutputDebugString(L"Failed loading kernelbase module");
		RaiseException(1, 0, 0, nullptr); // TODO: better exception
	}

	const auto currentModuleHandle = GetModuleHandle(nullptr);
	if (!currentModuleHandle)
		return;
	if (!GetModuleInformation(GetCurrentProcess(), currentModuleHandle, &currentModuleInfo, sizeof(MODULEINFO)))
	{
		OutputDebugString(L"Failed getting main module information");
		RaiseException(1, 0, 0, nullptr); // TODO: better exception
	}

	const auto hFile = CreateFile(L"checks.json", GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
	if (INVALID_HANDLE_VALUE != hFile)
	{
		LARGE_INTEGER li;
		GetFileSizeEx(hFile, &li);

		auto chBuffer = std::unique_ptr<char[]>(new char[li.QuadPart + sizeof(char)]{});
		ReadFile(hFile, chBuffer.get(), li.QuadPart + sizeof(char), nullptr, nullptr);
		jsObject = nlohmann::json::parse(chBuffer.get());
		CloseHandle(hFile);
	}

#if defined(_WIN64)
	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
#else
	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_ADDRESS_WIDTH_32);
#endif
}

inline bool Hook::HookFuncs() const
{
	//// ntdll
	HookFunction("NtClose", DWORD_PTR(HookNtClose), "ntdll");
	HookFunction("NtOpenProcess", DWORD_PTR(HookNtOpenProcess), "ntdll");
	HookFunction("NtCreateFile", DWORD_PTR(HookNtCreateFile), "ntdll");
	HookFunction("NtSetDebugFilterState", DWORD_PTR(HookNtSetDebugFilterState), "ntdll");
	HookFunction("NtQueryInformationProcess", DWORD_PTR(HookNtQueryInformationProcess), "ntdll");
	HookFunction("NtQuerySystemInformation", DWORD_PTR(HookNtQuerySystemInformation), "ntdll");
	HookFunction("NtSetInformationThread", DWORD_PTR(HookNtSetInformationThread), "ntdll");
	HookFunction("NtCreateUserProcess", DWORD_PTR(HookNtCreateUserProcess), "ntdll");
	HookFunction("NtCreateThreadEx", DWORD_PTR(HookNtCreateThreadEx), "ntdll");
	HookFunction("NtSystemDebugControl", DWORD_PTR(HookNtSystemDebugControl), "ntdll");
	HookFunction("NtYieldExecution", DWORD_PTR(HookNtYieldExecution), "ntdll");
	HookFunction("NtSetLdtEntries", DWORD_PTR(HookNtSetLdtEntries), "ntdll");
	HookFunction("NtQueryInformationThread", DWORD_PTR(HookNtQueryInformationThread), "ntdll");
	HookFunction("NtCreateDebugObject", DWORD_PTR(HookNtCreateDebugObject), "ntdll");
	HookFunction("NtQueryObject", DWORD_PTR(HookNtQueryObject), "ntdll");
	HookFunction("RtlAdjustPrivilege", DWORD_PTR(HookRtlAdjustPrivilege), "ntdll");
	HookFunction("NtShutdownSystem", DWORD_PTR(HookNtShutdownSystem), "ntdll");
	HookFunction("ZwGetContextThread", DWORD_PTR(HookGetThreadContext), "ntdll");

	//// Causes ZwAllocateVirtualMemory related errors TODO: FIX it
	////hookFunction("ZwAllocateVirtualMemory", DWORD_PTR(hookZwAllocateVirtualMemory), L"ntdll");
	////hookFunction("ZwGetWriteWatch", DWORD_PTR(hookZwGetWriteWatch), L"ntdll");

	//// kernelbase
	HookFunction("IsDebuggerPresent", DWORD_PTR(HookIsDebuggerPresent), "kernelbase");
	HookFunction("CheckRemoteDebuggerPresent", DWORD_PTR(HookCheckRemoteDebuggerPresent), "kernelbase");
	//HookFunction("SetUnhandledExceptionFilter", DWORD_PTR(hookSetUnhandledExceptionFilter), "kernelbase");
	//// what about hooking Rtl version from ntdll?

	//// registry checks

	HookFunction("RegOpenKeyExInternalW", DWORD_PTR(HookRegOpenKeyExInternalW), "kernelbase"); // not stable
	HookFunction("RegQueryValueExW", DWORD_PTR(HookRegQueryValueExW), "RegQueryValueExW");
	//// don't forget "process_output_string" func

	return true;
}
