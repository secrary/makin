//
// author: Lasha Khasaia
// contact: @_qaz_qaz
// license: MIT License
//

#include "stdafx.h"
#include <Psapi.h>

enum DrReg
{
	Dr0,
	Dr1,
	Dr2,
	Dr3
};

typedef NTSTATUS (WINAPI *pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

std::vector<std::string> loadDll{};

std::vector<std::string> hookFunctions{};

inline void SetBits(DWORD_PTR& dw, const DWORD_PTR lowBit, const DWORD_PTR bits, const DWORD_PTR newValue)
{
	const auto mask = (1 << bits) - 1;

	dw = (dw & ~(mask << lowBit)) | (newValue << lowBit);
}

VOID ProcessOutputString(const PROCESS_INFORMATION pi, const OUTPUT_DEBUG_STRING_INFO out_info)
{
	std::unique_ptr<CHAR[]> pMsg{new CHAR[out_info.nDebugStringLength * sizeof(CHAR)]};

	ReadProcessMemory(pi.hProcess, out_info.lpDebugStringData, pMsg.get(), out_info.nDebugStringLength, nullptr);

	//const auto isUnicode = IsTextUnicode(pMsg.get(), out_info.nDebugStringLength, nullptr);

	//if (!isUnicode)
	//	printf("[OutputDebugString] msg: %s\n\n", reinterpret_cast<char*>(pMsg.get())); // as ASCII


	auto cmdSubStr = strstr(pMsg.get(), "DBG_NEW_PROC:");
	if (cmdSubStr != nullptr)
	{
		cmdSubStr += 13;
		printf_s("Monitor new process in a new console...\n\n");

		CHAR curExe[0x1000]{};
		GetModuleFileNameA(nullptr, curExe, 0x1000);

		sprintf_s(curExe, "%s %s", curExe, cmdSubStr);

		STARTUPINFOA nsi{sizeof(STARTUPINFOA)};
		PROCESS_INFORMATION npi{};

		CreateProcessA(nullptr, curExe, nullptr, nullptr, FALSE, CREATE_NEW_CONSOLE, nullptr, nullptr, &nsi, &npi);

		CloseHandle(npi.hProcess);
		CloseHandle(npi.hThread);

		return;
	}

	if (pMsg.get()[0] != '[')
	{
		printf_s("[OutputDebugString] msg: %s\n\n", pMsg.get()); // raw message from the sample
		return;
	}
	if (strlen(pMsg.get()) > 3 && (pMsg.get()[0] == '[' && pMsg.get()[1] == '_' && pMsg.get()[2] == ']'))
		// [_]
	{
		for (const auto& i : loadDll)
		{
			CHAR tmp[MAX_PATH + 2]{};
			strcpy_s(tmp, MAX_PATH + 2, pMsg.get() + 3);
			const std::string tmpStr(tmp);
			if (tmpStr == i) // #SOURCE - The "Ultimate" Anti-Debugging Reference: 7.B.iv
			{
				hookFunctions.emplace_back("LdrLoadDll");
				printf(
					"[LdrLoadDll] The debuggee attempts to use LdrLoadDll/NtCreateFile trick: %s\n\tref: The \"Ultimate\" Anti-Debugging Reference: 7.B.iv\n\n",
					tmpStr.data());
			}
		}
		return;
	}

	printf("%s\n", pMsg.get()); // from us, starts with [ symbol

	// save functions for IDA script
	std::string tmpStr(pMsg.get());

	// ntdll
	if (tmpStr.find("NtClose") != std::string::npos)
	{
		hookFunctions.emplace_back("NtClose");
	}
	else if (tmpStr.find("NtOpenProcess") != std::string::npos)
	{
		hookFunctions.emplace_back("NtOpenProcess");
	}
	else if (tmpStr.find("NtCreateFile") != std::string::npos)
	{
		hookFunctions.emplace_back("NtCreateFile");
	}
	else if (tmpStr.find("NtSetDebugFilterState") != std::string::npos)
	{
		hookFunctions.emplace_back("NtSetDebugFilterState");
	}
	else if (tmpStr.find("NtQueryInformationProcess") != std::string::npos)
	{
		hookFunctions.emplace_back("NtQueryInformationProcess");
	}
	else if (tmpStr.find("NtQuerySystemInformation") != std::string::npos)
	{
		hookFunctions.emplace_back("NtQuerySystemInformation");
	}
	else if (tmpStr.find("NtSetInformationThread") != std::string::npos)
	{
		hookFunctions.emplace_back("NtSetInformationThread");
	}
	else if (tmpStr.find("NtCreateUserProcess") != std::string::npos)
	{
		hookFunctions.emplace_back("NtCreateUserProcess");
	}
	else if (tmpStr.find("NtCreateThreadEx") != std::string::npos)
	{
		hookFunctions.emplace_back("NtCreateThreadEx");
	}
	else if (tmpStr.find("NtSystemDebugControl") != std::string::npos)
	{
		hookFunctions.emplace_back("NtSystemDebugControl");
	}
	else if (tmpStr.find("NtYieldExecution") != std::string::npos)
	{
		hookFunctions.emplace_back("NtYieldExecution");
	}
	else if (tmpStr.find("NtSetLdtEntries") != std::string::npos)
	{
		hookFunctions.emplace_back("NtSetLdtEntries");
	}
	else if (tmpStr.find("NtQueryInformationThread") != std::string::npos)
	{
		hookFunctions.emplace_back("NtQueryInformationThread");
	}
	else if (tmpStr.find("NtCreateDebugObject") != std::string::npos)
	{
		hookFunctions.emplace_back("NtCreateDebugObject");
	}
	else if (tmpStr.find("NtQueryObject") != std::string::npos)
	{
		hookFunctions.emplace_back("NtQueryObject");
	}
	else if (tmpStr.find("RtlAdjustPrivilege") != std::string::npos)
	{
		hookFunctions.emplace_back("RtlAdjustPrivilege");
	}
	else if (tmpStr.find("NtShutdownSystem") != std::string::npos)
	{
		hookFunctions.emplace_back("NtShutdownSystem");
	}
	else if (tmpStr.find("ZwAllocateVirtualMemory") != std::string::npos)
	{
		hookFunctions.emplace_back("ZwAllocateVirtualMemory");
	}
	else if (tmpStr.find("ZwGetWriteWatch") != std::string::npos)
	{
		hookFunctions.emplace_back("ZwGetWriteWatch");

		// kernelbase
	}
	else if (tmpStr.find("IsDebuggerPresent") != std::string::npos)
	{
		hookFunctions.emplace_back("IsDebuggerPresent");
	}
	else if (tmpStr.find("CheckRemoteDebuggerPresent") != std::string::npos)
	{
		hookFunctions.emplace_back("CheckRemoteDebuggerPresent");
	}
	else if (tmpStr.find("SetUnhandledExceptionFilter") != std::string::npos)
	{
		hookFunctions.emplace_back("SetUnhandledExceptionFilter");
	}
	else if (tmpStr.find("RegOpenKeyExInternalW") != std::string::npos)
	{
		hookFunctions.emplace_back("RegOpenKeyExInternalW");
	}
	else if (tmpStr.find("RegQueryValueExW") != std::string::npos)
	{
		hookFunctions.emplace_back("RegQueryValueExW");
	}
}

std::wstring GenRandStr(const size_t size) // just enough randomness
{
	srand(static_cast<unsigned int>(time(nullptr)));
	static const TCHAR ALPHABET[] =
		L"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		L"abcdefghijklmnopqrstuvwxyz";
	std::wstring randString(size, '\x0');
	for (auto& i : randString)
	{
		i = ALPHABET[rand() / (RAND_MAX / (_tcslen(ALPHABET) - 1) + 1)];
	}

	return randString;
}

void SetHardwareBreakpoint(HANDLE tHandle, CONTEXT& cxt, const DWORD_PTR addr, size_t size, DrReg dbgReg)
{
	cxt.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	GetThreadContext(tHandle, &cxt);

	const DWORD_PTR m_index = dbgReg; // Dr_
	switch (dbgReg)
	{
	case Dr0:
		cxt.Dr0 = addr;
		break;
	case Dr1:
		cxt.Dr1 = addr;
		break;
	case Dr2:
		cxt.Dr2 = addr;
		break;
	case Dr3:
		cxt.Dr3 = addr;
		break;
	}

	SetBits(cxt.Dr7, 16 + (m_index * 4), 2, 3); // read/write
	SetBits(cxt.Dr7, 18 + (m_index * 4), 2, size); // size
	SetBits(cxt.Dr7, m_index * 2, 1, 1);

	SetThreadContext(tHandle, &cxt);
}

int _tmain()
{
	// welcome 
	const TCHAR welcome[] = L"makin --- Copyright (c) 2019 Lasha Khasaia\n"
		L"https://www.secrary.com - @_qaz_qaz\n"
		L"----------------------------------------------------\n\n";
	wprintf(L"%s\n", welcome);

	STARTUPINFO si{};
	si.cb = sizeof(si);
	PROCESS_INFORMATION pi{};
	DWORD err;
	DEBUG_EVENT d_event{};
	auto done = FALSE;
	TCHAR dll_path[MAX_PATH + 2]{};
	TCHAR proc_path[MAX_PATH + 2]{};
	auto first_its_me = FALSE;
	CHAR filePath[MAX_PATH + 2]{};
	CONTEXT cxt{};
	//PVOID ex_addr = nullptr;
	HANDLE tHandle{};
	DWORD_PTR expAddress{};

	int nArgs{};
	const auto pArgv = CommandLineToArgvW(GetCommandLine(), &nArgs);

	if (nArgs < 2)
	{
		printf("Usage: \n./makin.exe \"/path/to/sample\"\n");
		return 1;
	}

	TCHAR cmdLine[0x1000]{};
	for (auto i = 2; i < nArgs; ++i)
	{
		_tcscat_s(cmdLine, pArgv[i]);
		_tcscat_s(cmdLine, L" ");
	}

	_tcsncpy_s(proc_path, pArgv[1], MAX_PATH + 2);

	if (!PathFileExists(proc_path))
	{
		err = GetLastError();
		wprintf(L"[!] %s is not a valid file\n", proc_path);
		return err;
	}


	const auto hFile = CreateFile(proc_path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		err = GetLastError();
		printf("CreateFile error: %lu\n", err);
		return err;
	}

	LARGE_INTEGER size{};
	GetFileSizeEx(hFile, &size);

	SYSTEM_INFO sysInfo{};
	GetSystemInfo(&sysInfo);

	const auto hMapFile = CreateFileMapping(hFile,
	                                        nullptr,
	                                        PAGE_READONLY,
	                                        size.HighPart,
	                                        size.LowPart,
	                                        nullptr);

	if (hMapFile == nullptr)
	{
		err = GetLastError();
		printf("CreateFileMapping is NULL: %lu", err);
		return err;
	}

	// Map just one page
	auto lpMapAddress = MapViewOfFile(hMapFile,
	                                  FILE_MAP_READ,
	                                  0,
	                                  0,
	                                  sysInfo.dwPageSize); // one page size is more than we need for now

	if (lpMapAddress == nullptr)
	{
		err = GetLastError();
		printf("MapViewOfFIle is NULL: %lu\n", err);
		return err;
	}
	// IMAGE_DOS_HEADER->e_lfanew
	const auto e_lfanew = *reinterpret_cast<DWORD*>(static_cast<byte*>(lpMapAddress) + sizeof(IMAGE_DOS_HEADER) - sizeof
		(
			DWORD));
	UnmapViewOfFile(lpMapAddress);


	const auto ntMapAddrLow = (e_lfanew / sysInfo.dwAllocationGranularity) * sysInfo.dwAllocationGranularity;
	lpMapAddress = MapViewOfFile(hMapFile,
	                             FILE_MAP_READ,
	                             0,
	                             ntMapAddrLow,
	                             sysInfo.dwPageSize);

	if (lpMapAddress == nullptr)
	{
		err = GetLastError();
		printf("MapViewOfFIle is NULL: %lu\n", err);
		return err;
	}

	auto ntHeaderAddr = lpMapAddress;
	if (ntMapAddrLow != e_lfanew)
	{
		ntHeaderAddr = static_cast<byte*>(ntHeaderAddr) + e_lfanew;
	}

	if (PIMAGE_NT_HEADERS(ntHeaderAddr)->OptionalHeader.DataDirectory[9].VirtualAddress != 0u)
	{
		printf(
			"[TLS] The executable contains TLS callback(s)\nI can not hook code executed by TLS callbacks\nPlease, abort execution and check it manually\n[c]ontinue / [A]bort: \n\n");
		const auto ic = getchar();
		if (ic != 'c')
		{
			ExitProcess(0);
		}
	}

	const DWORD_PTR sizeOfImage = PIMAGE_NT_HEADERS(ntHeaderAddr)->OptionalHeader.SizeOfImage;

	UnmapViewOfFile(lpMapAddress);
	CloseHandle(hMapFile);
	CloseHandle(hFile);

	wprintf(L"PROCESS NAME: %s\nCOMMAND LINE: %s\n\n", proc_path, cmdLine);

	if (!CreateProcess(proc_path, cmdLine, nullptr, nullptr, FALSE,
	                   DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED | DETACHED_PROCESS, nullptr, nullptr, &si, &pi))
	{
		err = GetLastError();
		printf_s("[!] CreateProces failed: %lu\n", err);
		return err;
	}

	// Detect memory accesses

	const auto ntQueryInformationProcess = pNtQueryInformationProcess(
		GetProcAddress(GetModuleHandle(L"ntdll"), "NtQueryInformationProcess"));

	PROCESS_BASIC_INFORMATION pbi{};
	ntQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), nullptr);

	auto peb = DWORD_PTR(pbi.PebBaseAddress);

	const auto pBeingDebugged = DWORD_PTR(reinterpret_cast<byte*>(peb) + 0x2); // PEB->BeingDebugged

#ifndef _WIN64
	peb -= 0x1000; // 32-bit PEB
#endif

	const auto pImageBaseAddress = DWORD_PTR(reinterpret_cast<byte*>(peb) + 0x10);
	// 0x010 ImageBaseAddress : Ptr64 Void

	DWORD_PTR imageBaseAddress{};
	SIZE_T ret{};
	if (pImageBaseAddress != 0u)
	{
		ReadProcessMemory(pi.hProcess, PVOID(pImageBaseAddress), &imageBaseAddress, sizeof(DWORD_PTR), &ret);
	}

	SetHardwareBreakpoint(pi.hThread, cxt, pBeingDebugged, 1, Dr0);

	// GlobalFlags
	DWORD_PTR pNtGlobalFlag{};
#ifdef _WIN64
	pNtGlobalFlag = DWORD_PTR(reinterpret_cast<byte*>(peb) + 0xBC);
#else
	pNtGlobalFlag = DWORD_PTR(reinterpret_cast<byte*>(peb) + 0x68);
	pNtGlobalFlag += 0x1000; // 32-bit PEB
#endif

	SetHardwareBreakpoint(pi.hThread, cxt, pNtGlobalFlag, 2, Dr1);

	// ref: https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/Anti%20Debug/SharedUserData_KernelDebugger.cpp
	// KUSER_SHARED_DATA: https://www.geoffchappell.com/studies/windows/km/ntoskrnl/structs/kuser_shared_data.htm
	const ULONG_PTR userSharedData = 0x7FFE0000;
	const auto kdDebuggerEnabledByte = userSharedData + 0x2D4; // UserSharedData->KdDebuggerEnabled

	SetHardwareBreakpoint(pi.hThread, cxt, kdDebuggerEnabledByte, sizeof(BOOLEAN), Dr2);


	// Create Job object
	// UPDATE: dbg child proc.
	//JOBOBJECT_EXTENDED_LIMIT_INFORMATION jbli{0};
	//JOBOBJECT_BASIC_UI_RESTRICTIONS jbur;
	//const auto hJob = CreateJobObject(nullptr, L"makinAKAasho");
	//if (hJob)
	//{
	//   jbli.BasicLimitInformation.ActiveProcessLimit = 1; // Blocked new process creation
	//   jbli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

	//   jbur.UIRestrictionsClass = JOB_OBJECT_UILIMIT_DESKTOP | JOB_OBJECT_UILIMIT_EXITWINDOWS;
	//   /*| JOB_OBJECT_UILIMIT_HANDLES*/ // uncomment if you want

	//   SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &jbli, sizeof(jbli));

	//   SetInformationJobObject(hJob, JobObjectBasicUIRestrictions, &jbur, sizeof(jbur));

	//   if (!AssignProcessToJobObject(hJob, pi.hProcess))
	//   {
	//      printf("[!] AssignProcessToJobObject failed: %ul\n", GetLastError());
	//   }
	//}

#ifdef _DEBUG
	SetCurrentDirectory(L"../Debug");
#ifdef _WIN64
	SetCurrentDirectory(L"../x64/Debug");
#endif
#endif

	GetFullPathName(L"./asho.dll", MAX_PATH + 2, dll_path, nullptr);
	if (!PathFileExists(dll_path))
	{
		err = GetLastError();
		wprintf(L"[!] %s is not a valid file\n", dll_path);

		return err;
	}

	// generate random name for asho.dll ;)
	TCHAR ashoTmpDir[MAX_PATH + 2]{};
	GetTempPath(MAX_PATH + 2, ashoTmpDir);
	auto ashoPath = std::wstring{ashoTmpDir} + GenRandStr(6) + L".dll";
	const auto cStatus = CopyFile(dll_path, ashoPath.c_str(), FALSE);
	if (cStatus == 0)
	{
		err = GetLastError();
		wprintf(L"[!] CopyFile failed: %lu\n", err);

		return err;
	}
	if (!PathFileExists(ashoPath.c_str()))
	{
		err = GetLastError();
		wprintf(L"[!] %s is not a valid file\n", ashoPath.c_str());

		return err;
	}

	const auto p_alloc = VirtualAllocEx(pi.hProcess, nullptr, MAX_PATH + 2, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (p_alloc == nullptr)
	{
		err = GetLastError();
		printf("[!] Allocation failed: %lu\n", err);
		return err;
	}
	if (WriteProcessMemory(pi.hProcess, p_alloc, ashoPath.c_str(), MAX_PATH + 2, nullptr) == 0)
	{
		err = GetLastError();
		printf("WriteProcessMemory failed: %lu\n", err);
		return err;
	}
	const auto h_module = GetModuleHandle(L"kernel32");
	if (h_module == nullptr)
	{
		err = GetLastError();
		printf("GetmModuleHandle failed: %lu\n", err);
		return err;
	}
	const auto loadLibraryAddress = GetProcAddress(h_module, "LoadLibraryW");

	if (loadLibraryAddress == nullptr)
	{
		err = GetLastError();
		printf("GetProcAddress failed: %lu\n", err);
		return err;
	}

	const auto qStatus = QueueUserAPC(PAPCFUNC(loadLibraryAddress), pi.hThread, ULONG_PTR(p_alloc));
	if (qStatus == 0u)
	{
		err = GetLastError();
		printf("QueueUserAPC failed: %lu\n", err);
		return err;
	}

	ResumeThread(pi.hThread);

	while (done == 0)
	{
		auto contStatus = DBG_CONTINUE;
		if (WaitForDebugEvent(&d_event, INFINITE) != 0)
		{
			switch (d_event.dwDebugEventCode)
			{
			case OUTPUT_DEBUG_STRING_EVENT:
				ProcessOutputString(pi, d_event.u.DebugString);

				contStatus = DBG_CONTINUE;
				break;
			case LOAD_DLL_DEBUG_EVENT:
				// we get load dll as file handle 
				if (GetFinalPathNameByHandleA(d_event.u.LoadDll.hFile, filePath, MAX_PATH + 2, 0) != 0u)
				{
					const std::string tmpStr(filePath + 4);
					loadDll.emplace_back(tmpStr);
				}
				// to avoid LdrloadDll / NtCreateFile trick ;)
				CloseHandle(d_event.u.LoadDll.hFile);
				break;

			case EXCEPTION_DEBUG_EVENT:
				contStatus = DBG_EXCEPTION_NOT_HANDLED;
				if (d_event.u.Exception.dwFirstChance == 0u)
				{
					break;
				}
				switch (d_event.u.Exception.ExceptionRecord.ExceptionCode)
				{
				case EXCEPTION_ACCESS_VIOLATION:
					printf("[EXCEPTION] EXCEPTION_ACCESS_VIOLATION\n\n");
					system("pause");
					//cont_status = DBG_EXCEPTION_HANDLED;
					break;

				case EXCEPTION_BREAKPOINT:

					if (first_its_me == 0)
					{
						first_its_me = TRUE;
						break;
					}
					printf("[EXCEPTION] EXCEPTION_BREAKPOINT\n\n");
					// cont_status = DBG_EXCEPTION_HANDLED;

					break;

					/*case EXCEPTION_DATATYPE_MISALIGNMENT:
					printf("[EXCEPTION] EXCEPTION_DATATYPE_MISALIGNMENT\n");
	 
					break;*/

				case EXCEPTION_SINGLE_STEP:

					expAddress = DWORD_PTR(d_event.u.Exception.ExceptionRecord.ExceptionAddress);

					// HANDLE hardware accesses

					tHandle = OpenThread(GENERIC_ALL, FALSE, d_event.dwThreadId);
					if (tHandle == nullptr)
					{
						break;
					}
					cxt.ContextFlags = CONTEXT_DEBUG_REGISTERS;
					GetThreadContext(tHandle, &cxt);
					CloseHandle(tHandle);

					if ((cxt.Dr6 & 0b1111) != 0u)
					{
						//  There are HBs
						contStatus = DBG_EXCEPTION_HANDLED;
					}
					else
					{
						printf("[EXCEPTION] EXCEPTION_SINGLE_STEP\n");
					}

					if (expAddress > imageBaseAddress && expAddress < imageBaseAddress + sizeOfImage)
					{
						if ((cxt.Dr6 & 0x1) != 0u)
						{
							printf(
								"[PEB->BeingDebugged] The debuggee attempts to detect a debugger.\nBase address of the image: 0x%p\nException address: 0x%p\nRVA: 0x%p\n\n",
								PVOID(imageBaseAddress), PVOID(expAddress), PVOID(expAddress - imageBaseAddress));
						}
						else if ((cxt.Dr6 & 0b10) != 0u)
						{
							printf(
								"[PEB->NtGlobalFlag] The debuggee attempts to detect a debugger.\nBase address of the image: 0x%p\nException address: 0x%p\nRVA: 0x%p\n\n",
								PVOID(imageBaseAddress), PVOID(expAddress), PVOID(expAddress - imageBaseAddress));
						}
						else if ((cxt.Dr6 & 0b100) != 0u)
						{
							printf(
								"[UserSharedData->KdDebuggerEnabled] The debuggee attempts to detect a debugger.\nBase address of the image: 0x%p\nException address: 0x%p\nRVA: 0x%p\n\n",
								PVOID(imageBaseAddress), PVOID(expAddress), PVOID(expAddress - imageBaseAddress));
						}
						else if ((cxt.Dr6 & 0b1000) != 0u)
						{
							printf("DR3\n"); // Not implemented yet
						}

						break;
					}

					break;

				case DBG_CONTROL_C:
					printf("[EXCEPTION] DBG_CONTROL_C\n\n");

					break;

				case EXCEPTION_GUARD_PAGE:
					printf("[EXCEPTION] EXCEPTION_GUARD_PAGE\n\n");
					// cont_status = DBG_EXCEPTION_HANDLED;
					break;

				default:
					// Handle other exceptions. 
					break;
				}
				break;
			case EXIT_PROCESS_DEBUG_EVENT:
				done = TRUE;
				printf("[EOF] ========================================================================\n");
				system("pause");
				break;

			default:
				break;
			}

			ContinueDebugEvent(d_event.dwProcessId, d_event.dwThreadId, contStatus);
		}
	}

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	//if (hJob)
	//   CloseHandle(hJob);

	// IDA script TODO: FIX fn calls
	//char header[] =
	//	"import idc\n"
	//	"import idaapi\n"
	//	"import idautils\n"
	//	"\n"
	//	"hookFunctions = [\n";
	//char tail[] =
	//	"\n]\n"
	//	"\n"
	//	"def makinbp():\n"
	//	"	if not idaapi.is_debugger_on():\n"
	//	"		print \"Please run the process... and call makinbp() again\"\n"
	//	"		return\n"
	//	"	print \"\\n\\n---------- makin ----------- \\n\\n\"\n"
	//	"	for mods in idautils.Modules():\n"
	//	"		if \"ntdll.dll\" in mods.name.lower() or \"kernelbase.dll\" in mods.name.lower():\n"
	//	"			# idaapi.analyze_area(mods.base, mods.base + mods.size)\n"
	//	"			name_addr = idaapi.get_debug_names(mods.base, mods.base + mods.size)\n"
	//	"			for addr in name_addr:\n"
	//	"				func_name = Name(addr)\n"
	//	"				func_name = func_name.split(\"_\")[1]\n"
	//	"				for funcs in hookFunctions:\n"
	//	"					if funcs.lower() == func_name.lower():\n"
	//	"						print \"Adding bp on \", hex(addr), func_name\n"
	//	"						add_bpt(addr)\n"
	//	"						hookFunctions.remove(funcs)\n"
	//	"	print \"\\n\\n----------EOF makin EOF----------- \\n\""
	//	"\n\n"
	//	"def main():\n"
	//	"	if idaapi.is_debugger_on():\n"
	//	"		makinbp()\n"
	//	"	else:\n"
	//	"		print \"Please run the process... and call makinbp()\"\n"
	//	"\n"
	//	"main()\n";


	//const auto hFileIda = CreateFile(L"makin_ida_bp.py", GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr);
	//if (hFileIda == INVALID_HANDLE_VALUE)
	//{
	//   err = GetLastError();
	//   wprintf(L"CreateFile failed: %lu", err);
	//}

	//WriteFile(hFileIda, header, strlen(header), nullptr, nullptr);

	//// http://en.cppreference.com/w/cpp/algorithm/unique
	//std::sort(hookFunctions.begin(), hookFunctions.end());
	//const auto last = std::unique(hookFunctions.begin(), hookFunctions.end());
	//hookFunctions.erase(last, hookFunctions.end());

	//for (auto func : hookFunctions)
	//{
	//   WriteFile(hFileIda, "\"", strlen("\""), nullptr, nullptr);
	//   WriteFile(hFileIda, func.data(), strlen(func.data()), nullptr, nullptr);
	//   WriteFile(hFileIda, "\",\n", strlen("\",\n"), nullptr, nullptr);
	//}

	//WriteFile(hFileIda, tail, strlen(tail), nullptr, nullptr);

	//CloseHandle(hFileIda);

	return 0;
}
