#pragma once

#define STATUS_SUCCESS                   0x00000000L  
#define STATUS_ACCESS_DENIED             0xC0000022L

typedef enum _PROCESSINFOCLASS {
	ProcessBasicInformation = 0,
	ProcessQuotaLimits = 1,
	ProcessIoCounters = 2,
	ProcessVmCounters = 3,
	ProcessTimes = 4,
	ProcessBasePriority = 5,
	ProcessRaisePriority = 6,
	ProcessDebugPort = 7,
	ProcessExceptionPort = 8,
	ProcessAccessToken = 9,
	ProcessLdrInformation = 10,
	ProcessLdtSize = 11,
	ProcessDefaultHardErrorMode = 12,
	ProcessIoPortHandlers = 13,
	ProcessPooledUsageAndLimits = 14,
	ProcessWorkingSetWatch = 15,
	ProcessUserModeIOPL = 16,
	ProcessEnableAlignmentFaultFixup = 17,
	ProcessPriorityClass = 18,
	ProcessWx86Information = 19,
	ProcessHandleCount = 20,
	ProcessAffinityMask = 21,
	ProcessPriorityBoost = 22,
	ProcessDeviceMap = 23,
	ProcessSessionInformation = 24,
	ProcessForegroundInformation = 25,
	ProcessWow64Information = 26,
	ProcessImageFileName = 27,
	ProcessLUIDDeviceMapsEnabled = 28,
	ProcessBreakOnTermination = 29,
	ProcessDebugObjectHandle = 30,
	ProcessDebugFlags = 31,
	ProcessHandleTracing = 32,
	ProcessIoPriority = 33,
	ProcessExecuteFlags = 34,
	ProcessTlsInformation = 35,
	ProcessCookie = 36,
	ProcessImageInformation = 37,
	ProcessCycleTime = 38,
	ProcessPagePriority = 39,
	ProcessInstrumentationCallback = 40,
	ProcessThreadStackAllocation = 41,
	ProcessWorkingSetWatchEx = 42,
	ProcessImageFileNameWin32 = 43,
	ProcessImageFileMapping = 44,
	ProcessAffinityUpdateMode = 45,
	ProcessMemoryAllocationMode = 46,
	ProcessGroupInformation = 47,
	ProcessTokenVirtualizationEnabled = 48,
	ProcessConsoleHostProcess = 49,
	ProcessWindowInformation = 50,
	MaxProcessInfoClass    // always last one so no need to add a value manually
} PROCESSINFOCLASS;

typedef enum _THREADINFOCLASS {
	ThreadBasicInformation = 0,
	ThreadTimes = 1,
	ThreadPriority = 2,
	ThreadBasePriority = 3,
	ThreadAffinityMask = 4,
	ThreadImpersonationToken = 5,
	ThreadDescriptorTableEntry = 6,
	ThreadEnableAlignmentFaultFixup = 7,
	ThreadEventPair_Reusable = 8,
	ThreadQuerySetWin32StartAddress = 9,
	ThreadZeroTlsCell = 10,
	ThreadPerformanceCount = 11,
	ThreadAmILastThread = 12,
	ThreadIdealProcessor = 13,
	ThreadPriorityBoost = 14,
	ThreadSetTlsArrayAddress = 15,   // Obsolete
	ThreadIsIoPending = 16,
	ThreadHideFromDebugger = 17,
	ThreadBreakOnTermination = 18,
	ThreadSwitchLegacyState = 19,
	ThreadIsTerminated = 20,
	ThreadLastSystemCall = 21,
	ThreadIoPriority = 22,
	ThreadCycleTime = 23,
	ThreadPagePriority = 24,
	ThreadActualBasePriority = 25,
	ThreadTebInformation = 26,
	ThreadCSwitchMon = 27,   // Obsolete
	ThreadCSwitchPmu = 28,
	ThreadWow64Context = 29,
	ThreadGroupInformation = 30,
	ThreadUmsInformation = 31,   // UMS
	ThreadCounterProfiling = 32,
	ThreadIdealProcessorEx = 33,
	ThreadCpuAccountingInformation = 34,
	ThreadSuspendCount = 35,
	ThreadActualGroupAffinity = 41,
	ThreadDynamicCodePolicyInfo = 42,
	ThreadSubsystemInformation = 45,

	MaxThreadInfoClass = 50,
} THREADINFOCLASS;

typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION
{
	BOOLEAN KernelDebuggerEnabled;
	BOOLEAN KernelDebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION, *PSYSTEM_KERNEL_DEBUGGER_INFORMATION;


typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE           Reserved1[16];
	PVOID          Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID;
typedef CLIENT_ID *PCLIENT_ID;

//typedef void xNtRaiseException(
//	IN PEXCEPTION_RECORD    ExceptionRecord,
//	IN PCONTEXT             ThreadContext,
//	IN BOOLEAN              HandleException);

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;        // Points to type SECURITY_DESCRIPTOR
	PVOID SecurityQualityOfService;  // Points to type SECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES *POBJECT_ATTRIBUTES;


typedef struct _PEB {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	LPVOID /*PPEB_LDR_DATA*/ Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID Reserved4[3];
	PVOID AtlThunkSListPtr;
	PVOID Reserved5;
	ULONG Reserved6;
	PVOID Reserved7;
	ULONG Reserved8;
	ULONG AtlThunkSListPtr32;
	PVOID Reserved9[45];
	BYTE Reserved10[96];
	LPVOID /*PPS_POST_PROCESS_INIT_ROUTINE*/ PostProcessInitRoutine;
	BYTE Reserved11[128];
	PVOID Reserved12[1];
	ULONG SessionId;
} PEB, *PPEB;


typedef enum _DEBUG_CONTROL_CODE {
	DebugSysGetTraceInformation = 1,
	DebugSysSetInternalBreakpoint,
	DebugSysSetSpecialCall,
	DebugSysClerSpecialCalls,
	DebugSysQuerySpecialCalls,
	DebugSysBreakpointWithStatus,
	DebugSysGetVersion,
	DebugSysReadVirtual,
	DebugSysWriteVirtual,
	DebugSysReadPhysical,
	DebugSysWritePhysical,
	DebugSysReadControlSpace,
	DebugSysWriteControlSpace,
	DebugSysReadIoSpace,
	DebugSysSysWriteIoSpace,
	DebugSysReadMsr,
	DebugSysWriteMsr,
	DebugSysReadBusData,
	DebugSysWriteBusData,
	DebugSysCheckLowMemory,
} DEBUG_CONTROL_CODE;

