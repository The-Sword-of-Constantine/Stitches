#pragma once

#pragma warning(push, 3)
#include <suppress.h>
#include <fltKernel.h>
#pragma warning(pop)

#include <ntifs.h>
#include <ntimage.h>
#include <ntstrsafe.h>
#include <ntddk.h>
#include "Locks.hpp"
#include "Api.hpp"

#ifndef MAX_PATH
#define MAX_PATH (260)
#endif

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,
	SystemProcessorInformation,             // obsolete...delete
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemMirrorMemoryInformation,
	SystemPerformanceTraceInformation,
	SystemObsolete0,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeperation,
	SystemVerifierAddDriverInformation,
	SystemVerifierRemoveDriverInformation,
	SystemProcessorIdleInformation,
	SystemLegacyDriverInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation,
	SystemTimeSlipNotification,
	SystemSessionCreate,
	SystemSessionDetach,
	SystemSessionInformation,
	SystemRangeStartInformation,
	SystemVerifierInformation,
	SystemVerifierThunkExtend,
	SystemSessionProcessInformation,
	SystemLoadGdiDriverInSystemSpace,
	SystemNumaProcessorMap,
	SystemPrefetcherInformation,
	SystemExtendedProcessInformation,
	SystemRecommendedSharedDataAlignment,
	SystemComPlusPackage,
	SystemNumaAvailableMemory,
	SystemProcessorPowerInformation,
	SystemEmulationBasicInformation,
	SystemEmulationProcessorInformation,
	SystemExtendedHandleInformation,
	SystemLostDelayedWriteInformation,
	SystemBigPoolInformation,
	SystemSessionPoolTagInformation,
	SystemSessionMappedViewInformation,
	SystemHotpatchInformation,
	SystemObjectSecurityMode,
	SystemWatchdogTimerHandler,
	SystemWatchdogTimerInformation,
	SystemLogicalProcessorInformation,
	SystemWow64SharedInformation,
	SystemRegisterFirmwareTableInformationHandler,
	SystemFirmwareTableInformation,
	SystemModuleInformationEx,
	SystemVerifierTriageInformation,
	SystemSuperfetchInformation,
	SystemMemoryListInformation,
	SystemFileCacheInformationEx,
	MaxSystemInfoClass  // MaxSystemInfoClass should always be the last enum
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER SpareLi1;
	LARGE_INTEGER SpareLi2;
	LARGE_INTEGER SpareLi3;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR PageDirectoryBase;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

typedef struct _SYSTEM_THREAD_INFORMATION {
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	LONG BasePriority;
	ULONG ContextSwitches;
	ULONG ThreadState;
	ULONG WaitReason;
} SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;

//typedef enum _MEMORY_INFORMATION_CLASS_EX
//{
//	MemoryBasicInformationEx = 0,
//	MemoryWorkingSetInformation = 1,
//	MemoryMappedFilenameInformation = 2,
//	MemoryRegionInformation = 3,
//	MemoryWorkingSetExInformation = 4,
//} MEMORY_INFORMATION_CLASS_EX;


EXTERN_C
{
NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID SystemInformation OPTIONAL,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL
);

NTSYSAPI
NTSTATUS
NTAPI
ZwQueryInformationProcess(
	IN  HANDLE ProcessHandle,
	IN  PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN  ULONG ProcessInformationLength,
	IN  PULONG ReturnLength
);



extern PSHORT NtBuildNumber;

NTKERNELAPI
PVOID
NTAPI
PsGetCurrentProcessWow64Process();

NTSYSAPI
NTSTATUS
NTAPI
ZwQueryInformationThread(
	IN HANDLE ThreadHandle,
	IN THREADINFOCLASS ThreadInformationClass,
	OUT PVOID ThreadInformation,
	IN ULONG ThreadInformationLength,
	OUT PULONG ReturnLength OPTIONAL
);

//NTSYSAPI
//NTSTATUS
//NTAPI
//ZwQueryVirtualMemory(
//	IN HANDLE  ProcessHandle,
//	IN PVOID   BaseAddress,
//	IN MEMORY_INFORMATION_CLASS_EX MemoryInformationClass,
//	OUT PVOID  Buffer,
//	IN SIZE_T  Length,
//	OUT PSIZE_T ResultLength
//);


};

//exported since Windows 8.0
typedef
__checkReturn
LOGICAL
(NTAPI* PPsIsProtectedProcess)(
	__in PEPROCESS Process
	);

typedef
__checkReturn
PVOID
(NTAPI* PPsGetProcessWow64Process)(
	__in PEPROCESS Process
	);

typedef
__checkReturn
NTSTATUS
(NTAPI* PPsWrapApcWow64Thread)(
	__inout PVOID* ApcContext,
	__inout PVOID* ApcRoutine
	);

typedef
__checkReturn
LOGICAL
(NTAPI* PPsIsProtectedProcessLight)(
	__in PEPROCESS Process
	);

typedef
__drv_maxIRQL(APC_LEVEL)
SE_SIGNING_LEVEL
(NTAPI* PPsGetProcessSignatureLevel)(
	__in PEPROCESS Process,
	__out PSE_SIGNING_LEVEL SectionSignatureLevel
	);

typedef
__drv_maxIRQL(APC_LEVEL)
__checkReturn
NTSTATUS
(NTAPI* PSeGetCachedSigningLevel)(
	__in PFILE_OBJECT FileObject,
	__out PULONG Flags,
	__out PSE_SIGNING_LEVEL SigningLevel,
	__reserved __out_ecount_full_opt(*ThumbprintSize) PUCHAR Thumbprint,
	__reserved __out_opt PULONG ThumbprintSize,
	__reserved __out_opt PULONG ThumbprintAlgorithm
	);

#define UNPROTECTED_FLAG (1 << 2)

//exported since Windows 8.0
typedef
__drv_maxIRQL(APC_LEVEL)
__checkReturn
NTSTATUS(NTAPI* PNtSetCachedSigningLevel)(
	__in ULONG Flags,
	__in SE_SIGNING_LEVEL InputSigningLevel,
	__in_ecount(SourceFileCount) PHANDLE SourceFiles,
	__in ULONG SourceFileCount,
	__in HANDLE TargetFile
	);

//
// ZwQueryInformationProcess needs dynamic linking
//
typedef NTSTATUS(NTAPI* PZwQueryInformationProcess)(
	_In_      HANDLE           ProcessHandle,
	_In_      PROCESSINFOCLASS ProcessInformationClass,
	_Out_     PVOID            ProcessInformation,
	_In_      ULONG            ProcessInformationLength,
	_Out_opt_ PULONG           ReturnLength
	);

//
// ZwQuerySystemInformation needs dynamic linking
//
typedef NTSTATUS(NTAPI* PZwQuerySystemInformation)(
	ULONG  SystemInformationClass,
	PVOID  SystemInformation,
	ULONG  SystemInformationLength,
	PULONG ReturnLength
	);

//
// CmCallbackGetKeyObjectIDEx is Win8+ routine
//
typedef NTSTATUS(NTAPI* PCmCallbackGetKeyObjectIDEx)(
	_In_ PLARGE_INTEGER Cookie,
	_In_ PVOID Object,
	_Out_opt_ PULONG_PTR ObjectID,
	_Outptr_opt_ PCUNICODE_STRING* ObjectName,
	_In_ ULONG Flags
	);

//
// CmCallbackReleaseKeyObjectIDEx is Win8+ routine
//
typedef VOID(NTAPI* PCmCallbackReleaseKeyObjectIDEx)(
	_In_ PCUNICODE_STRING ObjectName
	);

// 优先建议使用这个 VISTA SP1+
typedef NTSTATUS(NTAPI* PfnPsSetCreateProcessNotifyRoutineEx)(
	PCREATE_PROCESS_NOTIFY_ROUTINE_EX NotifyRoutine,
	BOOLEAN                           Remove
	);



#if (NTDDI_VERSION >= NTDDI_WIN10_RS2)
// WINDOWS 10 1703+
typedef NTSTATUS(NTAPI* PfnPsSetCreateProcessNotifyRoutineEx2)(
	PSCREATEPROCESSNOTIFYTYPE NotifyType,
	PVOID                     NotifyInformation,
	BOOLEAN                   Remove
	);
#endif

typedef NTSTATUS(NTAPI* PfnZwTerminateProcess)(
	IN OPTIONAL		HANDLE   ProcessHandle,
	IN				NTSTATUS ExitStatus
	);

#ifndef ZWTERMINATEPROCESS
#define ZWTERMINATEPROCESS				L"ZwTerminateProcess"
#endif


typedef enum  _VolumeControlFlag
{
	/// <summary>
	/// Get all the attached volumes' information.
	/// </summary>
	GET_ATTACHED_VOLUME_INFO = 0x00000001,
	/// <summary>
	/// Get a notification when the filter driver attached to a volume.
	/// </summary>
	VOLUME_ATTACHED_NOTIFICATION = 0x00000002,
	/// <summary>
	/// Get a notification when the filter driver detached from a volume.
	/// </summary>
	VOLUME_DETACHED_NOTIFICATION = 0x00000004,
	/// <summary>
	///Prevent the attched volumes from being formatted or dismounted.
	/// </summary>
	BLOCK_VOLUME_DISMOUNT = 0x00000008,
	/// <summary>
	///Block the read from the USB disk.
	/// </summary>
	BLOCK_USB_READ = 0x00000010,
	/// <summary>
	///Block the write to the USB disk
	/// </summary>
	BLOCK_USB_WRITE = 0x00000020,


}VolumeControlFlag;

struct  GlobalData
{
	GlobalData();
	~GlobalData();

	PDRIVER_OBJECT							pDriverObject	= nullptr;
	PDEVICE_OBJECT							pDeviceObject	= nullptr;
	PFLT_FILTER								pFileFilter		= nullptr;

	NtFunction<PZwQueryInformationProcess> fnZwQueryInformationProcess;
	NtFunction<PZwQuerySystemInformation> fnZwQuerySystemInformation;
	NtFunction<PCmCallbackGetKeyObjectIDEx> fnCmCallbackGetKeyObjectIDEx;
	NtFunction<PCmCallbackReleaseKeyObjectIDEx> fnCmCallbackReleaseKeyObjectIDEx;

	// Notify
	BOOLEAN									bNoptifyIntialized {FALSE};


	//
	// process Notify
	//
	NtFunction<PfnPsSetCreateProcessNotifyRoutineEx> pfnPsSetCreateProcessNotifyRoutineEx;
#if (NTDDI_VERSION >= NTDDI_WIN10_RS2)
	NtFunction<PfnPsSetCreateProcessNotifyRoutineEx> pfnPsSetCreateProcessNotifyRoutineEx2;
#endif
	NPAGED_LOOKASIDE_LIST					ProcessCtxNPList;
	LIST_ENTRY								ProcessCtxList;
	//kstd::fast_mutex						ProcessCtxFastMutex;
	kstd::spinlock_mutex					ProcessCtxSpinLock;


	// APC Injector
	UNICODE_STRING InjectDllx64{};
	UNICODE_STRING InjectDllx86{};

	//
	// Signing verification API
	//
	NtFunction<PPsIsProtectedProcess>					PsIsProtectedProcess;
	NtFunction<PPsIsProtectedProcessLight>				PsIsProtectedProcessLight;
	NtFunction<PPsGetProcessSignatureLevel>				PsGetProcessSignatureLevel;
	NtFunction<PSeGetCachedSigningLevel>				SeGetCachedSigningLevel;
	NtFunction<PNtSetCachedSigningLevel>				NtSetCachedSigningLevel;
	NtFunction<PPsGetProcessWow64Process>				PsGetProcessWow64Process;
	NtFunction<PPsWrapApcWow64Thread>					PsWrapApcWow64Thread;

	
	NtFunction<PfnZwTerminateProcess>					ZwTerminateProcess;


	volatile VolumeControlFlag				volumeControlFlag;
};