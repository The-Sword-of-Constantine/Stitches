#include "RegistryProtector.hpp"
#include "CRules.hpp"
#include "Imports.hpp"
#include "Utils.hpp"
#include "Lazy.hpp"

extern LazyInstance<GlobalData> g_pGlobalData;


/*
* "\REGISTRY\USER\S-1-5-21-824517415-2516791506-2384372594-1000\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
*/
static 
UNICODE_STRING 
g_AutoRunKeys[] = {
	RTL_CONSTANT_STRING(
		L"\\REGISTRY\\USER\\S*\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUN"),
	RTL_CONSTANT_STRING(
		L"\\REGISTRY\\USER\\S*\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUN\\*"),
	RTL_CONSTANT_STRING(
		L"\\REGISTRY\\USER\\S*\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUNONCE"),
	RTL_CONSTANT_STRING(
		L"\\REGISTRY\\USER\\S*\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUNONCE\\*")
};

constexpr ULONG AUTORUN_COUNT = sizeof(g_AutoRunKeys) / sizeof(g_AutoRunKeys[0]);

static
BOOLEAN
IsInAutoRunKeys(PUNICODE_STRING RegPath)
{
	for (auto i = 0; i != AUTORUN_COUNT; ++i)
	{
		if (FsRtlIsNameInExpression(&g_AutoRunKeys[i], RegPath, TRUE, NULL))
		{
			return TRUE;
		}
	}

	return FALSE;
}

static
BOOLEAN
MonitorAutorunOperation(
	IN CONST HANDLE Pid,
	IN CONST PVOID RegObject)
{
	BOOLEAN bIsAllowRun{ FALSE };
	BOOLEAN bResult{ FALSE };

	BOOLEAN bTrustProcess{ FALSE };
	WCHAR wszRegistryPath[MAX_REGISTRYPATH]{ 0 };
	bResult = KGetRegistryPath(RegObject, wszRegistryPath, MAX_REGISTRYPATH * sizeof(WCHAR));
	if (!bResult)
	{
		bIsAllowRun = FALSE;
		return bIsAllowRun;
	}
	UNICODE_STRING ustrRgPath{};
	RtlInitUnicodeString(&ustrRgPath, wszRegistryPath);

	bResult = IsInAutoRunKeys(&ustrRgPath);

	// trust process
	WCHAR wszProcessPath[MAX_PATH]{ 0 };
	auto status = GetProcessImageByPid(Pid, wszProcessPath);
	if (!NT_SUCCESS(status) && !bResult)
	{
		bIsAllowRun = TRUE;
		return bIsAllowRun;
	}
	bTrustProcess = CRULES_FIND_TRUST_PROCESS(wszProcessPath);
	if (bTrustProcess)
	{
		bIsAllowRun = TRUE;
	}

	return bIsAllowRun;
}


static 
BOOLEAN
AllowedRegistryOperation(
	IN CONST HANDLE Pid, 
	IN CONST PVOID RegObject)
{
	BOOLEAN bAllow = TRUE;

	BOOLEAN bTrustProcess	 = FALSE;
	BOOLEAN bProtectRegistry = FALSE;
	
	WCHAR wszRegistryPath[MAX_REGISTRYPATH]{ 0 };
	bProtectRegistry = KGetRegistryPath(RegObject, wszRegistryPath, MAX_REGISTRYPATH * sizeof(WCHAR));
	if (!bProtectRegistry)
	{
		bAllow = TRUE;
		return bAllow;
	}
	bProtectRegistry = CRULES_FIND_PROTECT_REGISTRY(wszRegistryPath);

	// trust process
	WCHAR wszProcessPath[MAX_PATH]{ 0 };
	auto status = GetProcessImageByPid(Pid, wszProcessPath);
	if (!NT_SUCCESS(status) &&
		!bProtectRegistry)
	{
		bAllow = TRUE;
		return bAllow;
	}
	bTrustProcess = CRULES_FIND_TRUST_PROCESS(wszProcessPath);

	if (bProtectRegistry && 
		!bTrustProcess)
	{
		bAllow = FALSE;
	}

	return bAllow;
}

RegistryProtectorEx::RegistryProtectorEx()
{
	m_Cookie.QuadPart = 0;
	m_bInitSuccess = FALSE;
}

RegistryProtectorEx::~RegistryProtectorEx()
{
	if (!m_bInitSuccess)
	{
		return;
	}

	NTSTATUS status{ STATUS_SUCCESS };
	status = CmUnRegisterCallback(m_Cookie);
	if (NT_SUCCESS(status))
	{
		m_bInitSuccess = FALSE;
	}
}

NTSTATUS RegistryProtectorEx::Init()
{
	NTSTATUS status{ STATUS_SUCCESS };

	if (TRUE == m_bInitSuccess)
	{
		return status;
	}

	UNICODE_STRING usCallbackAltitude = {};
	RtlInitUnicodeString(&usCallbackAltitude, L"38325");

	status = CmRegisterCallbackEx(NotifyOnRegistryActions,
		&usCallbackAltitude,
		g_pGlobalData->pDriverObject,
		nullptr,
		&m_Cookie,
		nullptr);
	if (NT_SUCCESS(status))
	{
		m_bInitSuccess = TRUE;
	}
	

	return status;
}

NTSTATUS 
RegistryProtectorEx::NotifyOnRegistryActions(
	_In_ PVOID CallbackContext, 
	_In_opt_ PVOID Argument1,
	_In_opt_ PVOID Argument2)
{
	UNREFERENCED_PARAMETER(CallbackContext);
	UNREFERENCED_PARAMETER(Argument1);
	UNREFERENCED_PARAMETER(Argument2);
	NTSTATUS status{ STATUS_SUCCESS };

	if (KeGetCurrentIrql() > PASSIVE_LEVEL)
	{
		return status;
	}

	auto eNotifyClass = static_cast<REG_NOTIFY_CLASS>((ULONG_PTR)Argument1);

	typedef struct _BASE_REG_KEY_INFO
	{
		PVOID		pObject;
		PVOID		reserved;
		// 
	} BASE_REG_KEY_INFO, * PBASE_REG_KEY_INFO;

	HANDLE	hPid			= PsGetCurrentProcessId();
	BOOLEAN bAllowed		= FALSE;
	BOOLEAN bAllowAutoRun	= FALSE;

	switch (eNotifyClass)
	{
	case RegNtPreCreateKey:
	case RegNtPreCreateKeyEx:
	{
		PREG_CREATE_KEY_INFORMATION_V1 pkeyInfo = reinterpret_cast<PREG_CREATE_KEY_INFORMATION_V1>(Argument2);
		if (!pkeyInfo)
		{
			status = STATUS_SUCCESS;
			break;
		}
		bAllowAutoRun = MonitorAutorunOperation(hPid, pkeyInfo->RootObject);
		if (!bAllowAutoRun)
		{
			status = STATUS_ACCESS_DENIED;
			break;
		}

	}
	break;
		 
		//case RegNtPreOpenKey:
		//case RegNtPreOpenKeyEx:
		//
		
	case RegNtPreSetValueKey:
	{
		PBASE_REG_KEY_INFO pkeyInfo = reinterpret_cast<PBASE_REG_KEY_INFO>(Argument2);
		if (!pkeyInfo)
		{
			status = STATUS_SUCCESS;
			break;
		}

		bAllowed = AllowedRegistryOperation(hPid, pkeyInfo->pObject);
		if (!bAllowed)
		{
			status = STATUS_ACCESS_DENIED;
			break;
		}

		bAllowAutoRun = MonitorAutorunOperation(hPid, pkeyInfo->pObject);
		if (!bAllowAutoRun)
		{
			status = STATUS_ACCESS_DENIED;
			break;
		}
	}
	break;

	case RegNtPreDeleteKey:
	case RegNtPreRenameKey:
	case RegNtPreDeleteValueKey:
	{
		PBASE_REG_KEY_INFO pkeyInfo = reinterpret_cast<PBASE_REG_KEY_INFO>(Argument2);
		if (!pkeyInfo)
		{
			status = STATUS_SUCCESS;
			break;
		}

		bAllowed = AllowedRegistryOperation(hPid, pkeyInfo->pObject);
		if (!bAllowed)
		{
			status = STATUS_ACCESS_DENIED;
			break;
		}

	}
	break;

	default:
		break;
	}

	return status;
}
