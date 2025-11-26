// StitchesApi.cpp : 定义 DLL 的导出函数。
//

#include "pch.h"
#include "framework.h"
#include "StitchesApi.h"
#include "Common.h"
#include "Sync.hpp"


using namespace StitchesApi;

static  AutoHandle	g_hDevice;

// 这是已导出类的构造函数。
CStitchesApi::CStitchesApi()
{
	memcpy(m_wstrServiceName, KERNELDEVICE_DEVICE_NAME, wcslen(KERNELDEVICE_DEVICE_NAME) * sizeof(WCHAR));
}

BOOLEAN
STITCHESAPI_CC 
CStitchesApi::InstallDriver()
{
	std::wstring wstrCurrentSys = std::filesystem::current_path().wstring();
	wstrCurrentSys += L"\\";
	wstrCurrentSys += KERNELDEVICE_DEVICE_NAME;
	wstrCurrentSys += L".sys";

	WCHAR wszSystemPath[MAX_PATH]{ 0 };
	GetSystemDirectoryW(wszSystemPath, MAX_PATH);
	std::wstring wstrSysPath{ wszSystemPath };
	wstrSysPath += L"\\drivers\\";
	wstrSysPath += KERNELDEVICE_DEVICE_NAME;
	wstrSysPath += L".sys";

	CopyFileW(wstrCurrentSys.c_str(), wstrSysPath.c_str(), FALSE);

	BOOLEAN bResult{ FALSE };

	std::wstring wstrInstance{ m_wstrServiceName };
	std::wstring wstrAltitude{ L"388450" };

	bResult = InstallMinifilterDriver(wstrSysPath, wstrInstance, wstrAltitude);
	if (bResult)
	{
		auto sc = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
		if (!sc)
		{
			return FALSE;
		}

		auto hService = OpenServiceW(sc, m_wstrServiceName, SERVICE_ALL_ACCESS);
		if (hService)
		{
			bResult = StartServiceW(hService, 0, nullptr) 
				|| GetLastError() == ERROR_SERVICE_ALREADY_RUNNING
				|| GetLastError() == ERROR_SERVICE_DISABLED;
		}
		else
		{
			bResult = FALSE;
		}

		if (hService)
		{
			CloseServiceHandle(hService);
			hService = nullptr;
		}

		if (sc)
		{
			CloseServiceHandle(sc);
			sc = nullptr;
		}
	}


	return bResult;
}

BOOLEAN
STITCHESAPI_CC 
CStitchesApi::UninstallDriver()
{
	BOOLEAN bResult{ FALSE };

	g_hDevice.Close();
	auto sc = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
	if (!sc)
	{
		return FALSE;
	}

	auto hService = OpenServiceW(sc, m_wstrServiceName, DELETE);
	if (hService)
	{
		bResult = DeleteService(hService);
		CloseServiceHandle(hService);
		hService = nullptr;
	}
	CloseServiceHandle(sc);
	sc = nullptr;


	return bResult;
}

BOOLEAN
STITCHESAPI_CC 
CStitchesApi::InstallMinifilterDriver(
	CONST std::wstring& DriverPath,
	CONST std::wstring& InstanceName,
	CONST std::wstring& Altitude, 
	BOOLEAN AutoStart /*= TRUE*/)
{
	BOOLEAN bResult{ FALSE };

	SC_HANDLE sc = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
	if (!sc)
	{
		return FALSE;
	}

	SC_HANDLE hService{ nullptr };

	do 
	{
		hService = CreateServiceW(sc,
								  m_wstrServiceName,
								  m_wstrServiceName,
								  SERVICE_ALL_ACCESS,
								  SERVICE_FILE_SYSTEM_DRIVER,
								  AutoStart ? SERVICE_AUTO_START : SERVICE_DEMAND_START,
								  SERVICE_ERROR_NORMAL,
								  DriverPath.c_str(),
								  nullptr, 
								  nullptr,
								  nullptr, 
								  nullptr, 
								  nullptr);
		if (ERROR_SERVICE_EXISTS == GetLastError())
		{
			bResult = TRUE;
		}
		if (!hService)
		{
			break;
		}
		if (hService)
		{
			bResult = TRUE;
		}
		if (bResult)
		{
			std::wstring subKeyPath = std::format(L"SYSTEM\\CurrentControlSet\\Services\\{}\\Instances", m_wstrServiceName);

			bResult = FALSE;

			HKEY hInstanceKey{ nullptr };
			HKEY hAltitudeKey{ nullptr };

			if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, 
				subKeyPath.c_str(),
				0,
				nullptr,
				REG_OPTION_NON_VOLATILE,
				KEY_WRITE,
				nullptr, 
				&hInstanceKey,
				nullptr) != ERROR_SUCCESS)
			{
				break;
			}

			if (RegSetValueExW(hInstanceKey,
				L"DefaultInstance",
				0,
				REG_SZ,
				reinterpret_cast<const BYTE*>(InstanceName.c_str()),
				(InstanceName.length() + 1)* sizeof(WCHAR)) != ERROR_SUCCESS)
			{
				break;
			}

			if (hInstanceKey)
			{
				RegFlushKey(hInstanceKey);
				RegCloseKey(hInstanceKey);
				hInstanceKey = nullptr;
			}


			std::wstring tmpSubkeyPath = std::format(L"SYSTEM\\CurrentControlSet\\Services\\{}\\Instances\\{}", m_wstrServiceName, InstanceName);
			if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, 
				tmpSubkeyPath.c_str(),
				0, 
				nullptr,
				REG_OPTION_NON_VOLATILE, 
				KEY_WRITE, 
				nullptr,
				&hAltitudeKey, 
				nullptr) != ERROR_SUCCESS)
			{
				break;
			}

			if (RegSetValueEx(hAltitudeKey, 
				L"Altitude", 
				0, 
				REG_SZ, 
				(const BYTE*)Altitude.c_str(), 
				(Altitude.length() + 1) * sizeof(WCHAR)) != ERROR_SUCCESS)
			{
				break;
			}

			DWORD flags = 0;
			if (RegSetValueEx(hAltitudeKey, 
				L"Flags",
				0, 
				REG_DWORD, 
				(const BYTE*)&flags, 
				sizeof(flags)) != ERROR_SUCCESS)
			{
				break;
			}

			if (hAltitudeKey)
			{
				RegFlushKey(hAltitudeKey);
				RegCloseKey(hAltitudeKey);
				hAltitudeKey = nullptr;
			}

			bResult = TRUE;
		}

	} while (FALSE);



	if (hService)
	{
		CloseServiceHandle(hService);
		hService = nullptr;
	}

	if (sc)
	{
		CloseServiceHandle(sc);
		sc = nullptr;
	}

	return bResult;
}

BOOLEAN
STITCHESAPI_CC 
CStitchesApi::OpenDevice()
{
	HANDLE hDevice{ nullptr };
	hDevice = CreateFileW(KERNELDEVICE_DEVICE_FILE,
						  GENERIC_READ | GENERIC_WRITE,
						  0,
						  nullptr,
						  OPEN_EXISTING,
						  FILE_FLAG_OVERLAPPED,
						  nullptr);

	if (INVALID_HANDLE_VALUE == hDevice)
	{
		return FALSE;
	}
	
	g_hDevice.Attach(hDevice);
	return TRUE;
}

BOOLEAN
STITCHESAPI_CC 
CStitchesApi::AddTrustProcess(CONST std::wstring& ProcessPath)
{
	DWORD	dwBytesReturned{ 0 };
	if (INVALID_HANDLE_VALUE == g_hDevice)
	{
		return FALSE;
	}

	if (!DeviceIoControl(g_hDevice,
		IOCTL_STITCHES_ADD_TRUST_PROCESS,
		reinterpret_cast<LPVOID>(const_cast<PWCHAR>(ProcessPath.c_str())),
		ProcessPath.length() * sizeof(WCHAR),
		nullptr,
		0,
		&dwBytesReturned,
		nullptr))
	{
		return FALSE;
	}


	return TRUE;
}

BOOLEAN 
STITCHESAPI_CC 
CStitchesApi::DelTrustProcess(CONST std::wstring& ProcessPath)
{
	DWORD	dwBytesReturned{ 0 };
	if (INVALID_HANDLE_VALUE == g_hDevice)
	{
		return FALSE;
	}

	if (!DeviceIoControl(g_hDevice,
		IOCTL_STITCHES_DEL_TRUST_PROCESS,
		reinterpret_cast<LPVOID>(const_cast<PWCHAR>(ProcessPath.c_str())),
		ProcessPath.length() * sizeof(WCHAR),
		nullptr,
		0,
		&dwBytesReturned,
		nullptr))
	{
		return FALSE;
	}


	return TRUE;
}

BOOLEAN 
STITCHESAPI_CC 
CStitchesApi::AddProtectProcess(CONST std::wstring& ProcessPath)
{
	DWORD	dwBytesReturned{ 0 };
	if (INVALID_HANDLE_VALUE == g_hDevice)
	{
		return FALSE;
	}

	if (!DeviceIoControl(g_hDevice,
		IOCTL_STITCHES_ADD_PROTECT_PROCESS,
		reinterpret_cast<LPVOID>(const_cast<PWCHAR>(ProcessPath.c_str())),
		ProcessPath.length() * sizeof(WCHAR),
		nullptr,
		0,
		&dwBytesReturned,
		nullptr))
	{
		return FALSE;
	}


	return TRUE;
}

BOOLEAN 
STITCHESAPI_CC 
CStitchesApi::DelProtectProcess(CONST std::wstring& ProcessPath)
{
	DWORD	dwBytesReturned{ 0 };
	if (INVALID_HANDLE_VALUE == g_hDevice)
	{
		return FALSE;
	}

	if (!DeviceIoControl(g_hDevice,
		IOCTL_STITCHES_DEL_PROTECT_PROCESS,
		reinterpret_cast<LPVOID>(const_cast<PWCHAR>(ProcessPath.c_str())),
		ProcessPath.length() * sizeof(WCHAR),
		nullptr,
		0,
		&dwBytesReturned,
		nullptr))
	{
		return FALSE;
	}


	return TRUE;
}

BOOLEAN 
STITCHESAPI_CC 
CStitchesApi::AddProtectFile(CONST std::wstring& ProcessPath)
{
	DWORD	dwBytesReturned{ 0 };
	if (INVALID_HANDLE_VALUE == g_hDevice)
	{
		return FALSE;
	}

	if (!DeviceIoControl(g_hDevice,
		IOCTL_STITCHES_ADD_PROTECT_FILE,
		reinterpret_cast<LPVOID>(const_cast<PWCHAR>(ProcessPath.c_str())),
		ProcessPath.length() * sizeof(WCHAR),
		nullptr,
		0,
		&dwBytesReturned,
		nullptr))
	{
		return FALSE;
	}


	return TRUE;
}

BOOLEAN 
STITCHESAPI_CC 
CStitchesApi::DelProtectFile(CONST std::wstring& ProcessPath)
{
	DWORD	dwBytesReturned{ 0 };
	if (INVALID_HANDLE_VALUE == g_hDevice)
	{
		return FALSE;
	}

	if (!DeviceIoControl(g_hDevice,
		IOCTL_STITCHES_DEL_PROTECT_FILE,
		reinterpret_cast<LPVOID>(const_cast<PWCHAR>(ProcessPath.c_str())),
		ProcessPath.length() * sizeof(WCHAR),
		nullptr,
		0,
		&dwBytesReturned,
		nullptr))
	{
		return FALSE;
	}


	return TRUE;
}

BOOLEAN 
STITCHESAPI_CC 
CStitchesApi::AddProtectRegistry(CONST std::wstring& RegistryPath)
{
	DWORD	dwBytesReturned{ 0 };
	if (INVALID_HANDLE_VALUE == g_hDevice)
	{
		return FALSE;
	}

	if (!DeviceIoControl(g_hDevice,
		IOCTL_STITCHES_ADD_PROTECT_REGISTRY,
		reinterpret_cast<LPVOID>(const_cast<PWCHAR>(RegistryPath.c_str())),
		RegistryPath.length() * sizeof(WCHAR),
		nullptr,
		0,
		&dwBytesReturned,
		nullptr))
	{
		return FALSE;
	}


	return TRUE;
}

BOOLEAN 
STITCHESAPI_CC 
CStitchesApi::DelProtectRegistry(CONST std::wstring& RegistryPath)
{
	DWORD	dwBytesReturned{ 0 };
	if (INVALID_HANDLE_VALUE == g_hDevice)
	{
		return FALSE;
	}

	if (!DeviceIoControl(g_hDevice,
		IOCTL_STITCHES_DEL_PROTECT_REGISTRY,
		reinterpret_cast<LPVOID>(const_cast<PWCHAR>(RegistryPath.c_str())),
		RegistryPath.length() * sizeof(WCHAR),
		nullptr,
		0,
		&dwBytesReturned,
		nullptr))
	{
		return FALSE;
	}


	return TRUE;
}

BOOLEAN
STITCHESAPI_CC
CStitchesApi::SetHookDllPath(
	CONST std::wstring& x64dll,
	CONST std::wstring& x86dll)
{
	DWORD	dwBytesReturned{ 0 };
	if (INVALID_HANDLE_VALUE == g_hDevice)
	{
		return FALSE;
	}

	HOOK_DLL_PATH hookDllPath{};

	memcpy(hookDllPath.x64Dll, x64dll.c_str(), x64dll.length() * sizeof(WCHAR));
	memcpy(hookDllPath.x86Dll, x86dll.c_str(), x86dll.length() * sizeof(WCHAR));

	if (!DeviceIoControl(g_hDevice,
		IOCTL_STITCHES_DEL_PROTECT_FILE,
		reinterpret_cast<LPVOID>(&hookDllPath),
		sizeof(HOOK_DLL_PATH),
		nullptr,
		0,
		&dwBytesReturned,
		nullptr))
	{
		return FALSE;
	}


	return TRUE;
}

BOOLEAN 
STITCHESAPI_CC 
CStitchesApi::AdjustPriviledges()
{
	BOOLEAN bSuccess{ TRUE };

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
	if (hProcess)
	{
		HANDLE hToken{ nullptr };
		do 
		{
			if (OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken))
			{
				TOKEN_PRIVILEGES tokenPrivileges{};
				LUID luid{};

				if (LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luid))
				{
					tokenPrivileges.PrivilegeCount = 1;
					tokenPrivileges.Privileges[0].Luid = luid;
					tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
				}
				else
				{
					bSuccess = FALSE;
					break;
				}

				if (!AdjustTokenPrivileges(hToken,
						FALSE, 
						&tokenPrivileges, 
						sizeof(TOKEN_PRIVILEGES),
						nullptr, 
						nullptr)
					)
				{
					bSuccess = FALSE;
					break;
				}
			}
		} while (FALSE);

		if (hToken)
		{
			CloseHandle(hToken);
		}

		CloseHandle(hProcess);
	}


	return bSuccess;
}


static
UINT
_stdcall
HandleIoFuc(PVOID param)
{
	BOOLEAN bResult{ FALSE };

	auto pSsApi = reinterpret_cast<CStitchesApi*>(param);

	DWORD			dwReadBytes{ 0 };
	ULONG_PTR		uCompletionKey{ 0 };
	LPOVERLAPPED	lpOverlapped{ nullptr };

	IO_MESSAGE*		pIoData{ nullptr };
	EventData*		pEventData{ nullptr };

	while (true)
	{
		bResult = GetQueuedCompletionStatus(pSsApi->GetIocpHandle(), 
											&dwReadBytes, 
											&uCompletionKey, 
											&lpOverlapped, 
											INFINITE);
		if(!bResult)
		{
			break;
		}

		pIoData = CONTAINING_RECORD(lpOverlapped, IO_MESSAGE, OverLapped);
		if (!pIoData)
		{
			break;
		}

		pEventData = reinterpret_cast<EventData*>(pIoData->Data);
		
		{
			// 解析
		}
		
		auto hResult = FilterGetMessage(pSsApi->GetCommunicationPort(),
										&pIoData->FilterMessageHander,
										sizeof(IO_MESSAGE) - sizeof(OVERLAPPED),
										&pIoData->OverLapped);
		if (S_OK != hResult)
		{
			break;
		}
	}


	return 0;
}


BOOLEAN 
STITCHESAPI_CC
CStitchesApi::HandleIoData()
{
	BOOLEAN bResult{ TRUE };

	HRESULT hResult{ 0 };

	do 
	{
		// 创建驱动层与应用层的统信端口
		hResult = FilterConnectCommunicationPort(m_wstrPortName, 0, nullptr, 0, nullptr, &m_hCommunicationPort);
		if (IS_ERROR(hResult))
		{
			break;
		}

		// 创建IO完成端口
		m_hIocp = CreateIoCompletionPort(m_hCommunicationPort, nullptr, 0, m_nThreadPoolSize);
		if (!m_hIocp)
		{
			break;
		}

		// 创建线程解析驱动层向应用层发送的数据
		for (auto i = 0; i != m_nThreadPoolSize; ++i)
		{
		    m_ThreadPoolArray[i] = _beginthreadex(nullptr, 0, HandleIoFuc, this, 0, nullptr);
			if (0 == m_ThreadPoolArray[i])
			{
				break;
			}
		}

		bResult = TRUE;
		return bResult;
	} while (FALSE);

	// failure
	if (!bResult)
	{
		if (m_hIocp)
		{
			CloseHandle(m_hIocp);
			m_hIocp = nullptr;
		}

		if (m_hCommunicationPort)
		{
			CloseHandle(m_hCommunicationPort);
			m_hCommunicationPort = nullptr;
		}
	}

	return bResult;
}
