#include "DeviceControl.hpp"
#include "Common.h"
#include "Imports.hpp"
#include "CRules.hpp"
#include "Log.hpp"
#include "Lazy.hpp"

extern LazyInstance<GlobalData> g_pGlobalData;

#ifndef IS_MY_CONTROL_DEVICE_OBJECT
#define IS_MY_CONTROL_DEVICE_OBJECT(p) ((p) == g_pGlobalData->pDeviceObject)
#endif

_Function_class_(DRIVER_INITIALIZE)
_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS 
DeviceControl::InitializeIoctlDevice(
	IN CONST PUNICODE_STRING DeviceName,
	IN CONST PUNICODE_STRING SymbolicLinkName)
{
	NTSTATUS status{STATUS_SUCCESS};

	__try
	{
		status = IoCreateDevice(g_pGlobalData->pDriverObject,
								0, 
								DeviceName,
								FILE_DEVICE_KERNELCODE, 
								FILE_DEVICE_SECURE_OPEN,
								FALSE, 
								&g_pGlobalData->pDeviceObject);
		if (NT_SUCCESS(status))
		{
			status = IoCreateSymbolicLink(SymbolicLinkName, DeviceName);
			if (NT_SUCCESS(status))
			{
				m_bSymbolicLinkCreated = TRUE;
			}
		}
	}
	__finally
	{
		if (!m_bSymbolicLinkCreated)
		{
			FinalizeIoctlDevice(DeviceName, SymbolicLinkName);
		}
	}



	return status;
}


VOID
DeviceControl::FinalizeIoctlDevice(
	IN CONST PUNICODE_STRING DeviceName,
	IN CONST PUNICODE_STRING SymbolicLinkName)
{
	UNREFERENCED_PARAMETER(DeviceName);
	UNREFERENCED_PARAMETER(SymbolicLinkName);

	if (!m_bSymbolicLinkCreated)
	{
		return;
	}

	IoDeleteSymbolicLink(SymbolicLinkName);

	if (g_pGlobalData->pDeviceObject)
	{
		IoDeleteDevice(g_pGlobalData->pDeviceObject);
	}

}


NTSTATUS
DriverDispatch(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp)
{
	if (!IS_MY_CONTROL_DEVICE_OBJECT(DeviceObject))
	{
		Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
		Irp->IoStatus.Information = 0;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return STATUS_SUCCESS;
	}

	NTSTATUS			status				{ STATUS_SUCCESS };
	PIO_STACK_LOCATION	pIrpStack			{ nullptr };
	PVOID				pIoBuffer			{ nullptr };
	ULONG				nInputbufferLength  { 0 };
	ULONG				nOutputbufferLength { 0 };


	pIrpStack = IoGetCurrentIrpStackLocation(Irp);

	pIoBuffer = Irp->AssociatedIrp.SystemBuffer;

	nInputbufferLength	= pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
	nOutputbufferLength = pIrpStack->Parameters.DeviceIoControl.OutputBufferLength;

	// default setting
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	// 
	switch (pIrpStack->MajorFunction)
	{

	case IRP_MJ_DEVICE_CONTROL:
	{
		auto nIoctlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;
		switch (nIoctlCode)
		{
		case IOCTL_STITCHES_SET_HOOK_DLL_PATH:
		{	
			if (nInputbufferLength >= sizeof(HOOK_DLL_PATH) && 
				pIoBuffer)
			{
				PHOOK_DLL_PATH pHookDllPath = reinterpret_cast<PHOOK_DLL_PATH>(pIoBuffer);

				auto nAllocDllLength = MAX_PATH * 2 + sizeof(UNICODE_STRING);

				g_pGlobalData->InjectDllx64.Buffer = reinterpret_cast<PWCH>(ExAllocatePoolWithTag(NonPagedPoolNx, nAllocDllLength, GLOBALDATA_TAG));
				if (g_pGlobalData->InjectDllx64.Buffer)
				{
					RtlZeroMemory(g_pGlobalData->InjectDllx64.Buffer, nAllocDllLength);
					g_pGlobalData->InjectDllx64.Length = 
					g_pGlobalData->InjectDllx64.MaximumLength = static_cast<USHORT>((wcslen(pHookDllPath->x64Dll) + 1) * sizeof(WCHAR));
					
					__try
					{
						RtlCopyMemory(g_pGlobalData->InjectDllx64.Buffer,
									  pHookDllPath->x64Dll, 
									  wcslen(pHookDllPath->x64Dll) * sizeof(WCHAR));
					}
					__except(EXCEPTION_EXECUTE_HANDLER)
					{
						Irp->IoStatus.Status = STATUS_ACCESS_VIOLATION;
						break;
					}
				}
				else
				{
					LOGERROR(STATUS_NO_MEMORY, "g_pGlobalData->InjectDllx64.Buffer alloc faid\r\n");
				}

				g_pGlobalData->InjectDllx86.Buffer = reinterpret_cast<PWCH>(ExAllocatePoolWithTag(NonPagedPoolNx, nAllocDllLength, GLOBALDATA_TAG));
				if (g_pGlobalData->InjectDllx86.Buffer)
				{
					RtlZeroMemory(g_pGlobalData->InjectDllx86.Buffer, nAllocDllLength);
					g_pGlobalData->InjectDllx86.Length =
						g_pGlobalData->InjectDllx86.MaximumLength = static_cast<USHORT>((wcslen(pHookDllPath->x86Dll) + 1) * sizeof(WCHAR));
					__try
					{
						RtlCopyMemory(g_pGlobalData->InjectDllx86.Buffer, 
									  pHookDllPath->x86Dll, 
									  wcslen(pHookDllPath->x86Dll) * sizeof(WCHAR));
					}
					__except (EXCEPTION_EXECUTE_HANDLER)
					{
						Irp->IoStatus.Status = STATUS_ACCESS_VIOLATION;
						break;
					}
				}
				else
				{
					LOGERROR(STATUS_NO_MEMORY, "g_pGlobalData->InjectDllx86.Buffer alloc faid\r\n");
				}

				Irp->IoStatus.Status = STATUS_SUCCESS;
			}
			else
			{
				Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
			}
		}
		break;


		case IOCTL_STITCHES_ADD_TRUST_PROCESS:
		{
			WCHAR wszTrustProcess[MAX_PATH]{ 0 };
			if (nInputbufferLength < sizeof(wszTrustProcess) && 
				pIoBuffer)
			{
				__try
				{
					RtlCopyMemory(wszTrustProcess, pIoBuffer, nInputbufferLength);
					Irp->IoStatus.Status = CRULES_ADD_TRUST_PROCESS(wszTrustProcess);
				}			
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					Irp->IoStatus.Status = STATUS_ACCESS_VIOLATION;
				}
			}
			else
			{
				Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
			}	
		}
		break;

		case IOCTL_STITCHES_DEL_TRUST_PROCESS:
		{
			WCHAR wszTrustProcess[MAX_PATH]{ 0 };
			if (nInputbufferLength < sizeof(wszTrustProcess) &&
				pIoBuffer)
			{
				__try
				{
					RtlCopyMemory(wszTrustProcess, pIoBuffer, nInputbufferLength);
					Irp->IoStatus.Status = CRULES_DEL_TRUST_PROCESS(wszTrustProcess);
				}	
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					Irp->IoStatus.Status = STATUS_ACCESS_VIOLATION;
				}
			}
			else
			{
				Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
			}
		}
		break;

		case IOCTL_STITCHES_ADD_PROTECT_PROCESS:
		{
			WCHAR wszTrustProcess[MAX_PATH]{ 0 };
			if (nInputbufferLength < sizeof(wszTrustProcess) &&
				pIoBuffer)
			{
				__try
				{
					RtlCopyMemory(wszTrustProcess, pIoBuffer, nInputbufferLength);
					Irp->IoStatus.Status = CRULES_ADD_PROTECT_PROCESS(wszTrustProcess);
				}	
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					Irp->IoStatus.Status = STATUS_ACCESS_VIOLATION;
				}
			}
			else
			{
				Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
			}
		}
		break;

		case IOCTL_STITCHES_DEL_PROTECT_PROCESS:
		{
			WCHAR wszTrustProcess[MAX_PATH]{ 0 };
			if (nInputbufferLength < sizeof(wszTrustProcess) &&
				pIoBuffer)
			{
				__try
				{
					RtlCopyMemory(wszTrustProcess, pIoBuffer, nInputbufferLength);
					Irp->IoStatus.Status = CRULES_DEL_PROTECT_PROCESS(wszTrustProcess);
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					Irp->IoStatus.Status = STATUS_ACCESS_VIOLATION;
				}
			}
			else
			{
				Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
			}
		}
		break;

		case IOCTL_STITCHES_ADD_PROTECT_REGISTRY:
		{
			WCHAR wszProtectRegistry[MAX_REGISTRYPATH]{ 0 };
			if (nInputbufferLength < sizeof(wszProtectRegistry) &&
				pIoBuffer)
			{
				__try
				{
					RtlCopyMemory(wszProtectRegistry, pIoBuffer, nInputbufferLength);
					Irp->IoStatus.Status = CRULES_ADD_PROTECT_REGISTRY(wszProtectRegistry);
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					Irp->IoStatus.Status = STATUS_ACCESS_VIOLATION;
				}
			}
			else
			{
				Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
			}
		}
		break;

		case IOCTL_STITCHES_DEL_PROTECT_REGISTRY:
		{
			WCHAR wszProtectRegistry[MAX_REGISTRYPATH]{ 0 };
			if (nInputbufferLength < sizeof(wszProtectRegistry) &&
				pIoBuffer)
			{
				__try
				{
					RtlCopyMemory(wszProtectRegistry, pIoBuffer, nInputbufferLength);
					Irp->IoStatus.Status = CRULES_DEL_PROTECT_REGISTRY(wszProtectRegistry);
				}
				__except(EXCEPTION_EXECUTE_HANDLER)
				{
					Irp->IoStatus.Status = STATUS_ACCESS_VIOLATION;
				}

			}
			else
			{
				Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
			}
		}
		break;

		default:
			Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
			break;
		}
	}
	break;
	default:
		break;
	}

	status = Irp->IoStatus.Status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

_Function_class_(DRIVER_INITIALIZE)
_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS 
DeviceControl::InitializeDriverDispatch()
{
	for (size_t i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; ++i)
	{
		g_pGlobalData->pDriverObject->MajorFunction[i] = static_cast<PDRIVER_DISPATCH>(DriverDispatch);
	}

	return STATUS_SUCCESS;
}