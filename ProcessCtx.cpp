#include "ProcessCtx.hpp"
#include "Imports.hpp"
#include "Utils.hpp"
#include "Log.hpp"
#include "CRules.hpp"
#include "Locks.hpp"
#include "Lazy.hpp"

extern LazyInstance<GlobalData> g_pGlobalData;

VOID ProcessCtx::Initialization()
{
	ExInitializeNPagedLookasideList(&g_pGlobalData->ProcessCtxNPList,
		nullptr,
		nullptr,
		0,
		ProcessContextSize,
		ProcessContextTag,
		0);

	InitializeListHead(&g_pGlobalData->ProcessCtxList);
	//ExInitializeFastMutex(&g_pGlobalData->ProcessCtxFastMutex);
}



VOID
ProcessCtx::AddProcessContext(
	IN CONST			PEPROCESS	Process,
	IN CONST			HANDLE		Pid,
	IN OUT OPTIONAL		PPS_CREATE_NOTIFY_INFO CreateInfo)
{
	//ExAcquireFastMutex(&g_pGlobalData->ProcessCtxFastMutex);
	kstd::UniqueLock<kstd::fast_mutex> _lock(g_pGlobalData->ProcessCtxFastMutex);
	ProcessContext* pProcessCtx = reinterpret_cast<ProcessContext*>(ExAllocateFromNPagedLookasideList(&g_pGlobalData->ProcessCtxNPList));
	if (!pProcessCtx)
	{
		LOGERROR(STATUS_INSUFFICIENT_RESOURCES, "ExAllocateFromNPagedLookasideList");
		//ExReleaseFastMutex(&g_pGlobalData->ProcessCtxFastMutex);
		return;
	}
	RtlZeroMemory(pProcessCtx, ProcessContextSize);

	pProcessCtx->Pid = Pid;
	pProcessCtx->bProtected = IsProtectedProcess(Process);

	if (g_pGlobalData->PsGetProcessWow64Process)
	{
		pProcessCtx->bIsWow64 = (g_pGlobalData->PsGetProcessWow64Process(Process) != nullptr);
	}

	do
	{
		UNICODE_STRING ustrPrefix{};
		RtlInitUnicodeString(&ustrPrefix, L"\\??\\");
		if (RtlPrefixUnicodeString(&ustrPrefix, CreateInfo->ImageFileName, TRUE))
		{
			// process image file name
			pProcessCtx->ProcessPath.Buffer = reinterpret_cast<PWCH>(ExAllocatePoolWithTag(NonPagedPoolNx, CreateInfo->ImageFileName->MaximumLength + sizeof(UNICODE_STRING), ProcessContextTag));
			if (pProcessCtx->ProcessPath.Buffer)
			{
				RtlZeroMemory(pProcessCtx->ProcessPath.Buffer, CreateInfo->ImageFileName->MaximumLength + sizeof(UNICODE_STRING));
				pProcessCtx->ProcessPath.Length = CreateInfo->ImageFileName->Length - sizeof(L"\\??");
				pProcessCtx->ProcessPath.MaximumLength = CreateInfo->ImageFileName->MaximumLength;
				//RtlCopyUnicodeString(&pProcessCtx->ProcessPath, CreateInfo->ImageFileName);
				RtlCopyMemory(pProcessCtx->ProcessPath.Buffer, 
					reinterpret_cast<PUCHAR>(CreateInfo->ImageFileName->Buffer) + sizeof(L"\\??"),
					CreateInfo->ImageFileName->Length - sizeof(L"\\??"));

				// check trust process
				pProcessCtx->bTrusted = CRULES_FIND_TRUST_PROCESS(pProcessCtx->ProcessPath.Buffer);
				
				// check protect process
				pProcessCtx->bProtected = CRULES_FIND_PROTECT_PROCESS(pProcessCtx->ProcessPath.Buffer);
			}
			else
			{
				LOGERROR(STATUS_INSUFFICIENT_RESOURCES, "[ProcessCtx ERROR]ProcessCtx ProcessPath buffer alloc failed\r\n");
				break;
			}
		}


		// process commandline
		pProcessCtx->ProcessCmdLine.Buffer = reinterpret_cast<PWCH>(ExAllocatePoolWithTag(NonPagedPoolNx, CreateInfo->CommandLine->MaximumLength + sizeof(UNICODE_STRING), ProcessContextTag));
		if (pProcessCtx->ProcessCmdLine.Buffer)
		{
			RtlZeroMemory(pProcessCtx->ProcessCmdLine.Buffer, CreateInfo->CommandLine->MaximumLength + sizeof(UNICODE_STRING));
			pProcessCtx->ProcessCmdLine.Length = 0;
			pProcessCtx->ProcessCmdLine.MaximumLength = CreateInfo->CommandLine->MaximumLength;
			RtlCopyUnicodeString(&pProcessCtx->ProcessCmdLine, CreateInfo->CommandLine);
		}
		else
		{
			LOGERROR(STATUS_INSUFFICIENT_RESOURCES, "[ProcessCtx ERROR]ProcessCtx cmdline buffer alloc failed\r\n");
			break;
		}

		InsertHeadList(&g_pGlobalData->ProcessCtxList, &pProcessCtx->ListHeader);

		//ExReleaseFastMutex(&g_pGlobalData->ProcessCtxFastMutex);

		return;
	} while (FALSE);

	//ExReleaseFastMutex(&g_pGlobalData->ProcessCtxFastMutex);
	// failed 
	if (pProcessCtx->ProcessPath.Buffer)
	{
		ExFreePoolWithTag(pProcessCtx->ProcessPath.Buffer, ProcessContextTag);
		pProcessCtx->ProcessPath.Buffer = nullptr;
	}


	ExFreeToNPagedLookasideList(&g_pGlobalData->ProcessCtxNPList, pProcessCtx);

}


VOID
ProcessCtx::DeleteProcessCtxByPid(IN CONST HANDLE ProcessId)
{
	//ExAcquireFastMutex(&g_pGlobalData->ProcessCtxFastMutex);
	kstd::UniqueLock<kstd::fast_mutex> _lock(g_pGlobalData->ProcessCtxFastMutex);
	if (!ProcessId || IsListEmpty(&g_pGlobalData->ProcessCtxList))
	{
		//ExReleaseFastMutex(&g_pGlobalData->ProcessCtxFastMutex);
		return;
	}

	PLIST_ENTRY pEntry = g_pGlobalData->ProcessCtxList.Flink;

	while (pEntry != &g_pGlobalData->ProcessCtxList && pEntry)
	{
		ProcessContext* pNode = CONTAINING_RECORD(pEntry, ProcessContext, ListHeader);
		if (pNode)
		{
			if (ProcessId == pNode->Pid)
			{
				if (pNode->ProcessPath.Buffer)
				{
					ExFreePoolWithTag(pNode->ProcessPath.Buffer, ProcessContextTag);
					pNode->ProcessPath.Buffer = nullptr;
				}

				if (pNode->ProcessCmdLine.Buffer)
				{
					ExFreePoolWithTag(pNode->ProcessCmdLine.Buffer, ProcessContextTag);
					pNode->ProcessCmdLine.Buffer = nullptr;
				}

				RemoveEntryList(&pNode->ListHeader);				

				ExFreeToNPagedLookasideList(&g_pGlobalData->ProcessCtxNPList, pNode);

				break;
			}
		}
		if (pEntry)
		{
			pEntry = pEntry->Flink;
		}
	}
	//ExReleaseFastMutex(&g_pGlobalData->ProcessCtxFastMutex);
}

ProcessContext*
ProcessCtx::FindProcessCtxByPid(IN CONST HANDLE Pid)
{
	//ExAcquireFastMutex(&g_pGlobalData->ProcessCtxFastMutex);
	kstd::UniqueLock<kstd::fast_mutex> _lock(g_pGlobalData->ProcessCtxFastMutex);
	if (!Pid || IsListEmpty(&g_pGlobalData->ProcessCtxList))
	{
		//ExReleaseFastMutex(&g_pGlobalData->ProcessCtxFastMutex);
		return nullptr;
	}

	ProcessContext* pNode{ nullptr };
	PLIST_ENTRY			pEntry = g_pGlobalData->ProcessCtxList.Flink;

	while (pEntry != &g_pGlobalData->ProcessCtxList && pEntry)
	{
		pNode = CONTAINING_RECORD(pEntry, ProcessContext, ListHeader);
		if (pNode && (Pid == pNode->Pid))
		{
			//ExReleaseFastMutex(&g_pGlobalData->ProcessCtxFastMutex);
			return pNode;
		}

		pEntry = pEntry->Flink;
	}

	//ExReleaseFastMutex(&g_pGlobalData->ProcessCtxFastMutex);

	return pNode;
}


VOID
ProcessCtx::CleanupProcessCtxList()
{
	//ExAcquireFastMutex(&g_pGlobalData->ProcessCtxFastMutex);
	kstd::UniqueLock<kstd::fast_mutex> _lock(g_pGlobalData->ProcessCtxFastMutex);
	while (!IsListEmpty(&g_pGlobalData->ProcessCtxList))
	{
		PLIST_ENTRY pEntry = g_pGlobalData->ProcessCtxList.Flink;
		ProcessContext* pNode = CONTAINING_RECORD(pEntry, ProcessContext, ListHeader);
		if (pNode)
		{

			if (pNode->ProcessPath.Buffer)
			{
				ExFreePoolWithTag(pNode->ProcessPath.Buffer, ProcessContextTag);
				pNode->ProcessPath.Buffer = nullptr;
			}

			if (pNode->ProcessCmdLine.Buffer)
			{
				ExFreePoolWithTag(pNode->ProcessCmdLine.Buffer, ProcessContextTag);
				pNode->ProcessCmdLine.Buffer = nullptr;
			}

			RemoveEntryList(&pNode->ListHeader);		

			ExFreeToNPagedLookasideList(&g_pGlobalData->ProcessCtxNPList, pNode);
		}
	}

	//ExReleaseFastMutex(&g_pGlobalData->ProcessCtxFastMutex);
}