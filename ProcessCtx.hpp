#pragma once
#include "Singleton.hpp"

struct ProcessContext
{
	LIST_ENTRY		ListHeader;
	HANDLE			Pid;
	UNICODE_STRING	ProcessPath;
	UNICODE_STRING	ProcessCmdLine;
	BOOLEAN			bProtected;
	BOOLEAN			bIsWow64;
	BOOLEAN			bTrusted;
	BOOLEAN			bIsProcessParentPidSpoofed;		// 是否是父进程欺骗
	BOOLEAN			bProcessGhosting;				// 文件被删除验证Process Ghosting
};

constexpr ULONG ProcessContextSize = sizeof(ProcessContext);
constexpr ULONG ProcessContextTag = 'pnCP';

class ProcessCtx : public Singleton<ProcessCtx>
{
public:
	VOID 
	Initialization();

	VOID 
	AddProcessContext(
		IN CONST PEPROCESS Process,
		IN CONST HANDLE Pid, 
		IN OUT OPTIONAL PPS_CREATE_NOTIFY_INFO CreateInfo);

	VOID 
	DeleteProcessCtxByPid(IN CONST HANDLE ProcessId);

	ProcessContext* 
	FindProcessCtxByPid(IN CONST HANDLE Pid);


	VOID 
	CleanupProcessCtxList();
};

#define PROCESS_CTX_INSTANCE()	(ProcessCtx::getInstance())
#define PROCESS_CTX_INIT()		(ProcessCtx::getInstance()->Initialization())
#define PROCESS_CTX_ADD(x,y,z)	(ProcessCtx::getInstance()->AddProcessContext((x), (y), (z)))
#define PROCESS_CTX_DEL(x)		(ProcessCtx::getInstance()->DeleteProcessCtxByPid(x))
#define PROCESS_CTX_FIND(x)		(ProcessCtx::getInstance()->FindProcessCtxByPid(x))
#define PROCESS_CTX_CLEAR()		(ProcessCtx::getInstance()->CleanupProcessCtxList())

