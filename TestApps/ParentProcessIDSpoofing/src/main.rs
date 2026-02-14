use std::{ffi::c_void, mem::size_of, mem::zeroed, ptr::null_mut};
use sysinfo::System;

use windows::Win32::System::Memory::HeapFree;
use windows::{
    Win32::{
        Foundation::{CloseHandle, HANDLE, LUID},
        Security::{
            AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, LookupPrivilegeValueA,
            SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
        },
        System::{
            Memory::{GetProcessHeap, HEAP_ZERO_MEMORY, HeapAlloc},
            Threading::{
                CreateProcessA, DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT,
                GetCurrentProcess, InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
                OpenProcess, OpenProcessToken, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                PROCESS_ALL_ACCESS, PROCESS_INFORMATION, STARTUPINFOEXA, UpdateProcThreadAttribute,
            },
        },
    },
    core::{PCSTR, PSTR, s},
};

fn enable_privilege(name: PCSTR) -> () {
    unsafe {
        let mut token: HANDLE = zeroed();
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
        .expect("TODO: panic message");

        let mut luid_private: LUID = zeroed();
        LookupPrivilegeValueA(None, name, &mut luid_private).expect("TODO: panic message");

        let mut tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid_private,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        let _r = AdjustTokenPrivileges(token, false, Some(&mut tp), 0, None, None);

        let _ = CloseHandle(token);
    }
}

/// 使用 sysinfo 库获取进程 PID
fn get_pid_by_name(process_name: &str) -> Option<u32> {
    // 1. 初始化系统对象并仅刷新进程列表
    let mut sys = System::new();
    sys.refresh_all();

    // 2. 遍历进程列表
    // Windows 上建议处理：确保输入带有 .exe 后缀，或者不区分大小写
    for process in sys.processes().values() {
        if *process.name().to_ascii_lowercase() == *process_name.to_ascii_lowercase() {
            return Some(process.pid().as_u32());
        }
    }

    None
}

fn main() {
    unsafe {
        // 提权
        enable_privilege(s!("SeDebugPrivilege"));

        // using explorer.exe as spoofing process
        let parent_process_id = get_pid_by_name("explorer.exe").unwrap();
        if parent_process_id == 0 {
            panic!("Parent process ID 0 not found");
        }

        let handle_of_ppid = OpenProcess(PROCESS_ALL_ACCESS, false, parent_process_id);
        if handle_of_ppid.is_err() {
            panic!("Parent process ID 0 not found");
        }

        let mut startup_info: STARTUPINFOEXA = zeroed();
        let mut process_info: PROCESS_INFORMATION = zeroed();
        startup_info.StartupInfo.cb = size_of::<STARTUPINFOEXA>() as u32;

        let mut attr_size: usize = 0;

        // Get attr_size
        let _ = InitializeProcThreadAttributeList(
            Some(LPPROC_THREAD_ATTRIBUTE_LIST(null_mut())),
            1,
            Some(0),
            &mut attr_size,
        );

        // allocate LPPROC_THREAD_ATTRIBUTE_LIST
        let attr_list_mem = HeapAlloc(GetProcessHeap().unwrap(), HEAP_ZERO_MEMORY, attr_size);

        let attr_list = LPPROC_THREAD_ATTRIBUTE_LIST(attr_list_mem);

        // initialize
        let _ = InitializeProcThreadAttributeList(Some(attr_list), 1, Some(0), &mut attr_size);

        // update lpAttributeList
        let _ = UpdateProcThreadAttribute(
            attr_list,
            0,
            PROC_THREAD_ATTRIBUTE_PARENT_PROCESS as usize,
            Some(&handle_of_ppid as *const _ as *const c_void),
            size_of::<HANDLE>(),
            None,
            None,
        );

        let windir = std::env::var("WINDIR").unwrap() + "\\System32\\notepad.exe";
        // change
        startup_info.lpAttributeList = attr_list;
        let _ = CreateProcessA(
            None,
            Some(PSTR(windir.as_ptr() as _)),
            None,
            None,
            false,
            EXTENDED_STARTUPINFO_PRESENT,
            None,
            None,
            &startup_info.StartupInfo,
            &mut process_info,
        );

        DeleteProcThreadAttributeList(attr_list);

        HeapFree(
            GetProcessHeap().unwrap(),
            HEAP_ZERO_MEMORY,
            Some(attr_list_mem),
        )
        .unwrap();

        CloseHandle(handle_of_ppid.unwrap()).unwrap();
    }
}
