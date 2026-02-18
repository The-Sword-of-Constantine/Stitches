use sysinfo::System;

pub fn get_pid_by_name(process_name: &str) -> u32 {
    // 1. 初始化系统对象并仅刷新进程列表
    let mut sys = System::new();
    sys.refresh_all();

    // 2. 遍历进程列表
    // Windows 上建议处理：确保输入带有 .exe 后缀，或者不区分大小写
    for process in sys.processes().values() {
        if *process.name().to_ascii_lowercase() == *process_name.to_ascii_lowercase() {
            return process.pid().as_u32();
        }
    }

    0
}
