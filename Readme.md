# Stitches(缝合怪)
中文 | [EN](./README_EN.md)

这个项目是集成了之前的一些Windows kernel开发代码，类似一个缝合怪项目所以取名为"Stitches"

## 目前的功能有
### Kernel Code
* APC 内核模式早鸟注入DLL (kernel apc injector(early bird mode))
* 内核日志实现（kernel log informations）
* 探针agent
  * 进程回调（获取进程上下文信息）
  * 线程回调（验证远程线程）
  * 映像回调（配合APC注入hook dll 监控进程行为）
  * 对象回调（进程防结束 + 防止非授信进程读取lsass进程）
  * 注册表回调（注册表路径保护 + autorun监控）
* MiniFilter
  * 文件保护
  * USB设备管控（待测试...）
* ...

### Test App Code
* 父进程欺骗
* Direct Syscall


### 参考项目
> https://github.com/ComodoSecurity/openedr   
> https://github.com/virtio-win/kvm-guest-drivers-windows
> https://github.com/janoglezcampos/rust_syscalls
> https://github.com/joaoviictorti/RustRedOps
> https://github.com/Whitecat18/Rust-for-Malware-Development


### 感谢
感谢好友 jacky(https://github.com/lzty)