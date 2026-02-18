# Stitches
EN | [中文](./Readme.md)

## Feature
### Kernel Code
* Early Birld Apc Injector
* Kernel log informations
* Agent
  * Process Notify Callback（Get Process Context Information）
  * Thread Notify Callback（Check Remote Thread）
  * Image Notify Callback（Inject Hook Dll With Apc Inject）
  * Object Notify Callback (Process Protector & Block read lsass）
  * Reg Notify Callback(Reg protector & autorun monitor)
* MiniFilter
  * File Protector
  * USB device control（Wating...）
* ...


### Test App Code
* Parent PID Spoofing
* Direct Syscall


> https://github.com/ComodoSecurity/openedr   
> https://github.com/virtio-win/kvm-guest-drivers-windows
> https://github.com/janoglezcampos/rust_syscalls
> https://github.com/joaoviictorti/RustRedOps
> https://github.com/Whitecat18/Rust-for-Malware-Development