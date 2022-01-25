<p align="center"><img src="https://github.com/hlldz/RefleXXion/blob/main/images/reflexxion.png" alt="RefleXXion" width="360"></p>

## Introduction
RefleXXion is a utility designed to aid in bypassing user-mode  hooks utilised by AV/EPP/EDR etc. In order to bypass the user-mode hooks, it first collects the syscall numbers of the NtOpenFile, NtCreateSection, NtOpenSection and NtMapViewOfSection found in the LdrpThunkSignature array.  After that, there are two techniques that the user can choose to bypass the user-mode hooks.

Technique-1, reads the NTDLL as a file from `C:\Windows\System32\ntdll.dll`. After parsing, the .TEXT section of the already loaded NTDLL (where the hooks are performed) in memory is replaced with the .TEXT section of the clean NTDLL.

In Technique-2, NTDLL reads as Section from KnownDlls, `\KnownDlls\ntdll.dll`. (beacuse DLL files are cached in KnownDlls as Section.) After parsing, the .TEXT section of the already loaded NTDLL (where the hooks are performed) in memory is replaced with the .TEXT section of the clean NTDLL.

The detailed flow of the methodology and all techniques is given below.

<p align="center"><img src="https://github.com/hlldz/RefleXXion/blob/main/images/flow.png?raw=true" alt="RefleXXion Flow" width="800"></p>

## How to Use
You can open and compile the project with Visual Studio. The whole project supports x64 architecture for both Debug and Release modes.

The  RefleXXion-EXE solution generates the EXE for PoC purpose. If you want to understand how the project works step by step, it will make your job easier. Main function contains Technique1 and Technique2 functions definations.  Comment one of them and compile. Do not use both functions at the same time.

The RefleXXion-DLL solution generates the DLL that you inject into the process you want to bypass the user-mode hooks for NTDLL. At the beginning of the `main.cpp` file, there are definitions of which technique to use. You can choose one of them and compile it. Do not set all values at the same time, set only the one technique you want. Example configuration is given below.

```cpp
// Techniques configuration section
#define FROM_DISK 1 // If you set it to 1, the Technique-1 will be used. For more information; https://github.com/hlldz/RefleXXion
#define FROM_KNOWNDLLS 0 // If you set it to 1, the Technique-2 will be used. For more information; https://github.com/hlldz/RefleXXion
```
## Operational Usage Notes & OPSEC Concerns
* RefleXXion currently is only supports for x64 architecture.
* RefleXXion only unhooks NTDLL functions, you may need to unhook other DLLs (kernel32.dll, advapi32.dll etc.) as well. For this, you can easily edit the necessary places in the project. 
* The RefleXXion only uses the RWX memory region when overwriting the .TEXT section process starts. For this process a new memory reginon is not created, the existing memory region (the TEXT section of the NTDLL that is already loaded) is RWXed and then converted to RX.

  ```cpp
  ULONG oldProtection;
  ntStatus = NtProtectVirtualMemory(NtCurrentProcess(), &lpBaseAddress, &uSize, PAGE_EXECUTE_READWRITE, &oldProtection);
  memcpy()...
  ntStatus = NtProtectVirtualMemory(NtCurrentProcess(), &lpBaseAddress, &uSize, oldProtection, &oldProtection);
  ```

  *P.S. The RefleXXion invokes the NtProtectVirtualMemory API over the cleanly installed NTDLL. It uses the CustomGetProcAddress function for this because the clean NTDLL is not in the InLoadOrderModuleList even though it is loaded into memory. So a solution like here (https://stackoverflow.com/questions/6734095/how-to-get-module-handle-from-func-ptr-in-win32) will not work. That's why the custom GetProcAddress function exists and is used.*
* You can load RefleXXion DLL from disk to target process. You may not prefer a run like this for sensitive work such as a Red Team operation. Therefore, you can convert the RefleXXion DLL to shellcode using the sRDI project or integrate the RefleXXion code into your own loader or project.
* Even if NTDLL (as file or as section) is reloaded to the injected process, it does not remain loaded. RefleXXion close all opened handles (file & section handles) for own processes.

## Special Thanks & Credits
* Research & PoC for collecting clean system calls with LdrpThunkSignature by Peter Winter-Smith, [@peterwintrsmith](https://twitter.com/peterwintrsmith). EDR Parallel-asis through Analysis, https://www.mdsec.co.uk/2022/01/edr-parallel-asis-through-analysis/
* Windows 10 Parallel Loading Breakdown by Jeffrey Tang. https://blogs.blackberry.com/en/2017/10/windows-10-parallel-loading-breakdown
* https://stackoverflow.com/questions/42789199/why-there-are-three-unexpected-worker-threads-when-a-win32-console-application-s
* Shellycoat by Upayan, [@slaeryan](https://twitter.com/slaeryan). https://github.com/slaeryan/AQUARMOURY/tree/master/Shellycoat
