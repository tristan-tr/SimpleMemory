using System;
using System.Runtime.InteropServices;


namespace SimpleMemory
{
    internal partial class Win32
    {
        public const int ERROR_SUCCESS = 0;

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr OpenProcess(Enums.ProcessAccessFlags processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
#pragma warning disable CS0618 // Type or member is obsolete
        internal static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [MarshalAs(UnmanagedType.AsAny)] object lpBuffer, int dwSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out, MarshalAs(UnmanagedType.AsAny)] object lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);
#pragma warning restore CS0618 // Type or member is obsolete

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpBaseAddress, out Structs.MemoryBasicInformation lpBuffer, int dwLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpBaseAddress, int dwSize, Enums.MemoryProtection flNewProtect, out Enums.MemoryProtection lpflOldProtect);
    }
}