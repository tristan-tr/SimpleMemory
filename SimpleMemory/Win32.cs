using System;
using System.Runtime.InteropServices;


namespace SimpleMemory
{
    internal class Win32
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
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpBaseAddress, int dwSize, Enums.MemoryProtection flNewProtect, out Enums.MemoryProtection lpflOldProtect);

        internal static class Wrappers
        {
            internal static IntPtr OpenProcess(int processId,
                Enums.ProcessAccessFlags processAccess = Enums.ProcessAccessFlags.VirtualMemoryOperation | Enums.ProcessAccessFlags.VirtualMemoryRead |
                Enums.ProcessAccessFlags.VirtualMemoryWrite | Enums.ProcessAccessFlags.Terminate)
            {
                return WrapFunction(() => Win32.OpenProcess(processAccess, false, processId));
            }

            internal static bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, object lpBuffer, int length)
            {
                return WrapFunction(() => Win32.WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, length, out _));
            }

            internal static object ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, object lpBuffer, int length)
            {
                return WrapFunction(() => {
                    Win32.ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, length, out _);
                    return lpBuffer;
                    });
            }

            internal static Enums.MemoryProtection VirtualProtectEx(IntPtr hProcess, IntPtr lpBaseAddress, int dwSize,
                Enums.MemoryProtection flNewProtect = Enums.MemoryProtection.PAGE_READWRITE)
            {
                return WrapFunction(() =>
                {
                    Win32.VirtualProtectEx(hProcess, lpBaseAddress, dwSize, flNewProtect, out Enums.MemoryProtection lpflOldProtect);
                    return lpflOldProtect;
                });
            }

            private static T WrapFunction<T>(Func<T> function)
            {
                // Run our function
                T returnValue = function.Invoke();

                // Check for errors
                if (Marshal.GetLastWin32Error() != ERROR_SUCCESS)
                {
                    throw new Exception($"Couldn't invoke win32 function, error: {Marshal.GetLastWin32Error()}");
                }

                return returnValue;
            }

            /// <summary>
            /// Wraps a function with VirtualProtect methods to be sure that any operation at that address can be executed
            /// </summary>
            /// <typeparam name="T"></typeparam>
            /// <param name="handle"></param>
            /// <param name="baseAddress"></param>
            /// <param name="function"></param>
            /// <returns>Return value of <paramref name="function"/></returns>
            internal static T SafeOperationWrap<T>(IntPtr handle, IntPtr baseAddress, int length, Func<T> function)
            {
                // Make sure we can do the operation there
                Win32.Enums.MemoryProtection oldProtection = Win32.Wrappers.VirtualProtectEx(handle, baseAddress, length);

                // Execute our operation
                T obj = function.Invoke();

                // Restore original protection to avoid detection
                // If the original is the same as we wrote then why would we restore it?
                if (oldProtection != Enums.MemoryProtection.PAGE_READWRITE)
                    Win32.Wrappers.VirtualProtectEx(handle, baseAddress, length);

                return obj;
            }
        }

        internal class Enums
        {
            [Flags]
            public enum ProcessAccessFlags : uint
            {
                All = 0x001F0FFF,
                Terminate = 0x00000001,
                CreateThread = 0x00000002,
                VirtualMemoryOperation = 0x00000008,
                VirtualMemoryRead = 0x00000010,
                VirtualMemoryWrite = 0x00000020,
                DuplicateHandle = 0x00000040,
                CreateProcess = 0x000000080,
                SetQuota = 0x00000100,
                SetInformation = 0x00000200,
                QueryInformation = 0x00000400,
                QueryLimitedInformation = 0x00001000,
                Synchronize = 0x00100000
            }

            public enum MemoryProtection : uint
            {
                PAGE_NOACCESS = 0x01,
                PAGE_READONLY = 0x02,
                PAGE_READWRITE = 0x04,
                PAGE_WRITECOPY = 0x08,
                PAGE_EXECUTE = 0x10,
                PAGE_EXECUTE_READ = 0x20,
                PAGE_EXECUTE_READWRITE = 0x40,
                PAGE_EXECUTE_WRITECOPY = 0x80,
                PAGE_GUARD = 0x100,
                PAGE_NOCACHE = 0x200,
                PAGE_WRITECOMBINE = 0x400
            }
        }
    }
}