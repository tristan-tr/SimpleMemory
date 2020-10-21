using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace SimpleMemory
{
    internal partial class Win32
    {
        internal static class Wrappers
        {
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
                Enums.MemoryProtection flNewProtect = Enums.MemoryProtection.PAGE_EXECUTE_READWRITE)
            {
                return WrapFunction(() =>
                {
                    Win32.VirtualProtectEx(hProcess, lpBaseAddress, dwSize, flNewProtect, out Enums.MemoryProtection lpflOldProtect);
                    return lpflOldProtect;
                });
            }

            internal static Structs.MemoryBasicInformation VirtualQueryEx(IntPtr hProcess, IntPtr lpBaseAddress, int dwLength)
            {
                return WrapFunction(() =>
                {
                    Win32.VirtualQueryEx(hProcess, lpBaseAddress, out Structs.MemoryBasicInformation lpBuffer, Marshal.SizeOf<Structs.MemoryBasicInformation>());
                    return lpBuffer;
                });
            }
        }
    }
}
