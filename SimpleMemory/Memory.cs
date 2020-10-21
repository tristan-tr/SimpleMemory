using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace SimpleMemory
{
    public class Memory
    {
        internal IntPtr Handle;

        private Process _process;
        public Process Process
        {
            get => _process;
            set
            {
                Handle = Win32.Wrappers.OpenProcess(value.Id, Win32.Enums.ProcessAccessFlags.VirtualMemoryOperation
                    | Win32.Enums.ProcessAccessFlags.VirtualMemoryRead | Win32.Enums.ProcessAccessFlags.VirtualMemoryWrite
                    | Win32.Enums.ProcessAccessFlags.QueryInformation);
                _process = value;
            }
        }

        private Dictionary<string, ProcessModule> _modules = new Dictionary<string, ProcessModule>();
        public Dictionary<string, ProcessModule> Modules
        {
            get
            {
                // Go through each module
                foreach (ProcessModule procModule in Process.Modules)
                {
                    // Add it to our dictionary
                    _modules[procModule.ModuleName] = procModule;
                }

                return _modules;
            }
        }

        #region Constructors
        public Memory(Process process)
        {
            Process = process;
        }

        public Memory(int processId)
        {
            Process = Process.GetProcessById(processId);
        }

        public Memory(string processName, int index = 0)
        {
            Process[] processes = Process.GetProcessesByName(processName);

            // Check if there are more processes than the user specified
            if(index > processes.Length)
            {
                throw new ArgumentException("Index is higher than the amount of processes found.");
            }

            Process = processes[index];
        }
        #endregion

        public IntPtr FollowPointer(IntPtr ptrBase, int[] offsets)
        {
            // Read our pointerbase first, then add offsets and read it again, etc
            IntPtr currentAddress = ptrBase;
            foreach (var currentOffset in offsets)
            {
                currentAddress = ReadMemory<IntPtr>(currentAddress);
                currentAddress += currentOffset;
            }

            return currentAddress;
        }
        public IntPtr FollowPointerSafe(IntPtr ptrBase, int[] offsets)
        {
            // Read our pointerbase first, then add offsets and read it again, etc
            IntPtr currentAddress = ptrBase;
            foreach (var currentOffset in offsets)
            {
                currentAddress = ReadMemorySafe<IntPtr>(currentAddress);
                currentAddress += currentOffset;
            }

            return currentAddress;
        }

        private bool CheckBufferForPattern(Nullable<byte>[] pattern, byte[] buffer, out int offset)
        {
            // Scan from the start to end
            for (offset = 0; offset < buffer.Length; offset++)
            {
                bool found = true;
                for (int i = 0; i < pattern.Length; i++)
                {
                    // Check if the current pattern offset has a value (not a wildcard) and if the current byte matches the pattern
                    if (pattern[i].HasValue && buffer[offset + i] != pattern[i].Value)
                    {
                        found = false;
                        break;
                    }
                }
                if (found)
                {
                    return true;
                }
            }

            // We haven't found the pattern
            return false;
        }

        private Nullable<byte>[] ParsePattern(string pattern)
        {
            // Our bytes are split by spaces
            string[] strBytes = pattern.Split(' ');

            Nullable<byte>[] patternBytes = new Nullable<byte>[strBytes.Length];

            for (int i = 0; i < strBytes.Length; i++)
            {
                // Check if the current byte is a wildcard (doesn't contain a byte value)
                bool isByte = byte.TryParse(strBytes[i], NumberStyles.HexNumber, null, out byte result);

                if (isByte)
                    patternBytes[i] = result;
                // The default value is null, so we don't need to set it to null if it is a wildcard
            }

            return patternBytes;
        }

        /// <summary>
        /// Scans for a pattern of bytes inside another process
        /// </summary>
        /// <param name="pattern">Pattern of bytes to be scanned for</param>
        /// <returns>IntPtr to the pattern or IntPtr.Zero if no pattern was found</returns>
        public IntPtr PatternScan(string pattern)
        {
            // Just scan every part of memory of the process
            IntPtr startAddress = IntPtr.Zero;
            // Scan to the end of the memory
            int endAddress = Process.VirtualMemorySize;

            return PatternScan(pattern, startAddress, endAddress);
        }

        /// <summary>
        /// Scans a module for a pattern of bytes
        /// </summary>
        /// <param name="pattern">Pattern of bytes to be scanned for</param>
        /// <param name="mask">Can be used to mask the pattern, e.g. with "x?xxxx" the 2nd byte is a wildcard and can be anything</param>
        /// <param name="module">Module to be scanned</param>
        /// <returns>IntPtr to the pattern or IntPtr.Zero if no pattern was found</returns>
        public IntPtr PatternScan(string pattern, ProcessModule module)
        {
            // EntryPointAddress is where the code starts
            IntPtr startAddress = module.EntryPointAddress;
            // The size after the entrypoint is the total size - the difference between entrypoint and base
            int endAddress = module.ModuleMemorySize - Math.Abs((int)module.EntryPointAddress - (int)module.BaseAddress);

            return PatternScan(pattern, startAddress, endAddress);
        }

        public IntPtr PatternScan(string pattern, IntPtr startAddress, int endAddress)
        {
            // Parse our pattern
            Nullable<byte>[] parsedPattern = ParsePattern(pattern);

            // Loop through every memory region seperately
            Win32.Structs.MemoryBasicInformation memoryBasicInformation = new Win32.Structs.MemoryBasicInformation();
            do
            {
                memoryBasicInformation = Win32.Wrappers.VirtualQueryEx(Handle, startAddress, Marshal.SizeOf(memoryBasicInformation));

                // Check if the memory has data and if its not readable
                if (memoryBasicInformation.State == Win32.Enums.MemState.MEM_COMMIT
                    && memoryBasicInformation.Protect != Win32.Enums.MemoryProtection.PAGE_NOACCESS
                    && memoryBasicInformation.Protect != Win32.Enums.MemoryProtection.PAGE_GUARD
                    && memoryBasicInformation.Type != Win32.Enums.MemType.MEM_MAPPED)
                {
                    // Read this region
                    byte[] buffer = ReadMemorySafe(startAddress, memoryBasicInformation.RegionSize);

                    // Check if our pattern is in here
                    if (CheckBufferForPattern(parsedPattern, buffer, out int offset))
                    {
                        // Return the address we found our pattern at
                        return memoryBasicInformation.BaseAddress + offset;
                    }
                }

                // Go to the next memory region
                startAddress = IntPtr.Add(startAddress, memoryBasicInformation.RegionSize);
            } while ((int)startAddress < (int)endAddress);

            // We haven't found our pattern
            return IntPtr.Zero;
        }


        public string ReadNullTerminatedString(IntPtr baseAddress, Encoding encoding, bool safe = false, int maxLength = 4096)
        {
            // Read our string with our correct method based on <safe (bool)>
            byte[] stringBlock;
            if (safe)
                stringBlock = ReadMemorySafe(baseAddress, maxLength);
            else
                stringBlock = ReadMemory(baseAddress, maxLength);

            // Add each byte to our string until the null terminator
            int stringLength = 0;
            foreach (var currentByte in stringBlock)
            {
                // Check if our byte is a null terminator
                if (currentByte == 0x00)
                    break;

                // Our byte isn't a null terminator, so increase our string length by one
                stringLength++;
            }

            // Get our string from our bytes without copying it
            var stringSegment = new ArraySegment<byte>(stringBlock, 0, stringLength);

            // Convert our byte array to a managed string object
            return encoding.GetString(stringSegment);
        }
        public string ReadNullTerminatedString(IntPtr baseAddress, bool safe = false, int maxLength = 4096)
        {
            return ReadNullTerminatedString(baseAddress, Encoding.Default, safe, maxLength);
        }


        public bool WriteNullTerminatedString(IntPtr baseAddress, string written, Encoding encoding, bool safe = false)
        {
            // Create our string buffer
            byte[] stringBytes = encoding.GetBytes(written);

            // Copy our bytes to a new array and add a null terminator (default value)
            byte[] terminatedString = new byte[stringBytes.Length + 1];
            Buffer.BlockCopy(stringBytes, 0, terminatedString, 0, stringBytes.Length);

            // Write our bytes with our correct function based on <safe>
            if (safe)
                return WriteMemorySafe(baseAddress, terminatedString, terminatedString.Length);
            else
                return WriteMemory(baseAddress, terminatedString, terminatedString.Length);
        }
        public bool WriteNullTerminatedString(IntPtr baseAddress, string written, bool safe = false)
        {
            return WriteNullTerminatedString(baseAddress, written, Encoding.Default, safe);
        }


        #region ReadMemory
        /// <summary>
        /// Reads memory at the target location
        /// </summary>
        /// <typeparam name="T">Unmanaged struct to read memory into</typeparam>
        /// <param name="baseAddress">Address at which memory is read</param>
        /// <returns>Object of type <typeparamref name="T"/></returns>
        public T ReadMemory<T>(IntPtr baseAddress) where T : struct
        {
            return (T)Win32.Wrappers.ReadProcessMemory(Handle, baseAddress, new T(), Marshal.SizeOf<T>());
        }

        /// <summary>
        /// Reads memory at the target location
        /// </summary>
        /// <param name="baseAddress">Address at which memory is read</param>
        /// <param name="length">Overwrites the length (in bytes) of data read</param>
        /// <returns>Object of type <typeparamref name="T"/></returns>
        public byte[] ReadMemory(IntPtr baseAddress, int length)
        {
            return (byte[])Win32.Wrappers.ReadProcessMemory(Handle, baseAddress, new byte[length], length);
        }

        /// <summary>
        /// Reads memory at the target location while making sure reading is allowed
        /// </summary>
        /// <typeparam name="T">Unmanaged struct to read memory into</typeparam>
        /// <param name="baseAddress">Address at which memory is read</param>
        /// <returns>Object of type <typeparamref name="T"/></returns>
        public T ReadMemorySafe<T>(IntPtr baseAddress) where T : struct
        {
            return Win32.Wrappers.SafeOperationWrap(Handle, baseAddress, Marshal.SizeOf<T>(), () => ReadMemory<T>(baseAddress));
        }

        /// <summary>
        /// Reads memory at the target location while making sure reading is allowed
        /// </summary>
        /// <param name="baseAddress">Address at which memory is read</param>
        /// <param name="length">Overwrites length (in bytes) of data read</param>
        /// <returns>Object of type <typeparamref name="T"/></returns>
        public byte[] ReadMemorySafe(IntPtr baseAddress, int length)
        {
            return Win32.Wrappers.SafeOperationWrap(Handle, baseAddress, length, () => ReadMemory(baseAddress, length));
        }
        #endregion
        #region WriteMemory
        /// <summary>
        /// Writes an object of type <typeparamref name="T"/> to target address
        /// </summary>
        /// <typeparam name="T">Type of object to write</typeparam>
        /// <param name="baseAddress">Address at which <paramref name="written"/> is written</param>
        /// <param name="written">Object which is written at <paramref name="baseAddress"/></param>
        /// <returns></returns>
        public bool WriteMemory<T>(IntPtr baseAddress, T written) where T : struct
        {
            return WriteMemory<T>(baseAddress, written, Marshal.SizeOf<T>());
        }

        /// <summary>
        /// Writes an object of type <typeparamref name="T"/> to target address
        /// </summary>
        /// <typeparam name="T">Type of object to write</typeparam>
        /// <param name="baseAddress">Address at which <paramref name="written"/> is written</param>
        /// <param name="written">Object which is written at <paramref name="baseAddress"/></param>
        /// <param name="length">Overwrites length (in bytes) of data written</param>
        /// <returns></returns>
        public bool WriteMemory<T>(IntPtr baseAddress, T written, int length)
        {
            return Win32.Wrappers.WriteProcessMemory(Handle, baseAddress, written, length);
        }

        /// <summary>
        /// Writes an object of type <typeparamref name="T"/> to target address while making sure writing is allowed
        /// </summary>
        /// <typeparam name="T">Type of object to write</typeparam>
        /// <param name="baseAddress">Address at which <paramref name="written"/> is written</param>
        /// <param name="written">Object which is written at <paramref name="baseAddress"/></param>
        /// <returns></returns>
        public bool WriteMemorySafe<T>(IntPtr baseAddress, T written) where T : struct
        {
            return Win32.Wrappers.SafeOperationWrap(Handle, baseAddress, Marshal.SizeOf<T>(), () => WriteMemory<T>(baseAddress, written));
        }

        /// <summary>
        /// Writes an object of type <typeparamref name="T"/> to target address while making sure writing is allowed
        /// </summary>
        /// <typeparam name="T">Type of object to write</typeparam>
        /// <param name="baseAddress">Address at which <paramref name="written"/> is written</param>
        /// <param name="written">Object which is written at <paramref name="baseAddress"/></param>
        /// <param name="length">Overwrites length (in bytes) of data written</param>
        /// <returns></returns>
        public bool WriteMemorySafe<T>(IntPtr baseAddress, T written, int length)
        {
            return Win32.Wrappers.SafeOperationWrap(Handle, baseAddress, length, () => WriteMemory<T>(baseAddress, written, length));
        }
        #endregion
    }
}