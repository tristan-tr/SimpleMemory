using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
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
                Handle = Win32.Wrappers.OpenProcess(value.Id);
                _process = value;
            }
        }

        private Dictionary<string, IntPtr> _modules = new Dictionary<string, IntPtr>();
        public Dictionary<string, IntPtr> Modules
        {
            get
            {
                // Go through each module
                foreach (ProcessModule procModule in Process.Modules)
                {
                    // Add it to our dictionary with it's baseaddress
                    _modules[procModule.ModuleName] = procModule.BaseAddress;
                }

                return _modules;
            }
        }

        public Memory(Process process)
        {
            Process = process;
        }

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