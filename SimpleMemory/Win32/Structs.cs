using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace SimpleMemory
{
    internal partial class Win32
    {
        internal class Structs
        {
            [StructLayout(LayoutKind.Sequential)]
            public struct MemoryBasicInformation
            {
                public IntPtr BaseAddress;
                public IntPtr AllocationBase;
                public Enums.MemoryProtection AllocationProtect;
                public IntPtr RegionSize;
                public Enums.MemState State;
                public Enums.MemoryProtection Protect;
                public Enums.MemType Type;
            }
        }
    }
}
