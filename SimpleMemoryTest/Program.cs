using System;
using System.Diagnostics;
using System.Reflection.Metadata;
using SimpleMemory;

namespace SimpleMemoryTest
{
    class Program
    {
        static void Main(string[] args)
        {
            Memory memClass = new Memory("Among Us");

            IntPtr value = memClass.PatternScan("38 D5 5C 00 B8 D6 5C 00 F8 CC 5C");

            Console.WriteLine("0x" + value.ToString("X"));

            Console.ReadKey();
        }
    }
}
