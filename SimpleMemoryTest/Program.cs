using System;
using System.Reflection.Metadata;
using SimpleMemory;

namespace SimpleMemoryTest
{
    class Program
    {
        static void Main(string[] args)
        {
            Memory memClass = new Memory("Among Us");

            var module = memClass.Modules["Among Us.exe"];

            IntPtr value = memClass.PatternScan(new byte[] { 0x38, 0xD5, 0x5C, 0x00, 0xB8, 0xD6, 0x5C, 0x00, 0xF8, 0xCC, 0x5C }, "xxxxxxxxxxx".ToCharArray(), module);

            Console.WriteLine("0x" + value.ToString("X"));

            Console.ReadKey();
        }
    }
}
