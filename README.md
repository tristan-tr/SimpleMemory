# SimpleMemory
Easy to use memory reading and writing API for C# on windows.

## Setup
```csharp
// Get a process object of the process you want to read memory off
Process process = Process.GetProcessById(1234);

Memory memClass = new Memory(process);
```

## Reading memory
```csharp
int value = memClass.ReadMemory<int>(new IntPtr(0xDEADBEEF));
```

## Writing memory
```csharp
memClass.WriteMemory(new IntPtr(0xDEADBEEF), 17);
```

## Notes
If you are writing to a protected area (e.g. code) then you should use the safe methods
```csharp
memClass.WriteMemorySafe(new IntPtr(0xDEADBEEF), 17);
```
