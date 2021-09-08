using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security;
using System.Text;

namespace PwnAdventure
{
    class Memory
    {
        private static readonly long INVALID_HANDLE_VALUE = -1;

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESSENTRY32
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ProcessID;
            public IntPtr th32DefaultHeapID;
            public uint th32ModuleID;
            public uint cntThreads;
            public uint th32ParentProcessID;
            public int pcPriClassBase;
            public uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExeFile;
        };

        [StructLayout(LayoutKind.Sequential, CharSet = System.Runtime.InteropServices.CharSet.Ansi)]
        public struct MODULEENTRY32
        {
            internal uint dwSize;
            internal uint th32ModuleID;
            internal uint th32ProcessID;
            internal uint GlblcntUsage;
            internal uint ProccntUsage;
            internal IntPtr modBaseAddr;
            internal uint modBaseSize;
            internal IntPtr hModule;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            internal string szModule;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            internal string szExePath;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ModuleInformation
        {
            public IntPtr lpBaseOfDll;
            public uint SizeOfImage;
            public IntPtr EntryPoint;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct Module
        {
            public string moduleName;
            public IntPtr baseAddress;
            public uint size;
        }

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

        [Flags]
        private enum SnapshotFlags : uint
        {
            HeapList = 0x00000001,
            Process = 0x00000002,
            Thread = 0x00000004,
            Module = 0x00000008,
            Module32 = 0x00000010,
            Inherit = 0x80000000,
            All = 0x0000001F,
            NoHeaps = 0x40000000
        }

        [Flags]
        enum LoadLibraryFlags : uint
        {
            None = 0,
            DONT_RESOLVE_DLL_REFERENCES = 0x00000001,
            LOAD_IGNORE_CODE_AUTHZ_LEVEL = 0x00000010,
            LOAD_LIBRARY_AS_DATAFILE = 0x00000002,
            LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE = 0x00000040,
            LOAD_LIBRARY_AS_IMAGE_RESOURCE = 0x00000020,
            LOAD_LIBRARY_SEARCH_APPLICATION_DIR = 0x00000200,
            LOAD_LIBRARY_SEARCH_DEFAULT_DIRS = 0x00001000,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR = 0x00000100,
            LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800,
            LOAD_LIBRARY_SEARCH_USER_DIRS = 0x00000400,
            LOAD_WITH_ALTERED_SEARCH_PATH = 0x00000008
        }

        internal enum ModuleFilter
        {
            ListModulesDefault = 0x0,
            ListModules32Bit = 0x01,
            ListModules64Bit = 0x02,
            ListModulesAll = 0x03,
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);


        [DllImport("kernel32.dll")]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [MarshalAs(UnmanagedType.AsAny)] object lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll")]
        static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll")]
        static extern bool Module32First(IntPtr hSnapshot, ref MODULEENTRY32 lpme);

        [DllImport("kernel32.dll")]
        static extern bool Module32Next(IntPtr hSnapshot, ref MODULEENTRY32 lpme);

        [DllImport("kernel32.dll", SetLastError = true)]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [SuppressUnmanagedCodeSecurity]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateToolhelp32Snapshot(SnapshotFlags dwFlags, int th32ProcessID);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("psapi.dll", SetLastError = true)]
        public static extern bool EnumProcessModules(IntPtr hProcess,
[MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U4)][In][Out] uint[] lphModule, uint cb, [MarshalAs(UnmanagedType.U4)] out uint lpcbNeeded);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr LoadLibraryEx(string lpFileName, IntPtr hReservedNull, LoadLibraryFlags dwFlags);

        [DllImport("psapi.dll")]
        public static extern bool EnumProcessModulesEx(IntPtr hProcess, [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U4)][In][Out] IntPtr[] lphModule, int cb, [MarshalAs(UnmanagedType.U4)] out int lpcbNeeded, uint dwFilterFlag);

        [DllImport("psapi.dll")]
        public static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, [Out] StringBuilder lpBaseName, [In][MarshalAs(UnmanagedType.U4)] uint nSize);

        [DllImport("psapi.dll", SetLastError = true)]
        public static extern bool GetModuleInformation(IntPtr hProcess, IntPtr hModule, out ModuleInformation lpmodinfo, uint cb);

        public static IntPtr GetModuleBaseAddress(Process process, string moduleName)
        {
            foreach (ProcessModule m in process.Modules)
            {
                if (m.ModuleName == moduleName)
                {
                    return m.BaseAddress;
                }
            }

            throw new ApplicationException("Couldn't find Module Base Address \"" + moduleName + "\"");
        }

        public static IntPtr GetModuleBaseAddress(int processId, string moduleName)
        {
            IntPtr hSnap = CreateToolhelp32Snapshot(SnapshotFlags.All, processId);

            if (hSnap.ToInt64() != INVALID_HANDLE_VALUE)
            {
                MODULEENTRY32 moduleEntry = new MODULEENTRY32();
                moduleEntry.dwSize = (uint)Marshal.SizeOf(typeof(MODULEENTRY32));

                if (Module32First(hSnap, ref moduleEntry))
                {
                    while (Module32Next(hSnap, ref moduleEntry))
                    {
                        if (moduleEntry.szModule.Equals(moduleName, StringComparison.OrdinalIgnoreCase))
                        {
                            CloseHandle(hSnap);
                            return moduleEntry.modBaseAddr;
                        }
                    }
                }
            }
            CloseHandle(hSnap);
            Console.WriteLine("\nCouldn't find Module Base Address \"" + moduleName + "\"");
            Console.WriteLine("\nPress any key to continue...");
            Console.ReadKey();
            Environment.Exit(1);
            return IntPtr.Zero;
        }

        public static IntPtr FindDynamicMemoryAddress(IntPtr moduleBaseAddress, IntPtr ptr, int[] offsets)
        {
            byte[] buffer = new byte[IntPtr.Size];
            foreach (int nextOffset in offsets)
            {
                ReadProcessMemory(moduleBaseAddress, ptr, buffer, buffer.Length, out var read);
                // PwnAdventure is a 32bit game so pointer size is 4, use ToInt64 if 64 bit.
                IntPtr nextOffsetPtr = new IntPtr(BitConverter.ToInt32(buffer, 0));
                ptr = IntPtr.Add(nextOffsetPtr, nextOffset);
            }

            return ptr;
        }

        public static byte[] Serialize<T>(T data)
        where T : struct
        {
            var formatter = new BinaryFormatter();
            var stream = new MemoryStream();
            formatter.Serialize(stream, data);
            return stream.ToArray();
        }


        public static T Deserialize<T>(byte[] array)
        where T : struct
        {
            var stream = new MemoryStream(array);
            var formatter = new BinaryFormatter();
            return (T)formatter.Deserialize(stream);
        }
    }



}
