using System;
using System.Diagnostics;
using System.IO;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace PwnAdventure
{
    class Program
    {

        private static readonly string PROCESS_NAME = "PwnAdventure3-Win32-Shipping";
        private static readonly string MODULE_NAME = "GameLogic.dll";

        private static readonly float SPEED = 0.08f;

        static void Main(string[] args)
        {
            Process pwnAdventure3 = Process.GetProcessesByName(PROCESS_NAME)[0];
            Console.WriteLine($"\nFound {PROCESS_NAME}. Process ID = ${pwnAdventure3.Id}");

            IntPtr pwnAdventure3Address = getPwnAdventure3Address(pwnAdventure3);
            IntPtr gameLogicAddress = getGameLogicAddress(pwnAdventure3);
            IntPtr freezeAddress = getFreezeAddress(pwnAdventure3);
            IntPtr locationAddress = getLocationAdress(pwnAdventure3Address, gameLogicAddress);
            IntPtr viewAddress = getViewAddress(pwnAdventure3Address, gameLogicAddress);

            var freezing = Task.Run(async () =>
            {
                for (; ; )
                {
                    await Task.Delay(10);
                    unfreezeUser(pwnAdventure3Address, freezeAddress);
                    await Task.Delay(10);
                    freezeUser(pwnAdventure3Address, freezeAddress);
                }
            });

            var moving = Task.Run(async () =>
            {
                for (; ; )
                {
                    move(pwnAdventure3Address, locationAddress, translateForward(pwnAdventure3Address, locationAddress, viewAddress));
                }
            });

            Console.WriteLine("\nPress enter to quit");
            Console.ReadKey();

        }

        static IntPtr getLocationAdress(IntPtr pwnAdventure3Address, IntPtr gameLogicAddress)
        {
            return Memory.FindDynamicMemoryAddress(pwnAdventure3Address, IntPtr.Add(gameLogicAddress, 0x00097D7C), new int[] { 0x1C, 0x4, 0x114, 0x90 });
        }

        static IntPtr getViewAddress(IntPtr pwnAdventure3Address, IntPtr gameLogicAddress)
        {
            return Memory.FindDynamicMemoryAddress(pwnAdventure3Address, IntPtr.Add(gameLogicAddress, 0x00097D7C), new int[] { 0x1C, 0x4, 0x400, 0x80 });
        }

        static Vector3 getCurrentLocation(IntPtr pwnAdventure3Address, IntPtr locationAddress)
        {
            int bytesToRead = (int)Marshal.SizeOf(typeof(Vector3));
            byte[] buffer = new byte[bytesToRead];
            Memory.ReadProcessMemory(pwnAdventure3Address, locationAddress, buffer, bytesToRead, out var read);

            Vector3 location = new Vector3();
            using (var inputStream = new MemoryStream(buffer))
            {
                using (var reader = new BinaryReader(inputStream))
                {
                    location.X = reader.ReadSingle();
                    location.Y = reader.ReadSingle();
                    location.Z = reader.ReadSingle();
                }
            }

            return location;
        }

        static Quaternion getCurrentView(IntPtr pwnAdventure3Address, IntPtr viewAddress)
        {
            int bytesToRead = (int)Marshal.SizeOf(typeof(Quaternion));
            byte[] buffer = new byte[bytesToRead];
            Memory.ReadProcessMemory(pwnAdventure3Address, viewAddress, buffer, bytesToRead, out var read);

            Quaternion view = new Quaternion();
            using (var inputStream = new MemoryStream(buffer))
            {
                using (var reader = new BinaryReader(inputStream))
                {
                    view.X = reader.ReadSingle();
                    view.Y = reader.ReadSingle();
                    view.Z = reader.ReadSingle();
                    view.W = reader.ReadSingle();

                }
            }
            return view;
        }

        static void move(IntPtr pwnAdventure3Address, IntPtr locationPtr, Vector3 target)
        {
            // Console.WriteLine($"\nMoving to target {target}");
            float[] targetLocation = new float[] { target.X, target.Y, target.Z };
            var size = targetLocation.Length * 4;
            Memory.WriteProcessMemory(pwnAdventure3Address, locationPtr, targetLocation, size, out _);
        }

        static Vector3 translateForward(IntPtr pwnAdventure3Address, IntPtr locationAddress, IntPtr viewAddress)
        {
            Vector3 currentLocation = getCurrentLocation(pwnAdventure3Address, locationAddress);
            Quaternion currentView = getCurrentView(pwnAdventure3Address, viewAddress);
            Vector3 translation = new Vector3();
            translation.X = (2 * currentView.X * currentView.Z) - (2 * currentView.Y * currentView.W); // 2xz−2yw
            translation.Y = (2 * currentView.Y * currentView.Z) + (2 * currentView.X * currentView.W); // 2yz+2xw
            translation.Z = 1 - (2 * (currentView.X * currentView.X)) - (2 * (currentView.Y * currentView.Y)); //1−2x2−2y2]

            translation.X = 1 - 2 * (currentView.Y * currentView.Y + currentView.Z * currentView.Z); // 1 - 2 * (y^2 + z^2)
            translation.Y = 2 * (currentView.X * currentView.Y + currentView.W * currentView.Z); // 2 ( x * y + w * z)
            translation.Z = 2 * (currentView.X * currentView.Z - currentView.W * currentView.Y); // 2 ( x * z - w * y )

            translation.X = translation.X * SPEED;
            translation.Y = translation.Y * SPEED;
            translation.Z = translation.Z * SPEED;

            currentLocation.X = currentLocation.X + translation.X;
            currentLocation.Y = currentLocation.Y + translation.Y;
            currentLocation.Z = currentLocation.Z + translation.Z;

            return currentLocation;
        }


        static void freezeUser(IntPtr pwnAdventure3Address, IntPtr moveAddress)
        {
            byte[] freeze = new byte[] { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
            Memory.WriteProcessMemory(pwnAdventure3Address, moveAddress, freeze, freeze.Length, out _);
        }

        static void unfreezeUser(IntPtr pwnAdventure3Address, IntPtr moveAddress)
        {
            byte[] unFreeze = new byte[] { 0x0F, 0x29, 0x86, 0x90, 0x00, 0x00, 0x00 };
            Memory.WriteProcessMemory(pwnAdventure3Address, moveAddress, unFreeze, unFreeze.Length, out _);
        }

        static IntPtr getPwnAdventure3Address(Process pwnAdventure3)
        {
            return Memory.OpenProcess(Memory.ProcessAccessFlags.All, false, pwnAdventure3.Id);
        }

        static IntPtr getGameLogicAddress(Process pwnAdventure3)
        {
            return Memory.GetModuleBaseAddress(pwnAdventure3.Id, MODULE_NAME);
        }

        static IntPtr getFreezeAddress(Process pwnAdventure3)
        {
            return IntPtr.Add(pwnAdventure3.MainModule.BaseAddress, 0x008DB2D8);
        }

    }
}
