using System;
using System.Windows.Forms;
using System.Runtime.InteropServices;
using System.Reflection;
using Nektra.DeviareLite;

namespace CreateProcessWithDllTest
{
    class Program
    {
        static NktHookLib cHook = new NktHookLib();

        //--------

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        static void Main(string[] args)
        {
            string cmdLine, dllName;
            IntPtr startupInfo = IntPtr.Zero;
            STARTUPINFO si;
            NktHookProcessInfo pi;

            try
            {
                cmdLine = Environment.ExpandEnvironmentVariables("%WINDIR%") + @"\System32\calc.exe";
                dllName = System.Reflection.Assembly.GetEntryAssembly().Location;
                dllName = System.IO.Path.GetDirectoryName(dllName) + @"\TestDll.dll";

                si = new STARTUPINFO();
                si.cb = Marshal.SizeOf(si);
                startupInfo = Marshal.AllocHGlobal(Marshal.SizeOf(si));
                Marshal.StructureToPtr(si, startupInfo, false);

                pi = cHook.CreateProcessWithDll(cmdLine, "", IntPtr.Zero, IntPtr.Zero, false, 0, null, null, startupInfo, dllName);
            }
            finally
            {
                if (startupInfo != IntPtr.Zero)
                    Marshal.FreeHGlobal(startupInfo);
            }
        }
    }
}
