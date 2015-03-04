using System;
using System.Windows.Forms;
using System.Runtime.InteropServices;
using System.Reflection;

namespace CreateProcessWithDllTest
{
    class Program
    {
        //static DeviareLiteInterop.HookLib cHook = new DeviareLiteInterop.HookLib(); //<<<---- DON'T USE THIS WAY. SEE BELOW
        static DeviareLiteInterop.HookLib cHook;

        //--------

        static Program()
        {
            //USE THIS METHOD. Clarification: .Net initializes constructors and fields upon demand and NOT in
            //                                the C/C++ way. Because this constructor runs "before" Main,
            //                                DeviareLite internal hooks are properly installed before the Main
            //                                method is compiled by the JIT.
            cHook = new DeviareLiteInterop.HookLib();
        }

        static void Main(string[] args)
        {
            string cmdLine, dllName;
            DeviareLiteInterop.HookLib.STARTUPINFO si;
            DeviareLiteInterop.HookLib.ProcessInfo pi;

            cmdLine = Environment.ExpandEnvironmentVariables("%WINDIR%") + @"\System32\calc.exe";
            dllName = System.Reflection.Assembly.GetEntryAssembly().Location;
            dllName = System.IO.Path.GetDirectoryName(dllName) + @"\TestDll.dll";

            si = new DeviareLiteInterop.HookLib.STARTUPINFO();

            pi = cHook.CreateProcessWithDll(cmdLine, "", null, null, false, 0, null, null, si, dllName);
        }
    }
}
