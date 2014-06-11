using System;
using System.Windows.Forms;
using System.Runtime.InteropServices;
using System.Reflection;
using Nektra.DeviareLite;

namespace Test
{
    class Program
    {
        static NktHookLib cHook = new NktHookLib();

        //--------

        static void Main(string[] args)
        {
            IntPtr user32dll, msgBoxOrigProc;
            NktHookInfo sHookInfo = new NktHookInfo();

            user32dll = cHook.GetModuleBaseAddress("user32.dll");
            msgBoxOrigProc = cHook.GetProcedureAddress(user32dll, "MessageBoxW");
            if (msgBoxOrigProc == IntPtr.Zero)
            {
                MessageBox.Show("Error: Cannot Cannot get address of MessageBoxW", "HookTest", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            sHookInfo.OrigProcAddr = msgBoxOrigProc;
            sHookInfo.NewProcAddr = Marshal.GetFunctionPointerForDelegate(new delegMessageBoxApi(Hooked_MessageBoxApi));
            cHook.Hook(sHookInfo, 0);
            msgBoxCallOrigDeleg = (delegMessageBoxApi)Marshal.GetDelegateForFunctionPointer(sHookInfo.CallOriginalAddr, typeof(delegMessageBoxApi));

            MessageBox.Show("This should be hooked", "HookTest", MessageBoxButtons.OK);
            cHook.Unhook(sHookInfo);
            MessageBox.Show("This should NOT be hooked", "HookTest", MessageBoxButtons.OK);
        }

        [DllImport("user32.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, EntryPoint = "MessageBoxW")]
        public static extern uint MessageBoxApi(IntPtr hWnd, String text, String caption, int options);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate uint delegMessageBoxApi(IntPtr hWnd, String text, String caption, int options);
        static delegMessageBoxApi msgBoxCallOrigDeleg;

        static uint Hooked_MessageBoxApi(IntPtr hWnd, String text, String caption, int options)
        {
            return msgBoxCallOrigDeleg(hWnd, text, "HOOKED!!!", options);
        }

    }
}
