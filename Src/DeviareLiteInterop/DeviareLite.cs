using System;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace DeviareLiteInterop
{
    public sealed class HookLib
    {
        #region Public Enums
        public enum HookFlags : int
        {
            DontSkipInitialJumps     = 0x01,
            DontRemoveOnUnhook       = 0x02,
            DontSkipAnyJumps         = 0x04,
            SkipNullProcsToHook      = 0x08,
            UseAbsoluteIndirectJumps = 0x10,
            AllowReentrancy          = 0x20
        }
        #endregion

        #region Public Structs
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
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

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int length;
            public IntPtr lpSecurityDescriptor;
            public int inheritHandle;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ProcessInfo
        {
            public IntPtr procHandle;
            public IntPtr threadHandle;
            public int procId;
            public int threadId;
        }
        #endregion

        public HookLib()
        {
            Type hookLibType = Type.GetTypeFromCLSID(new Guid("CC78D151-6AA0-42d9-B9F1-C434CFAE695E"));
            this.hookLib = Activator.CreateInstance(hookLibType);
            this.hookInfoType = Type.GetTypeFromCLSID(new Guid("74A66D3C-D6D5-4991-90FC-59F312BCD624"));

            this.DotNetInit();
        }

        public object Hook(IntPtr origAddr, IntPtr newAddr)
        {
            return this.Hook(origAddr, newAddr, 0);
        }

        public object Hook(IntPtr origAddr, IntPtr newAddr, int flags)
        {
            Object hookInfo = Activator.CreateInstance(hookInfoType);

            this.SetProperty(hookInfo, "OrigProcAddr", IntPtr2Obj(origAddr));
            this.SetProperty(hookInfo, "NewProcAddr", IntPtr2Obj(newAddr));
            this.Invoke(hookLib, "Hook", new object[] { hookInfo, flags });
            return hookInfo;
        }

        public object Hook(Type origClassType, string origMethodName, Type[] origParams,
                           Type newClassType, string newMethodName, Type[] newParams)
        {
            return this.Hook(origClassType, origMethodName, origParams, newClassType, newMethodName, newParams, 0);
        }

        public object Hook(Type origClassType, string origMethodName, Type[] origParams,
                           Type newClassType, string newMethodName, Type[] newParams, int flags)
        {
            IntPtr origAddr = this.GetMethodAddress(origClassType, origMethodName, origParams);
            IntPtr newAddr = this.GetMethodAddress(newClassType, newMethodName, newParams);
            return this.Hook(origAddr, newAddr, flags);
        }

        public object RemoteHook(IntPtr origAddr, IntPtr newAddr, int pid)
        {
            return this.RemoteHook(origAddr, newAddr, pid, 0);
        }

        public object RemoteHook(IntPtr origAddr, IntPtr newAddr, int pid, int flags)
        {
            Object hookInfo = Activator.CreateInstance(hookInfoType);

            this.SetProperty(hookInfo, "OrigProcAddr", IntPtr2Obj(origAddr));
            this.SetProperty(hookInfo, "NewProcAddr", IntPtr2Obj(newAddr));
            this.Invoke(this.hookLib, "RemoteHook", new object[] { hookInfo, pid, flags });
            return hookInfo;
        }

        public void Unhook(object o)
        {
            this.Invoke(this.hookLib, "Unhook", new object[] { o });
        }

        public void UnhookProcess(int pid)
        {
            this.Invoke(this.hookLib, "UnhookProcess", new object[] { pid });
        }

        public void UnhookAll()
        {
            this.Invoke(this.hookLib, "UnhookAll", null);
        }

        public void EnableHook(object o, bool enable)
        {
            int e = (enable) ? -1 : 0;
            this.Invoke(this.hookLib, "EnableHook", new object[] { o, e });
        }

        public void RemoveHook(object o, bool disable)
        {
            int d = (disable) ? -1 : 0;
            this.Invoke(this.hookLib, "RemoveHook", new object[] { o, d });
        }

        public bool SuspendThreadsWhileHooking
        {
            get {
                int e = (int)GetProperty(this.hookLib, "SuspendThreadsWhileHooking");
                return (e != 0) ? true : false;
            }

            set
            {
                int e = (value) ? -1 : 0;
                this.SetProperty(this.hookLib, "SuspendThreadsWhileHooking", e);
            }
        }

        public bool ShowDebugOutput
        {
            get {
                int e = (int)GetProperty(this.hookLib, "ShowDebugOutput");
                return (e != 0) ? true : false;
            }

            set
            {
                int e = (value) ? -1 : 0;
                this.SetProperty(this.hookLib, "ShowDebugOutput", e);
            }
        }

        public IntPtr GetModuleBaseAddress(string moduleName)
        {
            object o = this.Invoke(this.hookLib, "GetModuleBaseAddress", new object[] { moduleName });
            return Obj2IntPtr(o);
        }

        public IntPtr GetRemoteModuleBaseAddress(int pid, string moduleName, bool scanMappedImages)
        {
            int scanMI = (scanMappedImages) ? -1 : 0;
            object o = this.Invoke(this.hookLib, "GetRemoteModuleBaseAddress", new object[] { pid, moduleName, scanMI });
            return Obj2IntPtr(o);
        }

        public IntPtr GetProcedureAddress(IntPtr moduleBaseAddress, string procName)
        {
            object o = this.Invoke(this.hookLib, "GetProcedureAddress", new object[] { IntPtr2Obj(moduleBaseAddress), procName });
            return Obj2IntPtr(o);
        }

        public IntPtr GetRemoteProcedureAddress(int pid, IntPtr moduleBaseAddress, string procName)
        {
            object o = this.Invoke(this.hookLib, "GetRemoteProcedureAddress", new object[] { pid, IntPtr2Obj(moduleBaseAddress), procName });
            return Obj2IntPtr(o);
        }

        public ProcessInfo CreateProcessWithDll(string applicationName, string commandLine, Nullable<SECURITY_ATTRIBUTES> processAttributes,
                                                Nullable<SECURITY_ATTRIBUTES> threadAttributes, bool inheritHandles, int creationFlags,
                                                string environment, string currentDirectory, Nullable<STARTUPINFO> startupInfo, string dllName)
        {
            ProcessInfo pi = new ProcessInfo();
            IntPtr procAttr = IntPtr.Zero;
            IntPtr threadAttr = IntPtr.Zero;
            IntPtr stInfo = IntPtr.Zero;
            int ih = (inheritHandles) ? -1 : 0;

            if (processAttributes.HasValue)
            {
                procAttr = Marshal.AllocHGlobal(Marshal.SizeOf(processAttributes.Value));
                Marshal.StructureToPtr(processAttributes.Value, procAttr, false);
            }
            if (threadAttributes.HasValue)
            {
                threadAttr = Marshal.AllocHGlobal(Marshal.SizeOf(threadAttributes.Value));
                Marshal.StructureToPtr(threadAttributes.Value, threadAttr, false);
            }
            if (startupInfo.HasValue)
            {
                stInfo = Marshal.AllocHGlobal(Marshal.SizeOf(startupInfo.Value));
                Marshal.StructureToPtr(startupInfo.Value, stInfo, false);
            }
            if (applicationName == null)
                applicationName = "";
            if (commandLine == null)
                commandLine = "";
            if (environment == null)
                environment = "";
            if (currentDirectory == null)
                currentDirectory = "";
            try
            {
                object o = this.Invoke(this.hookLib, "CreateProcessWithDll", new object[] { applicationName, commandLine,
                                       IntPtr2Obj(procAttr), IntPtr2Obj(threadAttr), ih, creationFlags, environment,
                                       currentDirectory, IntPtr2Obj(stInfo), dllName });
                pi.procHandle = Obj2IntPtr(this.GetProperty(o, "ProcessHandle"));
                pi.threadHandle = Obj2IntPtr(this.GetProperty(o, "ThreadHandle"));
                pi.procId = (int)(this.GetProperty(o, "ProcessId"));
                pi.threadId = (int)(this.GetProperty(o, "ThreadId"));
            }
            catch (Exception)
            {
                throw;
            }
            finally
            {
                if (stInfo != IntPtr.Zero)
                    Marshal.FreeHGlobal(stInfo);
                if (threadAttr != IntPtr.Zero)
                    Marshal.FreeHGlobal(threadAttr);
                if (procAttr != IntPtr.Zero)
                    Marshal.FreeHGlobal(procAttr);
            }
            return pi;
        }

        public ProcessInfo CreateProcessWithLogonAndDll(string userName, string domain, string password, int logonFlags,
                                                        string applicationName, string commandLine, int creationFlags,
                                                        string environment, string currentDirectory,
                                                        Nullable<STARTUPINFO> startupInfo, string dllName)
        {
            ProcessInfo pi = new ProcessInfo();
            IntPtr stInfo = IntPtr.Zero;

            if (startupInfo.HasValue)
            {
                stInfo = Marshal.AllocHGlobal(Marshal.SizeOf(startupInfo.Value));
                Marshal.StructureToPtr(startupInfo.Value, stInfo, false);
            }
            if (userName == null)
                userName = "";
            if (domain == null)
                domain = "";
            if (password == null)
                password = "";
            if (applicationName == null)
                applicationName = "";
            if (commandLine == null)
                commandLine = "";
            if (environment == null)
                environment = "";
            if (currentDirectory == null)
                currentDirectory = "";
            try
            {
                object o = this.Invoke(this.hookLib, "CreateProcessWithLogonAndDll", new object[] { userName, domain, password,
                                       logonFlags, applicationName, commandLine, creationFlags, environment,
                                       currentDirectory, IntPtr2Obj(stInfo), dllName });
                pi.procHandle = Obj2IntPtr(this.GetProperty(o, "ProcessHandle"));
                pi.threadHandle = Obj2IntPtr(this.GetProperty(o, "ThreadHandle"));
                pi.procId = (int)(this.GetProperty(o, "ProcessId"));
                pi.threadId = (int)(this.GetProperty(o, "ThreadId"));
            }
            catch (Exception)
            {
                throw;
            }
            finally
            {
                if (stInfo != IntPtr.Zero)
                    Marshal.FreeHGlobal(stInfo);
            }
            return pi;
        }

        public ProcessInfo CreateProcessWithTokenAndDll(IntPtr token, int logonFlags, string applicationName, string commandLine,
                                                        int creationFlags, string environment, string currentDirectory,
                                                        Nullable<STARTUPINFO> startupInfo, string dllName)
        {
            ProcessInfo pi = new ProcessInfo();
            IntPtr stInfo = IntPtr.Zero;

            if (startupInfo.HasValue)
            {
                stInfo = Marshal.AllocHGlobal(Marshal.SizeOf(startupInfo.Value));
                Marshal.StructureToPtr(startupInfo.Value, stInfo, false);
            }
            if (applicationName == null)
                applicationName = "";
            if (commandLine == null)
                commandLine = "";
            if (environment == null)
                environment = "";
            if (currentDirectory == null)
                currentDirectory = "";
            try
            {
                object o = this.Invoke(this.hookLib, "CreateProcessWithTokenAndDll", new object[] { IntPtr2Obj(token),
                                       logonFlags, applicationName, commandLine, creationFlags, environment,
                                       currentDirectory, IntPtr2Obj(stInfo), dllName });
                pi.procHandle = Obj2IntPtr(this.GetProperty(o, "ProcessHandle"));
                pi.threadHandle = Obj2IntPtr(this.GetProperty(o, "ThreadHandle"));
                pi.procId = (int)(this.GetProperty(o, "ProcessId"));
                pi.threadId = (int)(this.GetProperty(o, "ThreadId"));
            }
            catch (Exception)
            {
                throw;
            }
            finally
            {
                if (stInfo != IntPtr.Zero)
                    Marshal.FreeHGlobal(stInfo);
            }
            return pi;
        }

        #region Private Vars
        private Object hookLib;
        private Type hookInfoType;
        private IntPtr dummy;
        #endregion

        #region Internal Helpers
        private Object GetProperty(Object obj, string propName)
        {
            return obj.GetType().InvokeMember(propName, BindingFlags.GetProperty | BindingFlags.Instance | BindingFlags.Public,
                                              null, obj, new object[] { });
        }

        private void SetProperty(Object obj, string propName, object propValue)
        {

            obj.GetType().InvokeMember(propName, BindingFlags.SetProperty | BindingFlags.Instance | BindingFlags.Public,
                                       null, obj, new object[] { propValue });
        }

        private Object Invoke(Object obj, string methodName, object[] parameters)
        {
            if (parameters == null)
                parameters = new object[] { };
            return obj.GetType().InvokeMember(methodName, BindingFlags.InvokeMethod | BindingFlags.Instance | BindingFlags.Public,
                                              null, obj, parameters);
        }

        private IntPtr GetMethodAddress(Type classType, string methodName, Type[] parameters)
        {
            MethodInfo mi = classType.GetMethod(methodName, BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static, null, CallingConventions.Any, parameters, null);
            if (mi == null)
                return IntPtr.Zero;
            System.Runtime.CompilerServices.RuntimeHelpers.PrepareMethod(mi.MethodHandle);
            return mi.MethodHandle.GetFunctionPointer();
        }

        [MethodImpl(MethodImplOptions.NoOptimization)]
        private void DotNetInit()
        {
            //NOTE: This will enforce a call to compileMethod in JIT compiler so DeviareLite.dll internal data can be initialized
            IntPtr mod = GetModuleBaseAddress("kernel32.dll");
            dummy = GetProcedureAddress(mod, "WaitForSingleObject");
            return;
        }

        private object IntPtr2Obj(IntPtr val)
        {
            if (IntPtr.Size == 4)
                return (object)(val.ToInt32());
            return (object)(val.ToInt64());
        }

        private IntPtr Obj2IntPtr(object o)
        {
            if (o is int)
                return new IntPtr((int)o);
            if (o is long)
                return new IntPtr((long)o);
            return IntPtr.Zero;
        }
        #endregion
    }
}
