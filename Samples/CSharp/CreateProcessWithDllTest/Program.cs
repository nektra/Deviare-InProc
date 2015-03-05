/*
 * Copyright (C) 2010-2015 Nektra S.A., Buenos Aires, Argentina.
 * All rights reserved. Contact: http://www.nektra.com
 *
 *
 * This file is part of Deviare In-Proc
 *
 *
 * Commercial License Usage
 * ------------------------
 * Licensees holding valid commercial Deviare In-Proc licenses may use this
 * file in accordance with the commercial license agreement provided with the
 * Software or, alternatively, in accordance with the terms contained in
 * a written agreement between you and Nektra.  For licensing terms and
 * conditions see http://www.nektra.com/licensing/.  For further information
 * use the contact form at http://www.nektra.com/contact/.
 *
 *
 * GNU General Public License Usage
 * --------------------------------
 * Alternatively, this file may be used under the terms of the GNU
 * General Public License version 3.0 as published by the Free Software
 * Foundation and appearing in the file LICENSE.GPL included in the
 * packaging of this file.  Please review the following information to
 * ensure the GNU General Public License version 3.0 requirements will be
 * met: http://www.gnu.org/copyleft/gpl.html.
 *
 **/

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
