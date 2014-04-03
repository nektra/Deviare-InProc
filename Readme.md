Deviare In-Process is a code interception engine for Microsoft Windows®.

This library is at the core of our [Deviare 2.0 (hooking for the masses)](http://www.nektra.com/products/deviare-api-hook-windows/) and [SpyStudio Application Monitor](http://www.nektra.com/products/spystudio-api-monitor/) technologies. Deviare is an alternative to Microsoft Detours® but with a dual license distribution.

The library is coded in C++ and provides all the facilities required to instrumenting binary libraries during runtime. It includes support for both 32 bit and 64 bit applications and it implements the interception verifying different situations that can crash the process. If you need to intercept any Win32 functions or any other code, this library makes it easier than ever.

Unlike the rest of the libraries, Deviare In-Process provides a safe mecanism to implement multi-threaded application API hooking. When an application is running, more than one thread can be executing the code being intercepted. Deviare In-Process provides safe hooking even in this scenario. Additionally, Deviare In-Proc uses assembly code to locate needed Api's and it only depends on NTDLL.DLL, no Kernel32 nor another library is used.

Please read the [README.txt](README.txt) file for building and usage instructions.
