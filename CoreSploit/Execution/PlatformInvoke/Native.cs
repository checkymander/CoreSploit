// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.Runtime.InteropServices;

using Execute = CoreSploit.Execution;

namespace CoreSploit.Execution.PlatformInvoke
{
    public static class Native
    {
        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern int NtQueryInformationProcess(
            IntPtr hProcess,
            Execute.Native.PROCESSINFOCLASS pic,
            IntPtr pi,
            int cb,
            out int pSize
        );
    }
}