// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.Runtime.InteropServices;

namespace CoreSploit.Execution.PlatformInvoke
{
    /// <summary>
    /// Win32 is a library of PInvoke signatures for Win32 API functions.
    /// </summary>
    /// <remarks>
    /// A majority of this library is adapted from signatures found at www.pinvoke.net.
    /// </remarks>
    public static class Win32
    {
        public static class Kernel32
        {
            [DllImport("kernel32.dll")]
            public static extern bool OpenProcessToken(
                IntPtr hProcess,
                uint dwDesiredAccess,
                out IntPtr hToken
            );
        }
    }
}