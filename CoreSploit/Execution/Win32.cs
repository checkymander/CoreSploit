using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace CoreSploit.Execution
{
    public static class Win32
    {
        public static class Netapi32
        {
            #region Functions
            [DllImport("netapi32.dll", SetLastError = true)]
            public static extern int NetApiBufferFree(IntPtr Buffer);

            [DllImport("netapi32.dll")]
            public static extern int NetLocalGroupEnum(
            [MarshalAs(UnmanagedType.LPWStr)] string servername,
            int level,
            out IntPtr bufptr,
            int prefmaxlen,
            out int entriesread,
            out int totalentries,
            ref int resume_handle
            );

            #endregion

            #region Structs
            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            public struct LOCALGROUP_USERS_INFO_0
            {
                [MarshalAs(UnmanagedType.LPWStr)] internal string name;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct LOCALGROUP_USERS_INFO_1
            {
                [MarshalAs(UnmanagedType.LPWStr)] public string name;
                [MarshalAs(UnmanagedType.LPWStr)] public string comment;
            }
            #endregion
        }
    }
}
