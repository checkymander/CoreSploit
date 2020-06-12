using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace CoreSploit.Execution
{
    public class Linux
    {
        [DllImport("libc", SetLastError = true)]
        public static extern int getgrouplist(string user, int basegid, int groups, int ngroups);

        [DllImport("libc", SetLastError = true)]
        public static extern IntPtr getpwnam();


        //It might need to be
        //public static extern int getgrouplist(IntPtr user, int basegid, IntPtr groups, IntPtr ngroups);
    }
}
