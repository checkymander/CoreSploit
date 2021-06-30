using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Drawing;
using System.Security.Principal;

using CoreSploit.Generic;
using CoreSploit.Execution;

using PInvoke = CoreSploit.Execution.PlatformInvoke;

namespace CoreSploit.Enumeration
{
    public class Host
    {
        /// <summary>
        /// Gets a list of running processes on the system.
        /// </summary>
        /// <returns>List of ProcessResults.</returns>
        public static CoreSploitResultList<ProcessResult> GetProcessList()
        {
            var processes = Process.GetProcesses()
                .OrderBy(p => p.Id)
                .ToArray();
            
            var results = new CoreSploitResultList<ProcessResult>();

            foreach (var process in processes)
            {
                var processId = process.Id;
                var parentProcessId = 0;
                
                try
                {
                    parentProcessId = GetParentProcess(process.Handle);
                }
                catch { }
                
                
                var processName = process.ProcessName;
                var processPath = "";

                try
                {
                    processPath = process.MainModule?.FileName;
                }
                catch { }
                
                var sessionId = process.SessionId;
                var processOwner = GetProcessOwner(process);
                var processArch = RuntimeInformation.ProcessArchitecture;

                results.Add(new ProcessResult
                {
                    Pid = processId,
                    Ppid = parentProcessId,
                    Name = processName,
                    Path = processPath,
                    SessionId = sessionId,
                    Owner = processOwner,
                    Architecture = processArch
                });
            }

            return results;
        }

        /// <summary>
        /// Gets the parent process id of a process handle
        /// </summary>
        /// <author>Daniel Duggan (@_RastaMouse)</author>
        /// <param name="hProcess">Handle to the process to get the parent process id of</param>
        /// <returns>Parent Process Id</returns>
        private static int GetParentProcess(IntPtr hProcess)
        {
#if Windows
            var bpi = new Native.PROCESS_BASIC_INFORMATION();
            var pProcInfo = Marshal.AllocHGlobal(Marshal.SizeOf(bpi));
            Marshal.StructureToPtr(bpi, pProcInfo, true);
            PInvoke.Native.NtQueryInformationProcess(hProcess, Native.PROCESSINFOCLASS.ProcessBasicInformation, pProcInfo, Marshal.SizeOf(bpi), out _);
            bpi = (Native.PROCESS_BASIC_INFORMATION) Marshal.PtrToStructure(pProcInfo, typeof(Native.PROCESS_BASIC_INFORMATION));

            return bpi.InheritedFromUniqueProcessId;
#endif

            return 0;
        }

        /// <summary>
        /// Gets the username of the owner of a process
        /// </summary>
        /// <author>Daniel Duggan (@_RastaMouse)</author>
        /// <param name="process">Process to get owner of</param>
        /// <returns>Username of process owner. Returns empty string if unsuccessful.</returns>
        public static string GetProcessOwner(Process process)
        {
            #if Windows
            try
            {
                PInvoke.Win32.Kernel32.OpenProcessToken(process.Handle, 8, out var handle);
                using var winIdentity = new WindowsIdentity(handle);
                return winIdentity.Name;
            }
            catch
            {
                // ignore, probably access denied
            }
            #endif

            return string.Empty;
        }
        
        /// <summary>
        /// Gets a directory listing of a directory.
        /// </summary>
        /// <param name="path">The path of the directory to get a listing of.</param>
        /// <returns>CoreSploitResultList of FileSystemEntryResults.</returns>
        public static CoreSploitResultList<FileSystemEntryResult> GetDirectoryListing(string path)
        {
            var results = new CoreSploitResultList<FileSystemEntryResult>();
            
            foreach (var dir in Directory.GetDirectories(path))
            {
                var dirInfo = new DirectoryInfo(dir);
                
                results.Add(new FileSystemEntryResult
                {
                    Name = dirInfo.FullName,
                    Length = 0,
                    CreationTimeUtc = dirInfo.CreationTimeUtc,
                    LastAccessTimeUtc = dirInfo.LastAccessTimeUtc,
                    LastWriteTimeUtc = dirInfo.LastWriteTimeUtc
                });
            }
            
            foreach (var file in Directory.GetFiles(path))
            {
                var fileInfo = new FileInfo(file);
                
                results.Add(new FileSystemEntryResult
                {
                    Name = fileInfo.FullName,
                    Length = fileInfo.Length,
                    CreationTimeUtc = fileInfo.CreationTimeUtc,
                    LastAccessTimeUtc = fileInfo.LastAccessTimeUtc,
                    LastWriteTimeUtc = fileInfo.LastWriteTimeUtc
                });
            }
            
            return results;
        }

        /// <summary>
        /// Changes the current working directory.
        /// </summary>
        /// <param name="directoryName">Relative or absolute path to new working directory.</param>
        public static void ChangeCurrentDirectory(string directoryName)
        {
            Directory.SetCurrentDirectory(directoryName);
        }
        
        /// <summary>
        /// Gets the hostname of the system.
        /// </summary>
        /// <returns>Hostname of the system.</returns>
        public static string GetHostname()
        {
            return Environment.MachineName;
        }

        /// <summary>
        /// Gets the Domain name and username of the current logged on user.
        /// </summary>
        /// <returns>Current username.</returns>
        public static string GetUsername()
        {
            return Environment.UserDomainName + "\\" + Environment.UserName;
        }

        /// <summary>
        /// Take a screenshot of the current desktop
        /// </summary>
        /// <param name="width">Width in pixels</param>
        /// <param name="height">Height in pixels</param>
        /// <returns></returns>
        public static byte[] TakeScreenshot(int width, int height)
        {
            //ex.) 1920 x 1080
            using var bitmap = new Bitmap(width, height);
            using (var g = Graphics.FromImage(bitmap))
            {
                g.CopyFromScreen(0, 0, 0, 0,
                bitmap.Size, CopyPixelOperation.SourceCopy);
            }
            using (var stream = new MemoryStream())
            {
                bitmap.Save(stream, System.Drawing.Imaging.ImageFormat.Jpeg);
                return stream.ToArray();
            }
        }

        public sealed class ProcessResult : CoreSploitResult
        {
            public int Pid { get; set; }
            public int Ppid { get; set; }
            public string Name { get; set; } = "";
            public string Path { get; set; } = "";
            public int SessionId { get; set; }
            public string Owner { get; set; } = "";
            public Architecture Architecture { get; set; }

            protected internal override IList<CoreSploitResultProperty> ResultProperties =>
                new List<CoreSploitResultProperty>
                {
                    new() {Name = "Pid", Value = Pid},
                    new() {Name = "Ppid", Value = Ppid},
                    new() {Name = "Name", Value = Name},
                    new() {Name = "SessionID", Value = SessionId},
                    new() {Name = "Owner", Value = Owner},
                    new() {Name = "Architecture", Value = Architecture},
                    new() {Name = "Path", Value = Path}
                };
        }

        /// <summary>
        /// FileSystemEntryResult represents a file on disk, used with the GetDirectoryListing() function.
        /// </summary>
        public sealed class FileSystemEntryResult : CoreSploitResult
        {
            public string Name { get; set; } = "";
            public long Length { get; set; }
            public DateTime CreationTimeUtc { get; set; }
            public DateTime LastAccessTimeUtc { get; set; }
            public DateTime LastWriteTimeUtc { get; set; }

            protected internal override IList<CoreSploitResultProperty> ResultProperties =>
                new List<CoreSploitResultProperty>
                {
                    new() {Name = "Name", Value = Name},
                    new() {Name = "Length", Value = Length},
                    new() {Name = "CreationTimeUtc", Value = CreationTimeUtc},
                    new() {Name = "LastAccessTimeUtc", Value = LastAccessTimeUtc},
                    new() {Name = "LastWriteTimeUtc", Value = LastWriteTimeUtc}
                };
        }
    }
    
    /// <summary>
    /// Net is a library for localgroup/domain enumeration that can be used to search for users, groups, loggedonusers,
    /// and sessions on remote systems using Win32 API functions.
    /// </summary>
    /// <remarks>
    /// Net is adapted from Will Schroeder's (@harmj0y) PowerView. (Found
    /// at https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1)
    /// Further Adapted for Coresploit from SharpSploit by (@cobbr)
    /// at https://github.com/cobbr/SharpSploit/
    /// </remarks>
    public static class Net
    {
        /// <summary>
        /// LocalGroup represents a local group object on a remote system.
        /// </summary>
        public class LocalGroup
        {
            public string ComputerName { get; set; } = "";
            public string GroupName { get; set; } = "";
            public string Comment { get; set; } = "";

            public override string ToString()
            {
                var output = "";
                output += "ComputerName: " + ComputerName + Environment.NewLine;
                output += "GroupName: " + GroupName + Environment.NewLine;
                output += "Comment: " + Comment + Environment.NewLine;
                return output;
            }
        }

        /// <summary>
        /// LocalGroupMember represents a user's membership to a local group on a remote system.
        /// </summary>
        public class LocalGroupMember
        {
            public string ComputerName { get; set; } = "";
            public string GroupName { get; set; } = "";
            public string MemberName { get; set; } = "";
            public string SID { get; set; } = "";
            public bool IsGroup { get; set; } = false;
            public bool IsDomain { get; set; } = false;

            public override string ToString()
            {
                var output = "";
                if (ComputerName.Trim() != "") { output += "ComputerName: " + ComputerName + Environment.NewLine; }
                if (MemberName.Trim() != "") { output += "MemberName: " + MemberName + Environment.NewLine; }
                if (SID.Trim() != "") { output += "SID: " + SID + Environment.NewLine; }
                if (IsGroup.ToString().Trim() != "") { output += "IsGroup: " + IsGroup + Environment.NewLine; }
                if (IsDomain.ToString().Trim() != "") { output += "IsDomain: " + IsDomain + Environment.NewLine; }

                return output;
            }
        }

        /// <summary>
        /// Gets a list of `LocalGroup`s from a specified DomainCompter.
        /// </summary>
        /// <param name="DomainComputer">DomainComputer to query for LocalGroups.</param>
        /// <param name="Credential">Credential to use for authentication to the DomainComputer.</param>
        /// <returns>List of LocalGroups.</returns>
        public static List<LocalGroup> GetNetLocalGroups(Domain.DomainObject DomainComputer)
        {
            var ComputerNames = new List<string>();
            if (DomainComputer != null && DomainComputer.samaccounttype == Domain.SamAccountTypeEnum.MACHINE_ACCOUNT)
            {
                ComputerNames.Add(DomainComputer.cn);
            }
            return ComputerNames.Count == 0 ? new List<LocalGroup>() : GetNetLocalGroups(ComputerNames);
        }
        /// <summary>
        /// Gets a list of `LocalGroup`s from specified DomainComputers.
        /// </summary>
        /// <param name="DomainComputers">List of DomainComputers to query for LocalGroups.</param>
        /// <param name="Credential">Credential to use for authentication to the DomainComputer.</param>
        /// <returns>List of LocalGroups.</returns>
        public static List<LocalGroup> GetNetLocalGroups(IEnumerable<Domain.DomainObject> DomainComputers)
        {
            var ComputerNames = new List<string>();
            foreach (var DomainComputer in DomainComputers)
            {
                if (DomainComputer != null && DomainComputer.samaccounttype == Domain.SamAccountTypeEnum.MACHINE_ACCOUNT)
                {
                    ComputerNames.Add(DomainComputer.cn);
                }
            }
            return ComputerNames.Count == 0 ? new List<LocalGroup>() : GetNetLocalGroups(ComputerNames);
        }
        /// <summary>
        /// Gets a list of `LocalGroup`s from specified remote computer(s).
        /// </summary>
        /// <param name="ComputerName">ComputerName to query for LocalGroups.</param>
        /// <param name="Credential">Credential to use for authentication to the ComputerName.</param>
        /// <returns>List of LocalGroups.</returns>
        public static List<LocalGroup> GetNetLocalGroups(string ComputerName = "127.0.0.1")
        {
            return ComputerName == null ? new List<LocalGroup>() : GetNetLocalGroups(new List<string> { ComputerName });
        }

        /// <summary>
        /// Gets a list of `LocalGroup`s from specified remote computer(s).
        /// </summary>
        /// <param name="ComputerNames">List of ComputerNames to query for LocalGroups.</param>
        /// <param name="Credential">Credential to use for authentication to the ComputerNames.</param>
        /// <returns>List of LocalGroups.</returns>
        public static List<LocalGroup> GetNetLocalGroups(IEnumerable<string> ComputerNames)
        {
            ComputerNames = ComputerNames.Where(CN => CN != null);
            var localGroups = new List<LocalGroup>();




            //Old Code Let's see if we can update it.
            /**
            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX) || RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                foreach (string ComputerName in ComputerNames)
                {
                    foreach (var Groupline in File.ReadAllLines("/etc/group"))
                    {
                        string[] GroupSplit = Groupline.Split(':');
                        string GroupName = GroupSplit[0];

                        localGroups.Add(
                        new LocalGroup
                        {
                            ComputerName = ComputerName,
                            GroupName = GroupName,
                            Comment = ""
                        }
                    );

                    }
                }
                return localGroups;
               **/
            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX) || RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                var c = "root";
                Linux.getgrouplist(c, 0, 0, 0);
            }   
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                foreach (var ComputerName in ComputerNames)
                {
                    var QueryLevel = 1;
                    var PtrInfo = IntPtr.Zero;
                    var EntriesRead = 0;
                    var TotalRead = 0;
                    var ResumeHandle = 0;
                    var Result = Win32.Netapi32.NetLocalGroupEnum(ComputerName, QueryLevel, out PtrInfo, -1, out EntriesRead, out TotalRead, ref ResumeHandle);
                    var Offset = PtrInfo.ToInt64();
                    if (Result == 0 && Offset > 0)
                    {
                        var increment = Marshal.SizeOf(typeof(Win32.Netapi32.LOCALGROUP_USERS_INFO_1));
                        for (var i = 0; i < EntriesRead; i++)
                        {
                            var NextIntPtr = new IntPtr(Offset);
                            var Info = (Win32.Netapi32.LOCALGROUP_USERS_INFO_1)Marshal.PtrToStructure(NextIntPtr, typeof(Win32.Netapi32.LOCALGROUP_USERS_INFO_1));
                            Offset = NextIntPtr.ToInt64();
                            Offset += increment;
                            localGroups.Add(
                                new LocalGroup
                                {
                                    ComputerName = ComputerName,
                                    GroupName = Info.name,
                                    Comment = Info.comment
                                }
                            );
                        }
                        Win32.Netapi32.NetApiBufferFree(PtrInfo);
                    }
                    else
                    {
                        Console.Error.WriteLine("Error: " + new Win32Exception(Result).Message);
                    }
                }
                return localGroups;
            }
             return new List<LocalGroup>();
            
        }
    }
}
