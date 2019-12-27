using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;
using CoreSploit.Generic;

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
            Platform processorArchitecture = Platform.Unknown;
            if (System.Environment.Is64BitOperatingSystem)
            {
                processorArchitecture = Platform.x64;
            }
            else
            {
                processorArchitecture = Platform.x86;
            }
            Process[] processes = Process.GetProcesses().OrderBy(P => P.Id).ToArray();
            CoreSploitResultList<ProcessResult> results = new CoreSploitResultList<ProcessResult>();
            foreach (Process process in processes)
            {
                int processId = process.Id;
                int parentProcessId = 0;
                string processName = process.ProcessName;
                string processPath = string.Empty;
                int sessionId = process.SessionId;
                //string processOwner = GetProcessOwner(process);
                Platform processArch = Platform.Unknown;

                if (parentProcessId != 0)
                {
                    try
                    {
                        processPath = process.MainModule.FileName;
                    }
                    catch (System.ComponentModel.Win32Exception) { }
                }
                /**
                if (processorArchitecture == Platform.x64)
                {
                    processArch = IsWow64(process) ? Win32.Kernel32.Platform.x86 : Win32.Kernel32.Platform.x64;
                }
                else if (processorArchitecture == Win32.Kernel32.Platform.x86)
                {
                    processArch = Win32.Kernel32.Platform.x86;
                }
                else if (processorArchitecture == Win32.Kernel32.Platform.IA64)
                {
                    processArch = "x86";
                }
                **/
                results.Add(new ProcessResult
                {
                    Pid = processId,
                    Ppid = parentProcessId,
                    Name = processName,
                    Path = processPath,
                    SessionID = sessionId,
                    //Owner = processOwner,
                    //Architecture = processArch
                });
            }
            return results;
        }


        /// <summary>
        /// Gets a directory listing of a directory.
        /// </summary>
        /// <param name="Path">The path of the directory to get a listing of.</param>
        /// <returns>CoreSploitResultList of FileSystemEntryResults.</returns>
        public static CoreSploitResultList<FileSystemEntryResult> GetDirectoryListing(string Path)
        {
            CoreSploitResultList<FileSystemEntryResult> results = new CoreSploitResultList<FileSystemEntryResult>();
            foreach (string dir in Directory.GetDirectories(Path))
            {
                DirectoryInfo dirInfo = new DirectoryInfo(dir);
                results.Add(new FileSystemEntryResult
                {
                    Name = dirInfo.FullName,
                    Length = 0,
                    CreationTimeUtc = dirInfo.CreationTimeUtc,
                    LastAccessTimeUtc = dirInfo.LastAccessTimeUtc,
                    LastWriteTimeUtc = dirInfo.LastWriteTimeUtc
                });
            }
            foreach (string file in Directory.GetFiles(Path))
            {
                FileInfo fileInfo = new FileInfo(file);
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
        /// <param name="DirectoryName">Relative or absolute path to new working directory.</param>
        public static void ChangeCurrentDirectory(string DirectoryName)
        {
            Directory.SetCurrentDirectory(DirectoryName);
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



        public sealed class ProcessResult : CoreSploitResult
        {
            public int Pid { get; set; } = 0;
            public int Ppid { get; set; } = 0;
            public string Name { get; set; } = "";
            public string Path { get; set; } = "";
            public int SessionID { get; set; } = 0;
            //public string Owner { get; set; } = "";
            //public string Architecture { get; set; } = "unkonwn";
            protected internal override IList<CoreSploitResultProperty> ResultProperties
            {
                get
                {
                    return new List<CoreSploitResultProperty> {
                        new CoreSploitResultProperty { Name = "Pid", Value = this.Pid },
                        new CoreSploitResultProperty { Name = "Ppid", Value = this.Ppid },
                        new CoreSploitResultProperty { Name = "Name", Value = this.Name },
                        new CoreSploitResultProperty { Name = "SessionID", Value = this.SessionID },
                        //new CoreSploitResultProperty { Name = "Owner", Value = this.Owner },
                        //new CoreSploitResultProperty { Name = "Architecture", Value = this.Architecture },
                        new CoreSploitResultProperty { Name = "Path", Value = this.Path }
                    };
                }
            }
        }

        /// <summary>
        /// FileSystemEntryResult represents a file on disk, used with the GetDirectoryListing() function.
        /// </summary>
        public sealed class FileSystemEntryResult : CoreSploitResult
        {
            public string Name { get; set; } = "";
            public long Length { get; set; } = 0;
            public DateTime CreationTimeUtc { get; set; } = new DateTime();
            public DateTime LastAccessTimeUtc { get; set; } = new DateTime();
            public DateTime LastWriteTimeUtc { get; set; } = new DateTime();
            protected internal override IList<CoreSploitResultProperty> ResultProperties
            {
                get
                {
                    return new List<CoreSploitResultProperty>
                    {
                        new CoreSploitResultProperty
                        {
                            Name = "Name",
                            Value = this.Name
                        },
                        new CoreSploitResultProperty
                        {
                            Name = "Length",
                            Value = this.Length
                        },
                        new CoreSploitResultProperty
                        {
                            Name = "CreationTimeUtc",
                            Value = this.CreationTimeUtc
                        },
                        new CoreSploitResultProperty
                        {
                            Name = "LastAccessTimeUtc",
                            Value = this.LastAccessTimeUtc
                        },
                        new CoreSploitResultProperty
                        {
                            Name = "LastWriteTimeUtc",
                            Value = this.LastWriteTimeUtc
                        }
                    };
                }
            }
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
                string output = "";
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
                string output = "";
                if (this.ComputerName.Trim() != "") { output += "ComputerName: " + ComputerName + Environment.NewLine; }
                if (this.MemberName.Trim() != "") { output += "MemberName: " + MemberName + Environment.NewLine; }
                if (this.SID.Trim() != "") { output += "SID: " + SID + Environment.NewLine; }
                if (this.IsGroup.ToString().Trim() != "") { output += "IsGroup: " + IsGroup + Environment.NewLine; }
                if (this.IsDomain.ToString().Trim() != "") { output += "IsDomain: " + IsDomain + Environment.NewLine; }

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
            List<string> ComputerNames = new List<string>();
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
            List<string> ComputerNames = new List<string>();
            foreach (Domain.DomainObject DomainComputer in DomainComputers)
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
            List<LocalGroup> localGroups = new List<LocalGroup>();
            
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
                
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                /**
                foreach (string ComputerName in ComputerNames)
                {
                    int QueryLevel = 1;
                    IntPtr PtrInfo = IntPtr.Zero;
                    int EntriesRead = 0;
                    int TotalRead = 0;
                    int ResumeHandle = 0;
                    int Result = PInvoke.Win32.Netapi32.NetLocalGroupEnum(ComputerName, QueryLevel, out PtrInfo, -1, out EntriesRead, out TotalRead, ref ResumeHandle);
                    long Offset = PtrInfo.ToInt64();
                    if (Result == 0 && Offset > 0)
                    {
                        int increment = Marshal.SizeOf(typeof(Win32.Netapi32.LOCALGROUP_USERS_INFO_1));
                        for (int i = 0; i < EntriesRead; i++)
                        {
                            IntPtr NextIntPtr = new IntPtr(Offset);
                            Win32.Netapi32.LOCALGROUP_USERS_INFO_1 Info = (Win32.Netapi32.LOCALGROUP_USERS_INFO_1)Marshal.PtrToStructure(NextIntPtr, typeof(Win32.Netapi32.LOCALGROUP_USERS_INFO_1));
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
                        PInvoke.Win32.Netapi32.NetApiBufferFree(PtrInfo);
                    }
                    else
                    {
                        Console.Error.WriteLine("Error: " + new System.ComponentModel.Win32Exception(Result).Message);
                    }
                }
                return localGroups;
                **/
            }
             return new List<LocalGroup>();
            
        }
    }
}
