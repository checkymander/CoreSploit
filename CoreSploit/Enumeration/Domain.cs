﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.DirectoryServices.Protocols;
using System.Net;
using System.DirectoryServices;
using System.Text.RegularExpressions;
using System.Security.AccessControl;
using System.Runtime.InteropServices;

namespace CoreSploit.Enumeration
{
    public class Domain
    {
        public enum NameType
        {
            DN = 1,
            Canonical = 2,
            NT4 = 3,
            Display = 4,
            DomainSimple = 5,
            EnterpriseSimple = 6,
            GUID = 7,
            Unknown = 8,
            UPN = 9,
            CanonicalEx = 10,
            SPN = 11,
            SID = 12
        }
        public enum SamAccountTypeEnum : uint
        {
            DOMAIN_OBJECT = 0x00000000,
            GROUP_OBJECT = 0x10000000,
            NON_SECURITY_GROUP_OBJECT = 0x10000001,
            ALIAS_OBJECT = 0x20000000,
            NON_SECURITY_ALIAS_OBJECT = 0x20000001,
            USER_OBJECT = 0x30000000,
            MACHINE_ACCOUNT = 0x30000001,
            TRUST_ACCOUNT = 0x30000002,
            APP_BASIC_GROUP = 0x40000000,
            APP_QUERY_GROUP = 0x40000001,
            ACCOUNT_TYPE_MAX = 0x7fffffff
        }
        [Flags]
        public enum GroupTypeEnum : uint
        {
            CREATED_BY_SYSTEM = 0x00000001,
            GLOBAL_SCOPE = 0x00000002,
            DOMAIN_LOCAL_SCOPE = 0x00000004,
            UNIVERSAL_SCOPE = 0x00000008,
            APP_BASIC = 0x00000010,
            APP_QUERY = 0x00000020,
            SECURITY = 0x80000000
        }
        [Flags]
        public enum UACEnum : uint
        {
            SCRIPT = 1,
            ACCOUNTDISABLE = 2,
            HOMEDIR_REQUIRED = 8,
            LOCKOUT = 16,
            PASSWD_NOTREQD = 32,
            PASSWD_CANT_CHANGE = 64,
            ENCRYPTED_TEXT_PWD_ALLOWED = 128,
            TEMP_DUPLICATE_ACCOUNT = 256,
            NORMAL_ACCOUNT = 512,
            INTERDOMAIN_TRUST_ACCOUNT = 2048,
            WORKSTATION_TRUST_ACCOUNT = 4096,
            SERVER_TRUST_ACCOUNT = 8192,
            DONT_EXPIRE_PASSWORD = 65536,
            MNS_LOGON_ACCOUNT = 131072,
            SMARTCARD_REQUIRED = 262144,
            TRUSTED_FOR_DELEGATION = 524288,
            NOT_DELEGATED = 1048576,
            USE_DES_KEY_ONLY = 2097152,
            DONT_REQ_PREAUTH = 4194304,
            PASSWORD_EXPIRED = 8388608,
            TRUSTED_TO_AUTH_FOR_DELEGATION = 16777216,
            PARTIAL_SECRETS_ACCOUNT = 67108864
        }
        public enum DomainObjectType
        {
            User,
            Group,
            Computer
        }
        public class DomainSearcher
        {
            public Credential Credentials { get; set; } = null;
            private string Domain { get; set; }
            private string Server { get; set; }
            private LdapConnection ldapConnection { get; set; }
            private string SearchBase { get; set; }


            /// <summary>
            /// Constructor for the DomainSearcher class.
            /// </summary>
            /// <param name="Credentials">Optional alternative Credentials to authenticate to the Domain.</param>
            /// <param name="Domain">Optional alternative Domain to authenticate to and search.</param>
            /// <param name="Server">Optional alternative Server within the Domain to authenticate to and search.</param>
            /// <param name="SearchBase">Optional SearchBase to prepend to all LDAP searches.</param>
            /// <param name="SearchString">Optional SearchString to append to SearchBase for all LDAP searches.</param>
            /// <param name="SearchScope">Optional SearchScope for the underlying DirectorySearcher object.</param>
            /// <param name="ResultPageSize">Optional ResultPageSize for the underlying DirectorySearcher object.</param>
            /// <param name="ServerTimeLimit">Optional max time limit for the server per search.</param>
            /// <param name="TombStone">Optionally retrieve deleted/tombstoned DomainObjects</param>
            /// <param name="SecurityMasks">Optional SecurityMasks for the underlying DirectorySearcher object.</param>
            public DomainSearcher(Credential Credentials = null, string Domain = "", string Server = "", string SearchBase = "", string SearchString = "", System.DirectoryServices.Protocols.SearchScope SearchScope = System.DirectoryServices.Protocols.SearchScope.Subtree,
                int ResultPageSize = 200, TimeSpan ServerTimeLimit = default(TimeSpan), bool TombStone = false, System.DirectoryServices.Protocols.SecurityMasks SecurityMasks = System.DirectoryServices.Protocols.SecurityMasks.None, int PortNum = 389)
            {
                this.Domain = Domain;
                this.Server = Server;
                this.Credentials = Credentials;
                this.SearchBase = SearchBase;
                if (this.Domain == "")
                {
                    this.Domain = Environment.UserDomainName;
                }
                if (this.Server == "")
                {
                    string logonserver = Environment.GetEnvironmentVariable("logonserver");
                    this.Server = logonserver.Replace("\\", "") + this.Domain;
                }
                if (SearchBase == "")
                {
                    this.SearchBase = this.GetBaseDN();
                }
                else
                {
                    this.SearchBase = SearchBase;
                }

                this.Credentials = Credentials;
                if (this.Credentials == null)
                {
                    //this.ldapConnection = new LdapConnection("meteor.gaia.local");
                    this.ldapConnection = new LdapConnection(this.Server);
                }
                else
                {
                    //NetworkCredential cred = new NetworkCredential("meteor\\checkymander", "P@ssw0rd"); //Only works as domain\\user or user@domain
                    NetworkCredential cred = new NetworkCredential(this.Credentials.UserName, this.Credentials.Password);
                    LdapDirectoryIdentifier ldi = new LdapDirectoryIdentifier(this.Server, PortNum);
                    this.ldapConnection = new LdapConnection(ldi,cred);
                    this.ldapConnection.Credential = cred;
                }
            }

            /// <summary>
            /// Gets a specified user `DomainObject` in the current Domain.
            /// </summary>
            /// <param name="Identity">Username to search for.</param>
            /// <param name="LDAPFilter">Optional LDAP filter to apply to the search.</param>
            /// <param name="Properties">Optional list of properties to retrieve from the DomainObject.
            /// If not specified, all properties are included.</param>
            /// <param name="UACFilter">Optional filter to parse the userAccountControl DomainObject property.</param>
            /// <param name="SPN">Optionally filter for only a DomainObject with an SPN set.</param>
            /// <param name="AllowDelegation">Optionally filter for only a DomainObject that allows for delegation.</param>
            /// <param name="DisallowDelegation">Optionally filter for only a DomainObject that does not allow for delegation.</param>
            /// <param name="AdminCount">Optionally filter for only a DomainObject with the AdminCount property set.</param>
            /// <param name="TrustedToAuth">Optionally filter for only a DomainObject that is trusted to authenticate for other DomainObjects</param>
            /// <param name="PreauthNotRequired">Optionally filter for only a DomainObject does not require Kerberos preauthentication.</param>
            /// <returns>Matching user DomainObject</returns>
            public DomainObject GetDomainUser(string Identity, string LDAPFilter = "", IEnumerable<string> Properties = null, IEnumerable<UACEnum> UACFilter = null, bool SPN = false, bool AllowDelegation = false, bool DisallowDelegation = false, bool AdminCount = false, bool TrustedToAuth = false, bool PreauthNotRequired = false)
            {
                Console.WriteLine("GetDomainUser: " + Identity);
                return this.GetDomainUsers(new List<string> { Identity }, LDAPFilter, Properties, UACFilter, SPN, AllowDelegation, DisallowDelegation, AdminCount, TrustedToAuth, PreauthNotRequired, true).FirstOrDefault();
            }


            public List<DomainObject> GetDomainUsers(IEnumerable<string> Identities = null, string LDAPFilter = "", IEnumerable<string> Properties = null, IEnumerable<UACEnum> UACFilter = null, bool SPN = false, bool AllowDelegation = false, bool DisallowDelegation = false, bool AdminCount = false, bool TrustedToAuth = false, bool PreauthNotRequired = false, bool FindOne = false)
            {
                string Filter = "";
                string IdentityFilter = ConvertIdentitiesToFilter(Identities);
                string[] Attributes = null;
                if (IdentityFilter != null && IdentityFilter.Trim() != "")
                {
                    Filter += "(|" + IdentityFilter + ")";
                }
                if (SPN)
                {
                    Filter += "(servicePrincipalName=*)";
                }
                if (AllowDelegation)
                {
                    Filter += "(!(userAccountControl:1.2.840.113556.1.4.803:=1048574))";
                }
                if (DisallowDelegation)
                {
                    Filter += "(userAccountControl:1.2.840.113556.1.4.803:=1048574)";
                }
                if (AdminCount)
                {
                    Filter += "(admincount=1)";
                }
                if (TrustedToAuth)
                {
                    Filter += "(msds-allowedtodelegateto=*)";
                }
                if (PreauthNotRequired)
                {
                    Filter += "(userAccountControl:1.2.840.113556.1.4.803:=4194304)";
                }
                if (UACFilter != null)
                {
                    foreach (UACEnum uac in UACFilter)
                    {
                        Filter += "(userAccountControl:1.2.840.113556.1.4.803:=" + ((int)uac) + ")";
                    }
                }
                if (Properties != null)
                {
                    Attributes = Properties.ToArray();
                }
                //Going to need to figure out why the base SearchBase fails.
                if (SearchBase == GetBaseDN())
                {
                    SearchBase = "CN=Users," + SearchBase;
                }
                Filter += LDAPFilter;
                Filter = "(&(samAccountType=805306368)" + Filter + ")";
                /**
                Console.WriteLine("SearchBase: {0}", SearchBase);
                Console.WriteLine("UserName: {0}", this.Credentials.UserName);
                Console.WriteLine("Password: {0}", this.Credentials.Password);
                Console.WriteLine("Filter: {0}", Filter);
                Console.WriteLine("Domain: {0}", this.Domain);
                Console.WriteLine("Server: {0}", this.Server);
                **/
                try
                {
                    SearchRequest request = new SearchRequest(SearchBase, Filter, System.DirectoryServices.Protocols.SearchScope.Subtree, Attributes);
                    SearchResponse response = (SearchResponse)this.ldapConnection.SendRequest(request);
                    return ConvertSearchResultsToDomainObjects(response.Entries);
                }
                catch (Exception e)
                {
                    Console.Error.WriteLine("Exception: Can't construct Domain Searcher: " + e.Message + e.StackTrace);
                }
                return new List<DomainObject>();
            }

            /// <summary>
            /// Gets a specified group `DomainObject` in the current Domain.
            /// </summary>
            /// <param name="Identity">Group name to search for.</param>
            /// <param name="LDAPFilter">Optional LDAP filter to apply to the search.</param>
            /// <param name="Properties">Optional list of properties to retrieve from the DomainObject.
            /// If not specified, all properties are included.</param>
            /// <param name="AdminCount">Optionally filter for only a DomainObject with the AdminCount property set.</param>
            /// <param name="GroupScope">Optionally filter for a GroupScope (DomainLocal, Global, Universal, etc).</param>
            /// <param name="GroupProperty">Optionally filter for a GroupProperty (Security, Distribution, CreatedBySystem,
            /// NotCreatedBySystem,etc)</param>
            /// <returns>Matching group DomainObject</returns>
            public DomainObject GetDomainGroup(string Identity, string LDAPFilter = "", IEnumerable<string> Properties = null, bool AdminCount = false, string GroupScope = "", string GroupProperty = "")
            {
                return this.GetDomainGroups(new List<string> { Identity }, LDAPFilter, Properties, AdminCount, GroupScope, GroupProperty, true).FirstOrDefault();
            }


            /// <summary>
            /// Gets a list of specified (or all) group `DomainObject`s in the current Domain.
            /// </summary>
            /// <param name="Identities">Optional list of group names to search for.</param>
            /// <param name="LDAPFilter">Optional LDAP filter to apply to the search.</param>
            /// <param name="Properties">Optional list of properties to retrieve from the DomainObject.
            /// If not specified, all properties are included.</param>
            /// <param name="AdminCount">Optionally filter for only a DomainObject with the AdminCount property set.</param>
            /// <param name="GroupScope">Optionally filter for a GroupScope (DomainLocal, Global, Universal, etc).</param>
            /// <param name="GroupProperty">Optionally filter for a GroupProperty (Security, Distribution, CreatedBySystem,
            /// NotCreatedBySystem,etc).</param>
            /// <param name="FindOne">Optionally find only the first matching DomainObject.</param>
            /// <returns>List of matching group DomainObjects</returns>
            public List<DomainObject> GetDomainGroups(IEnumerable<string> Identities = null, string LDAPFilter = "", IEnumerable<string> Properties = null, bool AdminCount = false, string GroupScope = "", string GroupProperty = "", bool FindOne = false)
            {
                string Filter = "";
                string IdentityFilter = ConvertIdentitiesToFilter(Identities);
                string[] Attributes = null;

                if (IdentityFilter != null && IdentityFilter.Trim() != "")
                {
                    Filter += "(|" + IdentityFilter + ")";
                }
                if (AdminCount)
                {
                    Filter += "(admincount=1)";
                }
                if (GroupScope == "DomainLocal")
                {
                    Filter += "(groupType:1.2.840.113556.1.4.803:=4)";
                }
                else if (GroupScope == "NotDomainLocal")
                {
                    Filter += "(!(groupType:1.2.840.113556.1.4.803:=4))";
                }
                else if (GroupScope == "Global")
                {
                    Filter += "(groupType:1.2.840.113556.1.4.803:=2)";
                }
                else if (GroupScope == "NotGlobal")
                {
                    Filter += "(!(groupType:1.2.840.113556.1.4.803:=2))";
                }
                else if (GroupScope == "Universal")
                {
                    Filter += "(groupType:1.2.840.113556.1.4.803:=8)";
                }
                else if (GroupScope == "NotUniversal")
                {
                    Filter += "(!(groupType:1.2.840.113556.1.4.803:=8))";
                }

                if (GroupProperty == "Security")
                {
                    Filter += "(groupType:1.2.840.113556.1.4.803:=2147483648)";
                }
                else if (GroupProperty == "Distribution")
                {
                    Filter += "(!(groupType:1.2.840.113556.1.4.803:=2147483648))";
                }
                else if (GroupProperty == "CreatedBySystem")
                {
                    Filter += "(groupType:1.2.840.113556.1.4.803:=1)";
                }
                else if (GroupProperty == "NotCreatedBySystem")
                {
                    Filter += "(!(groupType:1.2.840.113556.1.4.803:=1))";
                }

                Filter += LDAPFilter;
                Filter = "(&(objectCategory=group)" + Filter + ")";

                if (Properties != null)
                {
                    Attributes = Properties.ToArray();
                }
                //Going to need to figure out why the base SearchBase fails.
                if (SearchBase == GetBaseDN())
                {
                    SearchBase = "CN=Users," + SearchBase;
                }

                SearchRequest request = new SearchRequest(SearchBase, Filter, System.DirectoryServices.Protocols.SearchScope.Subtree, Attributes);
                SearchResponse response = (SearchResponse)this.ldapConnection.SendRequest(request);
                try
                {
                    if (FindOne)
                    {
                        return ConvertSearchResultToDomainObject(response.Entries[0]);
                    }
                    else
                    {
                        return ConvertSearchResultsToDomainObjects(response.Entries);
                    }
                }
                catch (Exception e)
                {
                    Console.Error.WriteLine("Exception: Can't construct Domain Searcher: " + e.Message + e.StackTrace);
                }
                return new List<DomainObject>();
            }

            public DomainObject GetDomainComputer(string Identity, string LDAPFilter = "", IEnumerable<string> Properties = null, IEnumerable<UACEnum> UACFilter = null, bool Unconstrained = false, bool TrustedToAuth = false, bool Printers = false, string SPN = "", string OperatingSystem = "", string ServicePack = "", string SiteName = "", bool Ping = false)
            {
                return this.GetDomainComputers(new List<string> { Identity }, LDAPFilter, Properties, UACFilter, Unconstrained, TrustedToAuth, Printers, SPN, OperatingSystem, ServicePack, SiteName, Ping, true).FirstOrDefault();
            }

            /// <summary>
            ///  Gets a list of specified (or all) computer `DomainObject`s in the current Domain.
            /// </summary>
            /// <param name="Identities">Optional list of ComputerNames to search for.</param>
            /// <param name="LDAPFilter">Optional LDAP filter to apply to the search.</param>
            /// <param name="Properties">Optional list of properties to retrieve from the DomainObject.
            /// If not specified, all properties are included.</param>
            /// <param name="UACFilter">Optional filter to parse the userAccountControl DomainObject property.</param>
            /// <param name="Unconstrained">Optionally filter for only a DomainObject that has unconstrained delegation.</param>
            /// <param name="TrustedToAuth">Optionally filter for only a DomainObject that is trusted to authenticate for other DomainObjects</param>
            /// <param name="Printers">Optionally return only a DomainObject that is a printer.</param>
            /// <param name="SPN">Optionally filter for only a DomainObject with an SPN set.</param>
            /// <param name="OperatingSystem">Optionally filter for only a DomainObject with a specific Operating System, wildcards accepted.</param>
            /// <param name="ServicePack">Optionally filter for only a DomainObject with a specific service pack, wildcards accepted.</param>
            /// <param name="SiteName">Optionally filter for only a DomainObject in a specific Domain SiteName, wildcards accepted.</param>
            /// <param name="Ping">Optional switch, ping the computer to ensure it's up before enumerating.</param>
            /// <param name="FindOne">Optionally find only the first matching DomainObject.</param>
            /// <returns>List of matching computer DomainObjects</returns>
            public List<DomainObject> GetDomainComputers(IEnumerable<string> Identities = null, string LDAPFilter = "", IEnumerable<string> Properties = null, IEnumerable<UACEnum> UACFilter = null, bool Unconstrained = false, bool TrustedToAuth = false, bool Printers = false, string SPN = "", string OperatingSystem = "", string ServicePack = "", string SiteName = "", bool Ping = false, bool FindOne = false)
            {
                string Filter = "";
                string IdentityFilter = ConvertIdentitiesToFilter(Identities, DomainObjectType.Computer);
                string[] Attributes = null;
                if (IdentityFilter != null && IdentityFilter.Trim() != "")
                {
                    Filter += "(|" + IdentityFilter + ")";
                }

                if (Unconstrained)
                {
                    Filter += "(userAccountControl:1.2.840.113556.1.4.803:=524288)";
                }
                if (TrustedToAuth)
                {
                    Filter += "(msds-allowedtodelegateto=*)";
                }
                if (Printers)
                {
                    Filter += "(objectCategory=printQueue)";
                }
                if (SPN != "")
                {
                    Filter += "(servicePrincipalName=" + SPN + ")";
                }
                if (OperatingSystem != "")
                {
                    Filter += "(operatingsystem=" + OperatingSystem + ")";
                }
                if (ServicePack != "")
                {
                    Filter += "(operatingsystemservicepack=" + ServicePack + ")";
                }
                if (SiteName != "")
                {
                    Filter += "(serverreferencebl=" + SiteName + ")";
                }

                Filter += LDAPFilter;
                if (UACFilter != null)
                {
                    foreach (UACEnum uac in UACFilter)
                    {
                        Filter += "(userAccountControl:1.2.840.113556.1.4.803:=" + ((int)uac) + ")";
                    }
                }

                Filter = "(&(samAccountType=805306369)" + Filter + ")";

                List<SearchResult> results = new List<SearchResult>();
                if (Properties != null)
                {
                    Attributes = Properties.ToArray();
                }
                
                //Going to need to figure out why the base SearchBase fails.
                if (SearchBase == GetBaseDN())
                {
                    SearchBase = "CN=Computers," + SearchBase;
                }

                SearchRequest request = new SearchRequest(SearchBase, Filter, System.DirectoryServices.Protocols.SearchScope.Subtree, Attributes);
                SearchResponse response = (SearchResponse)this.ldapConnection.SendRequest(request);
                try
                {
                    if (FindOne)
                    {
                        return ConvertSearchResultToDomainObject(response.Entries[0]);
                    }
                    else
                    {
                        return ConvertSearchResultsToDomainObjects(response.Entries);
                    }
                }
                catch (Exception e)
                {
                    Console.Error.WriteLine("Exception: Can't construct Domain Searcher: " + e.Message + e.StackTrace);
                }
                return new List<DomainObject>();
            }


            private static List<DomainObject> ConvertSearchResultToDomainObject(SearchResultEntry Result)
            {
                List<DomainObject> ldaps = new List<DomainObject>();
                ldaps.Add(ConvertLDAPProperty(Result));
                return ldaps;
            }
            private static List<DomainObject> ConvertSearchResultsToDomainObjects(SearchResultEntryCollection Results)
            {
                List<DomainObject> ldaps = new List<DomainObject>();
                foreach (SearchResultEntry result in Results)
                {
                    ldaps.Add(ConvertLDAPProperty(result));
                }
                return ldaps;
            }

            private static DomainObject ConvertLDAPProperty(SearchResultEntry Result)
            {
                DomainObject ldap = new DomainObject();
                foreach (string PropertyName in Result.Attributes.AttributeNames)
                {
                    if (Result.Attributes[PropertyName].Count == 0) { continue; }
                    if (PropertyName == "objectsid")
                    {
                        //ldap.objectsid = new SecurityIdentifier((byte[])Result.Attributes["objectsid"][0], 0).Value;
                        ldap.objectsid = BitConverter.ToString((byte[])Result.Attributes["objectsid"][0], 0);
                    }
                    else if (PropertyName == "sidhistory")
                    {
                        List<string> historyListTemp = new List<string>();
                        foreach (byte[] bytes in Result.Attributes["sidhistory"])
                        {
                            //historyListTemp.Add(new SecurityIdentifier(bytes, 0).Value);
                            historyListTemp.Add(BitConverter.ToString(bytes));
                        }
                        ldap.sidhistory = historyListTemp.ToArray();
                    }
                    else if (PropertyName == "grouptype")
                    {
                        try { ldap.grouptype = (GroupTypeEnum)Enum.Parse(typeof(GroupTypeEnum), Result.Attributes["grouptype"][0].ToString()); }
                        catch (Exception) { }
                    }
                    else if (PropertyName == "samaccounttype")
                    {
                        try { ldap.samaccounttype = (SamAccountTypeEnum)Enum.Parse(typeof(SamAccountTypeEnum), Result.Attributes["samaccounttype"][0].ToString()); }
                        catch (Exception) { }
                    }
                    else if (PropertyName == "objectguid")
                    {
                        ldap.objectguid = new Guid((byte[])Result.Attributes["objectguid"][0]).ToString();
                    }
                    else if (PropertyName == "useraccountcontrol")
                    {
                        try { ldap.useraccountcontrol = (UACEnum)Enum.Parse(typeof(UACEnum), Result.Attributes["useraccountcontrol"][0].ToString()); }
                        catch (Exception) { }
                    }
                    else if (PropertyName == "ntsecuritydescriptor")
                    {
                        //ToFix
                        /**
                        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                        {
                            var desc = new RawSecurityDescriptor((byte[])Result.Attributes["ntsecuritydescriptor"][0], 0);
                            ldap.Owner = desc.Owner;
                            ldap.Group = desc.Group;
                            ldap.DiscretionaryAcl = desc.DiscretionaryAcl;
                            ldap.SystemAcl = desc.SystemAcl;
                        }
                        else
                        {

                        }
                        **/
                    }
                    else if (PropertyName == "accountexpires")
                    {
                        if (long.Parse(Result.Attributes["accountexpires"][0].ToString()) >= DateTime.MaxValue.Ticks)
                        {
                            ldap.accountexpires = DateTime.MaxValue;
                        }
                        try
                        {
                            //ldap.accountexpires = DateTime.FromFileTime((long)Result.Attributes["accountexpires"][0]);
                            ldap.accountexpires = DateTime.FromFileTime(long.Parse(Result.Attributes[PropertyName][0].ToString()));
                        }
                        catch (ArgumentOutOfRangeException)
                        {
                            ldap.accountexpires = DateTime.MaxValue;
                        }
                    }
                    else if (PropertyName == "lastlogon" || PropertyName == "lastlogontimestamp" || PropertyName == "pwdlastset" ||
                             PropertyName == "lastlogoff" || PropertyName == "badPasswordTime")
                    {
                        DateTime dateTime = DateTime.MinValue;
                        if (Result.Attributes[PropertyName][0].GetType().Name == "System.MarshalByRefObject")
                        {
                            var comobj = (MarshalByRefObject)Result.Attributes[PropertyName][0];
                            int high = (int)comobj.GetType().InvokeMember("HighPart", System.Reflection.BindingFlags.GetProperty, null, comobj, null);
                            int low = (int)comobj.GetType().InvokeMember("LowPart", System.Reflection.BindingFlags.GetProperty, null, comobj, null);
                            dateTime = DateTime.FromFileTime(long.Parse("0x" + high + "" + low, System.Globalization.NumberStyles.HexNumber));
                        }
                        else
                        {
                            dateTime = DateTime.FromFileTime(long.Parse(Result.Attributes[PropertyName][0].ToString()));

                        }
                        if (PropertyName == "lastlogon") { ldap.lastlogon = dateTime; }
                        else if (PropertyName == "lastlogontimestamp") { ldap.lastlogontimestamp = dateTime; }
                        else if (PropertyName == "pwdlastset") { ldap.pwdlastset = dateTime; }
                        else if (PropertyName == "lastlogoff") { ldap.lastlogoff = dateTime; }
                        else if (PropertyName == "badPasswordTime") { ldap.badpasswordtime = dateTime; }
                    }
                    else
                    {
                        string property = "0";
                        if (Result.Attributes[PropertyName][0].GetType().Name == "System.MarshalByRefObject")
                        {
                            var comobj = (MarshalByRefObject)Result.Attributes[PropertyName][0];
                            int high = (int)comobj.GetType().InvokeMember("HighPart", System.Reflection.BindingFlags.GetProperty, null, comobj, null);
                            int low = (int)comobj.GetType().InvokeMember("LowPart", System.Reflection.BindingFlags.GetProperty, null, comobj, null);
                            property = int.Parse("0x" + high + "" + low, System.Globalization.NumberStyles.HexNumber).ToString();
                        }
                        else if (Result.Attributes[PropertyName].Count == 1)
                        {
                            property = Result.Attributes[PropertyName][0].ToString();
                        }
                        else
                        {
                            List<string> propertyList = new List<string>();
                            foreach (object prop in Result.Attributes[PropertyName])
                            {
                                propertyList.Add(prop.ToString());
                            }
                            property = String.Join(", ", propertyList.ToArray());
                        }
                        if (PropertyName == "samaccountname") { ldap.samaccountname = property; }
                        else if (PropertyName == "distinguishedname") { ldap.distinguishedname = property; }
                        else if (PropertyName == "cn") { ldap.cn = property; }
                        else if (PropertyName == "admincount") { ldap.admincount = property; }
                        else if (PropertyName == "serviceprincipalname") { ldap.serviceprincipalname = property; }
                        else if (PropertyName == "name") { ldap.name = property; }
                        else if (PropertyName == "description") { ldap.description = property; }
                        else if (PropertyName == "memberof") {
                            foreach(byte[] group in Result.Attributes[PropertyName])
                            {
                                ldap.memberof += System.Text.Encoding.Default.GetString(group) + Environment.NewLine;
                            }
                            ldap.memberof = ldap.memberof.TrimEnd('\r','\n');
                        }
                        else if (PropertyName == "logoncount") { ldap.logoncount = property; }
                        else if (PropertyName == "badpwdcount") { ldap.badpwdcount = property; }
                        else if (PropertyName == "whencreated") { ldap.whencreated = property; }
                        else if (PropertyName == "whenchanged") { ldap.whenchanged = property; }
                        else if (PropertyName == "codepage") { ldap.codepage = property; }
                        else if (PropertyName == "objectcategory") { ldap.objectcategory = property; }
                        else if (PropertyName == "usnchanged") { ldap.usnchanged = property; }
                        else if (PropertyName == "instancetype") { ldap.instancetype = property; }
                        else if (PropertyName == "objectclass") { ldap.objectclass = property; }
                        else if (PropertyName == "iscriticalsystemobject") { ldap.iscriticalsystemobject = property; }
                        else if (PropertyName == "usncreated") { ldap.usncreated = property; }
                        else if (PropertyName == "dscorepropagationdata") { ldap.dscorepropagationdata = property; }
                        else if (PropertyName == "adspath") { ldap.adspath = property; }
                        else if (PropertyName == "countrycode") { ldap.countrycode = property; }
                        else if (PropertyName == "primarygroupid") { ldap.primarygroupid = property; }
                        else if (PropertyName == "msds_supportedencryptiontypes") { ldap.msds_supportedencryptiontypes = property; }
                        else if (PropertyName == "showinadvancedviewonly") { ldap.showinadvancedviewonly = property; }
                    }
                }
                return ldap;
            }

            private static string ConvertIdentitiesToFilter(IEnumerable<string> Identities, DomainObjectType ObjectType = DomainObjectType.User)
            {
                if (Identities == null) { return ""; }
                string IdentityFilter = "";
                foreach (string Identity in Identities)
                {
                    if (Identity == null || Identity == "") { continue; }
                    string IdentityInstance = Identity.Replace("(", "\\28").Replace(")", "\\29");
                    if (Regex.IsMatch(IdentityInstance, "^S-1-"))
                    {
                        IdentityFilter += "(objectsid=" + IdentityInstance + ")";
                    }
                    else if (Regex.IsMatch(IdentityInstance, "^CN="))
                    {
                        IdentityFilter += "(distinguishedname=" + IdentityInstance + ")";
                    }
                    else if (ObjectType == DomainObjectType.Computer && IdentityInstance.Contains("."))
                    {
                        IdentityFilter += "(|(name=" + IdentityInstance + ")(dnshostname=" + IdentityInstance + "))";
                    }
                    else if (Regex.IsMatch(IdentityInstance, "^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$"))
                    {
                        byte[] bytes = new Guid(IdentityInstance).ToByteArray();
                        string GuidByteString = "";
                        foreach (Byte b in bytes)
                        {
                            GuidByteString += "\\" + b.ToString("X2");
                        }
                        IdentityFilter += "(objectguid=" + GuidByteString + ")";
                    }
                    else if (ObjectType == DomainObjectType.User || ObjectType == DomainObjectType.Group)
                    {
                        if (IdentityInstance.Contains("\\"))
                        {
                            string ConvertedIdentityInstance = ConvertADName(IdentityInstance.Replace("\\28", "(").Replace("\\29", ")"));
                            if (ConvertedIdentityInstance != null && ConvertedIdentityInstance != "")
                            {
                                string UserDomain = ConvertedIdentityInstance.Substring(0, ConvertedIdentityInstance.IndexOf("/"));
                                string UserName = ConvertedIdentityInstance.Substring(0, ConvertedIdentityInstance.IndexOf("/"));
                                IdentityFilter += "(samAccountName=" + UserName + ")";
                            }
                        }
                        else if (ObjectType == DomainObjectType.User)
                        {
                            IdentityFilter += "(samAccountName=" + IdentityInstance + ")";
                        }
                        else if (ObjectType == DomainObjectType.Group)
                        {
                            IdentityFilter += "(|(samAccountName=" + IdentityInstance + ")(name=" + IdentityInstance + "))";
                        }
                    }
                    else if (ObjectType == DomainObjectType.Computer)
                    {
                        IdentityFilter += "(name=" + IdentityInstance + ")";
                    }
                }
                return IdentityFilter;
            }

            private static string ConvertADName(string Identity, NameType type = NameType.NT4, string domain = "")
            {
                //Convert from NT4 (DOMAIN\User) or domainSimple (user@domain.com) to canonical format (domain.com/Users/user)
                //It's really not possible to get the OU from this.
                string adname = "";
                switch (type)
                {
                    case NameType.NT4:
                        {
                            if (Identity.Contains('@'))
                            {
                                adname = domain + "\\" + Identity;
                            }
                            break;
                        }
                }

                return adname;
            }

            private string GetBaseDN()
            {
                return "DC=" + this.Domain.Replace(".", ",DC=");
            }
        }
        /// <summary>
        /// Generic DomainObject class for LDAP entries in Active Directory.
        /// </summary>
        public class DomainObject
        {
            public string samaccountname { get; set; }
            public SamAccountTypeEnum samaccounttype { get; set; }
            public string distinguishedname { get; set; }
            public string cn { get; set; }
            public string objectsid { get; set; }
            public string[] sidhistory { get; set; }
            public GroupTypeEnum grouptype { get; set; }
            //public SecurityIdentifier Owner { get; set; }
            //public SecurityIdentifier Group { get; set; }
            //public string Owner { get; set; }
            //public string Group { get; set; }
            public RawAcl DiscretionaryAcl { get; set; }
            public RawAcl SystemAcl { get; set; }

            public string admincount { get; set; }
            public string serviceprincipalname { get; set; }
            public string name { get; set; }
            public string description { get; set; }
            public string memberof { get; set; }
            public string logoncount { get; set; }
            public UACEnum useraccountcontrol { get; set; }

            public string badpwdcount { get; set; }
            public DateTime badpasswordtime { get; set; }
            public DateTime pwdlastset { get; set; }
            public string whencreated { get; set; }
            public string whenchanged { get; set; }
            public DateTime accountexpires { get; set; }

            public DateTime lastlogon { get; set; }
            public DateTime lastlogoff { get; set; }

            public string codepage { get; set; }
            public string objectcategory { get; set; }
            public string usnchanged { get; set; }
            public string instancetype { get; set; }
            public string objectclass { get; set; }
            public string iscriticalsystemobject { get; set; }
            public string usncreated { get; set; }
            public string dscorepropagationdata { get; set; }
            public string adspath { get; set; }
            public string countrycode { get; set; }
            public string primarygroupid { get; set; }
            public string objectguid { get; set; }
            public DateTime lastlogontimestamp { get; set; }
            public string msds_supportedencryptiontypes { get; set; }
            public string showinadvancedviewonly { get; set; }

            public override string ToString()
            {
                string output = "";
                if (this.samaccountname != null && this.samaccountname.Trim() != "") { output += "samaccountname: " + this.samaccountname + Environment.NewLine; }
                if (this.samaccounttype.ToString().Trim() != "") { output += "samaccounttype: " + this.samaccounttype + Environment.NewLine; }
                if (this.distinguishedname != null && this.distinguishedname.Trim() != "") { output += "distinguishedname: " + this.distinguishedname + Environment.NewLine; }
                if (this.cn != null && this.cn.Trim() != "") { output += "cn: " + this.cn + Environment.NewLine; }
                if (this.objectsid != null && this.objectsid.Trim() != "") { output += "objectsid: " + this.objectsid + Environment.NewLine; }
                if (this.sidhistory != null && String.Join(", ", this.sidhistory).Trim() != "") { output += "sidhistory: " + (this.sidhistory == null ? "" : String.Join(", ", this.sidhistory)) + Environment.NewLine; }
                if (this.grouptype.ToString().Trim() != "") { output += "grouptype: " + this.grouptype + Environment.NewLine; }
                //if (this.Owner != null && this.Owner.ToString().Trim() != "") { output += "Owner: " + this.Owner + Environment.NewLine; }
                //if (this.Group != null && this.Group.ToString().Trim() != "") { output += "Group: " + this.Group + Environment.NewLine; }
                if (this.DiscretionaryAcl != null && this.DiscretionaryAcl.ToString().Trim() != "") { output += "DiscretionaryAcl: " + this.DiscretionaryAcl + Environment.NewLine; }
                if (this.SystemAcl != null && this.SystemAcl.ToString().Trim() != "") { output += "SystemAcl: " + this.SystemAcl + Environment.NewLine; }
                if (this.admincount != null && this.admincount.Trim() != "") { output += "admincount: " + this.admincount + Environment.NewLine; }
                if (this.serviceprincipalname != null && this.serviceprincipalname.Trim() != "") { output += "serviceprincipalname: " + this.serviceprincipalname + Environment.NewLine; }
                if (this.name != null && this.name.Trim() != "") { output += "name: " + this.name + Environment.NewLine; }
                if (this.description != null && this.description.Trim() != "") { output += "description: " + this.description + Environment.NewLine; }
                if (this.memberof != null && this.memberof.Trim() != "") { output += "memberof: " + this.memberof + Environment.NewLine; }
                if (this.logoncount != null && this.logoncount.Trim() != "") { output += "logoncount: " + this.logoncount + Environment.NewLine; }
                if (this.useraccountcontrol.ToString().Trim() != "") { output += "useraccountcontrol: " + this.useraccountcontrol + Environment.NewLine; }
                if (this.badpwdcount != null && this.badpwdcount.Trim() != "") { output += "badpwdcount: " + this.badpwdcount + Environment.NewLine; }
                if (this.badpasswordtime != DateTime.MinValue && this.badpasswordtime.ToString().Trim() != "") { output += "badpasswordtime: " + this.badpasswordtime + Environment.NewLine; }
                if (this.pwdlastset != DateTime.MinValue && this.pwdlastset.ToString().Trim() != "") { output += "pwdlastset: " + this.pwdlastset + Environment.NewLine; }
                if (this.whencreated != null && this.whencreated.ToString().Trim() != "") { output += "whencreated: " + this.whencreated + Environment.NewLine; }
                if (this.whenchanged != null && this.whenchanged.ToString().Trim() != "") { output += "whenchanged: " + this.whenchanged + Environment.NewLine; }
                if (this.accountexpires != DateTime.MinValue && this.accountexpires.ToString().Trim() != "") { output += "accountexpires: " + this.accountexpires + Environment.NewLine; }
                if (this.lastlogon != DateTime.MinValue && this.lastlogon.ToString().Trim() != "") { output += "lastlogon: " + this.lastlogon + Environment.NewLine; }
                if (this.lastlogoff != DateTime.MinValue && this.lastlogoff.ToString().Trim() != "") { output += "lastlogoff: " + this.lastlogoff + Environment.NewLine; }
                if (this.codepage != null && this.codepage.Trim() != "") { output += "codepage: " + this.codepage + Environment.NewLine; }
                if (this.objectcategory != null && this.objectcategory.Trim() != "") { output += "objectcategory: " + this.objectcategory + Environment.NewLine; }
                if (this.usnchanged != null && this.usnchanged.Trim() != "") { output += "usnchanged: " + this.usnchanged + Environment.NewLine; }
                if (this.instancetype != null && this.instancetype.Trim() != "") { output += "instancetype: " + this.instancetype + Environment.NewLine; }
                if (this.objectclass != null && this.objectclass.Trim() != "") { output += "objectclass: " + this.objectclass + Environment.NewLine; }
                if (this.iscriticalsystemobject != null && this.iscriticalsystemobject.Trim() != "") { output += "iscriticalsystemobject: " + this.iscriticalsystemobject + Environment.NewLine; }
                if (this.usncreated != null && this.usncreated.Trim() != "") { output += "usncreated: " + this.usncreated + Environment.NewLine; }
                if (this.dscorepropagationdata != null && this.dscorepropagationdata.Trim() != "") { output += "dscorepropagationdata: " + this.dscorepropagationdata + Environment.NewLine; }
                if (this.adspath != null && this.adspath.Trim() != "") { output += "adspath: " + this.adspath + Environment.NewLine; }
                if (this.countrycode != null && this.countrycode.Trim() != "") { output += "countrycode: " + this.countrycode + Environment.NewLine; }
                if (this.primarygroupid != null && this.primarygroupid.Trim() != "") { output += "primarygroupid: " + this.primarygroupid + Environment.NewLine; }
                if (this.objectguid != null && this.objectguid.Trim() != "") { output += "objectguid: " + this.objectguid + Environment.NewLine; }
                if (this.lastlogontimestamp != DateTime.MinValue && this.lastlogontimestamp.ToString().Trim() != "") { output += "lastlogontimestamp: " + this.lastlogontimestamp + Environment.NewLine; }
                if (this.msds_supportedencryptiontypes != null && this.msds_supportedencryptiontypes.Trim() != "") { output += "msds_supportedencryptiontypes: " + this.msds_supportedencryptiontypes + Environment.NewLine; }
                if (this.showinadvancedviewonly != null && this.showinadvancedviewonly.Trim() != "") { output += "showinadvancedviewonly: " + this.showinadvancedviewonly + Environment.NewLine; }

                return output;
            }
        }

        /// <summary>
        /// Credential to authenticate to the Domain with a DomainSearcher object.
        /// </summary>
        public class Credential
        {
            public string UserName { get; set; }
            public string Password { get; set; }
            public string Domain { get; set; }
            public Credential(string UserName, string Password, string Domain)
            {
                this.UserName = UserName;
                this.Password = Password;
                this.Domain = Domain;
            }

            public static Credential EmptyCredential = new Credential("", "", "");

            public bool AreValid()
            {
                int ERROR_LOGON_FAILURE = 0x31;
                int LDAP_SERVER_UNAVAILABLE = 0x51;
                NetworkCredential credentials = new NetworkCredential(this.UserName, this.Password, this.Domain);

                LdapDirectoryIdentifier id = new LdapDirectoryIdentifier(this.Domain);

                using (LdapConnection connection = new LdapConnection(id, credentials, AuthType.Kerberos))
                {
                    connection.SessionOptions.Sealing = true;
                    connection.SessionOptions.Signing = true;

                    try
                    {
                        connection.Bind();
                    }
                    catch (LdapException e)
                    {
                        if (e.ErrorCode == ERROR_LOGON_FAILURE)
                        {
                            return false;
                        }
                        else if (e.ErrorCode == LDAP_SERVER_UNAVAILABLE)
                        {
                            return false;
                        }
                    }
                    return true;
                }
            }
        }

        public class SPNTicket
        {
            public string ServicePrincipleName { get; set; }
            public string SamAccountName { get; set; }
            public string UserDomain { get; set; }
            public string TicketByteHexStream { get; set; } = null;
            public string Hash { get; set; } = null;

            /// <summary>
            /// Constructor for SPNTicket.
            /// </summary>
            /// <param name="servicePrincipalName">Service Principal Name (SPN) for which the ticket applies.</param>
            /// <param name="samAccountName">SamAccountName for the user that has a SPN set.</param>
            /// <param name="userDomain">Domain name for the user that has a SPN set.</param>
            /// <param name="ticketHexStream">TicketHexStream of the SPNTicket.</param>
            public SPNTicket(string servicePrincipalName, string samAccountName, string userDomain, string ticketHexStream)
            {
                this.ServicePrincipleName = servicePrincipalName;
                this.SamAccountName = samAccountName;
                this.UserDomain = userDomain;
                this.TicketByteHexStream = ticketHexStream;
                var matches = Regex.Match(ticketHexStream, "a382....3082....A0030201(?<EtypeLen>..)A1.{1,4}.......A282(?<CipherTextLen>....)........(?<DataToEnd>.+)", RegexOptions.IgnoreCase);
                if (matches.Success)
                {
                    byte etype = Convert.ToByte(matches.Groups["EtypeLen"].Value, 16);
                    int cipherTextLen = Convert.ToInt32(matches.Groups["CipherTextLen"].Value, 16) - 4;
                    string cipherText = matches.Groups["DataToEnd"].Value.Substring(0, cipherTextLen * 2);

                    if (matches.Groups["DataToEnd"].Value.Substring(cipherTextLen * 2, 4) == "A482")
                    {
                        this.Hash = cipherText.Substring(0, 32) + "$" + cipherText.Substring(32);
                    }
                }
            }
            public enum HashFormat
            {
                Hashcat,
                John
            }

            /// <summary>
            /// Gets a krb5tgs hash formatted for a cracker.
            /// </summary>
            /// <param name="format">Format for the hash.</param>
            /// <returns>Formatted krb5tgs hash.</returns>
            public string GetFormattedHash(HashFormat format = HashFormat.Hashcat)
            {
                if (format == HashFormat.Hashcat)
                {
                    return "$krb5tgs$" + "23" + "$*" + this.SamAccountName + "$" + this.UserDomain + "$" + this.ServicePrincipleName + "$" + this.Hash;
                }
                else if (format == HashFormat.John)
                {
                    return "$krb5tgs$" + this.ServicePrincipleName + ":" + this.Hash;
                }
                return null;
            }
        }
    }
}
