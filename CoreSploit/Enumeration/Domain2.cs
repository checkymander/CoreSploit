using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.DirectoryServices.Protocols;
using System.Net;
using System.DirectoryServices;
using static CoreSploit.Enumeration.Domain;
using System.Text.RegularExpressions;
using System.Security.AccessControl;

namespace CoreSploit.Enumeration
{
    public class Domain2
    {
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
                        var desc = new RawSecurityDescriptor((byte[])Result.Attributes["ntsecuritydescriptor"][0], 0);
                        ldap.Owner = desc.Owner;
                        ldap.Group = desc.Group;
                        ldap.DiscretionaryAcl = desc.DiscretionaryAcl;
                        ldap.SystemAcl = desc.SystemAcl;
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
    }
}
