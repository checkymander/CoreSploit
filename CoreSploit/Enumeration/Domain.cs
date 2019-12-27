using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using Novell.Directory.Ldap;
using Novell.Directory.Ldap.Events;

namespace CoreSploit.Enumeration
{
    public class Domain
    {
        public class DomainSearcher : IDisposable
        {
            public string Domain { get; set; }
            public string Server { get; set; }
            public string SearchBase { get; set; }
            public LdapConnection Searcher { get; set; }

            public DomainSearcher(string username = "", string password = "", string Domain = "", string Server = "",
                string SearchBase = "", string SearchString = "",
                int ResultPageSize = 200, TimeSpan ServerTimeLimit = default(TimeSpan), bool TombStone = false,
                bool ssl = false)
            {
                this.Domain = Domain;
                this.Server = Server;
                this.SearchBase = SearchBase;
                this.Searcher = new LdapConnection();
                if (this.Domain == "")
                {
                    this.Domain = Environment.UserDomainName;
                }

                if (this.Server == "")
                {
                    if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    {
                        string logonserver = Environment.GetEnvironmentVariable(("logonserver"));
                        this.Server = logonserver.Replace("\\", "");
                    }
                    else
                    {
                        //Attempt to get userdomain from environmental variable linux.
                        this.Server = Environment.GetEnvironmentVariable("userdomain");
                    }

                }

                if (SearchBase == "")
                {
                    //this.SearchBase = "LDAP://" + this.GetBaseDN();
                    this.SearchBase = this.GetBaseDN();
                }

                if (ssl)
                {
                    this.Searcher.SecureSocketLayer = true;
                }
                else
                {
                    this.Searcher.SecureSocketLayer = false;
                }

                LdapSearchConstraints cons = this.Searcher.SearchConstraints;
                cons.ReferralFollowing = true;
                this.Searcher.Constraints = cons;
                this.Searcher.Connect(this.Server, 389);
                this.Searcher.Bind(username, password);
            }

            public DomainObject GetDomainUser(string Identity, string LDAPFilter = "",
                IEnumerable<string> Properties = null, bool SPN = false, bool AllowDelegation = false,
                bool DisallowDelegation = false, bool AdminCount = false, bool TrustedToAuth = false,
                bool PreauthNotRequired = false, int SearchScope = LdapConnection.SCOPE_SUB,
                IEnumerable<UACEnum> UACFilter = null)
            {
                return this.GetDomainUsers(new List<string> {Identity}, LDAPFilter, Properties, SPN, AllowDelegation,
                        DisallowDelegation, AdminCount, TrustedToAuth, PreauthNotRequired, SearchScope, UACFilter)
                    .FirstOrDefault();
            }

            public List<DomainObject> GetDomainUsers(IEnumerable<string> Identities = null, string LDAPFilter = "",
                IEnumerable<string> Properties = null, bool SPN = false, bool AllowDelegation = false,
                bool DisallowDelegation = false, bool AdminCount = false, bool TrustedToAuth = false,
                bool PreauthNotRequired = false, int SearchScope = LdapConnection.SCOPE_SUB,
                IEnumerable<UACEnum> UACFilter = null)
            {
                string Filter = "";
                string IdentityFilter = ConvertIdentitiesToFilter(Identities, DomainObjectType.User,this.Domain);
                string[] Props = null;

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

                if (Properties != null)
                {
                    Props = Props.ToArray();
                }

                Filter += LDAPFilter;
                //805306368 = All User objects
                Filter = "(&(sAMAccountType=805306368)" + Filter + ")";
               
                Console.WriteLine("Final Filter: {0}", Filter);
                Console.WriteLine(this.SearchBase);
                Console.WriteLine(SearchScope);
                LdapSearchResults lsc = this.Searcher.Search(this.SearchBase, SearchScope, Filter, Props, false);
                List<DomainObject> results = new List<DomainObject>();


                while (lsc.HasMore())
                {
                    try
                    {
                        results.Add(ConvertLDAPProperty(lsc.Next()));
                    }
                    catch
                    {
                        continue;
                    }
                }

                return results;
            }
            
            public DomainObject GetDomainGroup(string Identity, string LDAPFilter = "", IEnumerable<string> Properties = null, bool AdminCount = false, string GroupScope = "", string GroupProperty = "", int SearchScope = LdapConnection.SCOPE_SUB)
            {
                return this.GetDomainGroups(new List<string> { Identity }, LDAPFilter, Properties, AdminCount, GroupScope, GroupProperty, true).FirstOrDefault();
            }
            
            public List<DomainObject> GetDomainGroups(IEnumerable<string> Identities = null, string LDAPFilter = "",
                IEnumerable<string> Properties = null, bool AdminCount = false, string GroupScope = "",
                string GroupProperty = "", bool FindOne = false, int SearchScope = LdapConnection.SCOPE_SUB)
            {
                string Filter = "";
                string IdentityFilter = ConvertIdentitiesToFilter(Identities, DomainObjectType.User, this.Domain);
                string[] Props = null;

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
                if (Properties != null)
                {
                    Props = Props.ToArray();
                }

                Filter += LDAPFilter;
                Filter = "(&(objectCategory=group)" + Filter + ")";
                Console.WriteLine("Final Filter: {0}", Filter);
                Console.WriteLine(this.SearchBase);
                Console.WriteLine(SearchScope);
                LdapSearchResults lsc = this.Searcher.Search(this.SearchBase, SearchScope, Filter, Props, false);
                List<DomainObject> results = new List<DomainObject>();
                while (lsc.HasMore())
                {
                    try
                    {
                        results.Add(ConvertLDAPProperty(lsc.Next()));
                    }
                    catch (Exception e)
                    {
                        continue;
                    }
                }

                return results;
            }


            public List<DomainObject> GetDomainComputers(IEnumerable<string> Identities = null, string LDAPFilter = "", IEnumerable<string> Properties = null, IEnumerable<UACEnum> UACFilter = null, bool Unconstrained = false, bool TrustedToAuth = false, bool Printers = false, string SPN = "", string OperatingSystem = "", string ServicePack = "", string SiteName = "", bool Ping = false, bool FindOne = false, int SearchScope = LdapConnection.SCOPE_SUB)
            {
                string Filter = "";
                string IdentityFilter = ConvertIdentitiesToFilter(Identities, DomainObjectType.Computer);
                string[] Props = null;
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
                Console.WriteLine("Final Filter: {0}", Filter);
                Console.WriteLine(this.SearchBase);
                Console.WriteLine(SearchScope);
                LdapSearchResults lsc = this.Searcher.Search(this.SearchBase, SearchScope, Filter, Props, false);
                List<DomainObject> results = new List<DomainObject>();
                while (lsc.HasMore())
                {
                    try
                    {
                        results.Add(ConvertLDAPProperty(lsc.Next()));
                    }
                    catch (Exception e)
                    {
                        continue;
                    }
                }

                return results;


            }

            private string GetUserDN(string user)
            {
                return "DN=" + user + "," + GetBaseDN();
            }
     
            private string GetBaseDN()
            {
                return "DC=" + this.Domain.Replace(".", ",DC=");
            }

            public List<DomainObject> ConvertLdapResultsToDomainObjects(LdapEntry result)
            {
                return null;
            }

            public static DomainObject ConvertLDAPProperty(LdapEntry result)
            {
                DomainObject obj = new DomainObject();
                LdapAttributeSet attributeSet = result.getAttributeSet();
                System.Collections.IEnumerator ienum = attributeSet.GetEnumerator();
                while (ienum.MoveNext())
                {
                    LdapAttribute attr = (LdapAttribute)ienum.Current;
                    switch (attr.Name.ToLower())
                    {
                        case "objectsid":
                            //Will need to convert this to a string
                            obj.objectsid = attr.StringValue;
                            break;
                        case "sidhistory":
                            obj.sidhistory = attr.StringValueArray;
                            break;
                        case "grouptype":
                            obj.grouptype = (GroupTypeEnum)Enum.Parse(typeof(GroupTypeEnum), attr.StringValue);
                            break;
                        case "samaccounttype":
                            obj.samaccounttype = (SamAccountTypeEnum)Enum.Parse(typeof(SamAccountTypeEnum), attr.StringValue);
                            break;
                        case "objectguid":
                            //Will need to conver this to a string
                            obj.objectguid = attr.StringValue;
                            break;
                        case "useraccountcontrol":
                            //convertme
                            break;
                        case "ntsecuritydescriptor":
                            //convertme
                            break;
                        case "accountexpires":
                            if (long.Parse(attr.StringValue) >= DateTime.MaxValue.Ticks)
                            {
                                obj.accountexpires = DateTime.MaxValue;
                            }
                            try
                            {
                                obj.accountexpires = DateTime.FromFileTime(long.Parse(attr.StringValue));
                            }
                            catch (ArgumentOutOfRangeException)
                            {
                                obj.accountexpires = DateTime.MaxValue;
                            }
                            break;
                        case "lastlogon":
                            DateTime dateTime = DateTime.MinValue;
                            //Not sure if this syntax is right.
                            if (attr.StringValues.GetType().Name == "System.MarshalByRefObject")
                            {
                                var comobj = (MarshalByRefObject)attr.StringValues;
                                int high = (int)comobj.GetType().InvokeMember("HighPart", System.Reflection.BindingFlags.GetProperty, null, comobj, null);
                                int low = (int)comobj.GetType().InvokeMember("LowPart", System.Reflection.BindingFlags.GetProperty, null, comobj, null);
                                dateTime = DateTime.FromFileTime(int.Parse("0x" + high + "" + low, System.Globalization.NumberStyles.HexNumber));
                            }
                            else
                            {
                                dateTime = DateTime.FromFileTime(long.Parse(attr.StringValue));
                            }
                            obj.lastlogon = dateTime;
                            break;
                        case "pwdlastset":
                            if (attr.StringValues.GetType().Name == "System.MarshalByRefObject")
                            {
                                var comobj = (MarshalByRefObject)attr.StringValues;
                                int high = (int)comobj.GetType().InvokeMember("HighPart", System.Reflection.BindingFlags.GetProperty, null, comobj, null);
                                int low = (int)comobj.GetType().InvokeMember("LowPart", System.Reflection.BindingFlags.GetProperty, null, comobj, null);
                                dateTime = DateTime.FromFileTime(int.Parse("0x" + high + "" + low, System.Globalization.NumberStyles.HexNumber));
                            }
                            else
                            {
                                dateTime = DateTime.FromFileTime(long.Parse(attr.StringValue));
                            }
                            obj.pwdlastset = dateTime;
                            break;
                        case "lastlogoff":
                            if (attr.StringValues.GetType().Name == "System.MarshalByRefObject")
                            {
                                var comobj = (MarshalByRefObject)attr.StringValues;
                                int high = (int)comobj.GetType().InvokeMember("HighPart", System.Reflection.BindingFlags.GetProperty, null, comobj, null);
                                int low = (int)comobj.GetType().InvokeMember("LowPart", System.Reflection.BindingFlags.GetProperty, null, comobj, null);
                                dateTime = DateTime.FromFileTime(int.Parse("0x" + high + "" + low, System.Globalization.NumberStyles.HexNumber));
                            }
                            else
                            {
                                dateTime = DateTime.FromFileTime(long.Parse(attr.StringValue));
                            }
                            obj.lastlogoff = dateTime;
                            break;
                        case "badpasswordtime":
                            if (attr.StringValues.GetType().Name == "System.MarshalByRefObject")
                            {
                                var comobj = (MarshalByRefObject)attr.StringValues;
                                int high = (int)comobj.GetType().InvokeMember("HighPart", System.Reflection.BindingFlags.GetProperty, null, comobj, null);
                                int low = (int)comobj.GetType().InvokeMember("LowPart", System.Reflection.BindingFlags.GetProperty, null, comobj, null);
                                dateTime = DateTime.FromFileTime(int.Parse("0x" + high + "" + low, System.Globalization.NumberStyles.HexNumber));
                            }
                            else
                            {
                                dateTime = DateTime.FromFileTime(long.Parse(attr.StringValue));
                            }
                            obj.badpasswordtime = dateTime;
                            break;
                        default:
                            {
                                string property = "0";
                                if (attr.StringValue.GetType().Name == "System.MarshalByRefObject")
                                {
                                    var comobj = (MarshalByRefObject)attr.StringValues;
                                    int high = (int)comobj.GetType().InvokeMember("HighPart", System.Reflection.BindingFlags.GetProperty, null, comobj, null);
                                    int low = (int)comobj.GetType().InvokeMember("LowPart", System.Reflection.BindingFlags.GetProperty, null, comobj, null);
                                    property = int.Parse("0x" + high + "" + low, System.Globalization.NumberStyles.HexNumber).ToString();
                                }
                                else if (attr.StringValueArray.Length == 1)
                                {
                                    property = attr.StringValueArray[0];
                                }
                                else
                                {
                                    List<string> propertyList = new List<string>();
                                    foreach (object prop in attr.StringValueArray)
                                    {
                                        propertyList.Add(prop.ToString());
                                    }
                                    property = String.Join(", ", propertyList.ToArray());
                                }
                                string attribName = attr.Name.ToLower();
                                if (attribName == "samaccountname") { obj.samaccountname = property; }
                                else if (attribName == "distinguishedname") { obj.distinguishedname = property; }
                                else if (attribName == "cn") { obj.cn = property; }
                                else if (attribName == "admincount") { obj.admincount = property; }
                                else if (attribName == "serviceprincipalname") { obj.serviceprincipalname = property; }
                                else if (attribName == "name") { obj.name = property; }
                                else if (attribName == "description") { obj.description = property; }
                                else if (attribName == "memberof") { obj.memberof = property; }
                                else if (attribName == "logoncount") { obj.logoncount = property; }
                                else if (attribName == "badpwdcount") { obj.badpwdcount = property; }
                                else if (attribName == "whencreated") { obj.whencreated = property; }
                                else if (attribName == "whenchanged") { obj.whenchanged = property; }
                                else if (attribName == "codepage") { obj.codepage = property; }
                                else if (attribName == "objectcategory") { obj.objectcategory = property; }
                                else if (attribName == "usnchanged") { obj.usnchanged = property; }
                                else if (attribName == "instancetype") { obj.instancetype = property; }
                                else if (attribName == "objectclass") { obj.objectclass = property; }
                                else if (attribName == "iscriticalsystemobject") { obj.iscriticalsystemobject = property; }
                                else if (attribName == "usncreated") { obj.usncreated = property; }
                                else if (attribName == "dscorepropagationdata") { obj.dscorepropagationdata = property; }
                                else if (attribName == "adspath") { obj.adspath = property; }
                                else if (attribName == "countrycode") { obj.countrycode = property; }
                                else if (attribName == "primarygroupid") { obj.primarygroupid = property; }
                                else if (attribName == "msds_supportedencryptiontypes") { obj.msds_supportedencryptiontypes = property; }
                                else if (attribName == "showinadvancedviewonly") { obj.showinadvancedviewonly = property; }
                            }
                            break;
                    }
                }
                return obj;
            }

            private static string ConvertIdentitiesToFilter(IEnumerable<string> Identities, DomainObjectType objectType = DomainObjectType.User, string Domain = "")
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
                    else if (objectType == DomainObjectType.Computer && IdentityInstance.Contains("."))
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
                    else if (objectType == DomainObjectType.User || objectType == DomainObjectType.Group)
                    {
                        if (IdentityInstance.Contains("\\"))
                        {
                            //////////////
                            //
                            //
                            // Need to figure out what this returns
                            // Is this really even needed? I'll put a temporary translator function here.
                            // The only thing that really gets used here is the UserName.
                            //
                            //
                            /////////////
                            string ConvertedIdentityInstance = ConvertADName(IdentityInstance.Replace("\\28", "(").Replace("\\29", ")"), NameType.NT4, Domain);
                            if (ConvertedIdentityInstance != null && ConvertedIdentityInstance != "")
                            {
                                /**
                                string UserDomain = ConvertedIdentityInstance.Substring(0, ConvertedIdentityInstance.IndexOf("/"));
                                string UserName = ConvertedIdentityInstance.Substring(0, ConvertedIdentityInstance.IndexOf("/"));
                                **/
                                string UserName = ConvertedIdentityInstance.Substring(ConvertedIdentityInstance.IndexOf('/'), ConvertedIdentityInstance.Length);

                                IdentityFilter += "(samAccountName=" + UserName + ")";
                            }
                        }
                        else if (objectType == DomainObjectType.User)
                        {
                            IdentityFilter += "(samAccountName=" + IdentityInstance + ")";
                        }
                        else if (objectType == DomainObjectType.Group)
                        {
                            IdentityFilter += "(|(samAccountName=" + IdentityInstance + ")(name=" + IdentityInstance + "))";
                        }
                    }
                    else if (objectType == DomainObjectType.Computer)
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

            public void Dispose()
            {
                this.Searcher.Disconnect();
            }
        }



#region HelperFuncs

        #endregion
#region enums and objects
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
            //public RawAcl DiscretionaryAcl { get; set; }
            //public RawAcl SystemAcl { get; set; }

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
                //if (this.DiscretionaryAcl != null && this.DiscretionaryAcl.ToString().Trim() != "") { output += "DiscretionaryAcl: " + this.DiscretionaryAcl + Environment.NewLine; }
                //if (this.SystemAcl != null && this.SystemAcl.ToString().Trim() != "") { output += "SystemAcl: " + this.SystemAcl + Environment.NewLine; }
                if (this.admincount != null && this.admincount.Trim() != "") { output += "admincount: " + this.admincount + Environment.NewLine; }
                if (this.serviceprincipalname != null && this.serviceprincipalname.Trim() != "") { output += "serviceprincipalname: " + this.serviceprincipalname + Environment.NewLine; }
                if (this.name != null && this.name.Trim() != "") { output += "name: " + this.name + Environment.NewLine; }
                if (this.description != null && this.description.Trim() != "") { output += "description: " + this.description + Environment.NewLine; }
                if (this.memberof != null && this.memberof.Trim() != "") { output += "memberof: " + this.memberof + Environment.NewLine; }
                if (this.logoncount != null && this.logoncount.Trim() != "") { output += "logoncount: " + this.logoncount + Environment.NewLine; }
                if (this.useraccountcontrol.ToString().Trim() != "") { output += "useraccountcontrol: " + this.useraccountcontrol + Environment.NewLine; }
                if (this.badpwdcount != null && this.badpwdcount.Trim() != "") { output += "badpwdcount: " + this.badpwdcount + Environment.NewLine; }
                if (this.badpasswordtime != null && this.badpasswordtime.ToString().Trim() != "") { output += "badpasswordtime: " + this.badpasswordtime + Environment.NewLine; }
                if (this.pwdlastset != null && this.pwdlastset.ToString().Trim() != "") { output += "pwdlastset: " + this.pwdlastset + Environment.NewLine; }
                if (this.whencreated != null && this.whencreated.ToString().Trim() != "") { output += "whencreated: " + this.whencreated + Environment.NewLine; }
                if (this.whenchanged != null && this.whenchanged.ToString().Trim() != "") { output += "whenchanged: " + this.whenchanged + Environment.NewLine; }
                if (this.accountexpires != null && this.accountexpires.ToString().Trim() != "") { output += "accountexpires: " + this.accountexpires + Environment.NewLine; }
                if (this.lastlogon != null && this.lastlogon.ToString().Trim() != "") { output += "lastlogon: " + this.lastlogon + Environment.NewLine; }
                if (this.lastlogoff != null && this.lastlogoff.ToString().Trim() != "") { output += "lastlogoff: " + this.lastlogoff + Environment.NewLine; }
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
                if (this.lastlogontimestamp != null && this.lastlogontimestamp.ToString().Trim() != "") { output += "lastlogontimestamp: " + this.lastlogontimestamp + Environment.NewLine; }
                if (this.msds_supportedencryptiontypes != null && this.msds_supportedencryptiontypes.Trim() != "") { output += "msds_supportedencryptiontypes: " + this.msds_supportedencryptiontypes + Environment.NewLine; }
                if (this.showinadvancedviewonly != null && this.showinadvancedviewonly.Trim() != "") { output += "showinadvancedviewonly: " + this.showinadvancedviewonly + Environment.NewLine; }

                return output;
            }
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
        public enum GroupTypeEnum : long
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
    }
#endregion 

}
