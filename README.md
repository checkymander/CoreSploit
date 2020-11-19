# CoreSploit
A Post-Exploitation Framework written for .NET 5.0 (Previously known as .NET Core)

Following in the naming of the various *sploit projects, CoreSploit is designed to work with cross-platform agents that are made using the .NET Framework 5.0 and above.

# Supported Functionality and Namespaces

## CoreSploit.Enumeration.Domain
```
GetDomainUser - Pulls user information from an LDAP Server
GetDomainGroup - Pulls group information from an LDAP Server
GetDomainComputer - Pulls computer information from an LDAP Server
```

## CoreSploit.Enumeration.GPO
```
GetEnableLua - Checks that status of EnableLua in a GPO Object
GetFilterAdministratorToken - Checks that status of FilterAdministratorToken in a GPO Object
GetLocalAccountTokenFilterPolicy - Checks that status of LocalAccountTokenFilterPolicy in a GPO Object
GetSeDenyNetworkLogonRight - Checks that status of SeDenyNetworkLogonRight in a GPO Object
GetSeDenyRemoteInteractiveLogonRight - Checks that status of SeDenyRemoteInteractiveLogonRight in a GPO Object
```

## CoreSploit.Enumeration.Host
```
GetProcessList - Get a list of processes on the host
GetDirectoryListing - Get a directory listing on the host
GetHostname - Get hostname
GetUsername - Get current username
TakeScreenshot - Take a screenshot of the host
```

## CoreSploit.Enumeration.Network
```
PortScan - Check if a port is open on a host
Ping - Check if a host is up 
```

## Coresploit.LateralMovement
```
SMBAdminCheck - Using PassTheHash and SMB to check if a user is admin
SMBExecute - Using PassTheHash and SMB to execute a command
WMIAdminCheck- Using PassTheHash and WMI to check if a user is admin
WMIExecute- Using PassTheHash and WMI to execute a command
```

# Credits
* Dennis Panagiotopoulos ([@den_n1s](https://twitter.com/den_n1s)) for the GPO Setting Enumeration code.
* Ryan Cobb ([@cobbr_io](https://twitter.com/cobbr_io)) for the initial SharpSploit project which a lot of this code is heavily based on.
* Kevin Robertson ([@kevin_robertson](https://twitter.com/kevin_robertson)) for his Invoke-TheHash code, which the CoreSploit Pass the Hash functionality comes from.
* Matt Graeber ([@mattifestation](https://twitter.com/mattifestation)), Will Schroeder ([@harmj0y](https://twitter.com/harmj0y)), and Ruben ([@FuzzySec](https://twitter.com/fuzzysec)) - For their work on [PowerSploit](https://github.com/PowerShellMafia/PowerSploit).

