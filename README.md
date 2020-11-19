# CoreSploit
A Post-Exploitation Framework written for .NET 5.0 (Previously known as .NET Core)

Following in the naming of the various *sploit projects, CoreSploit is designed to work with cross-platform agents that are made using the .NET Framework 5.0 and above.

# Supported Functionality and Namespaces

## CoreSploit.Enumeration.Domain
```
GetDomainUser
GetDomainGroup
GetDomainComputer
```

## CoreSploit.Enumeration.GPO
```
GetEnableLua
GetFilterAdministratorToken
GetLocalAccountTokenFilterPolicy
GetSeDenyNetworkLogonRight
GetSeDenyRemoteInteractiveLogonRight
```

## CoreSploit.Enumeration.Host
```
GetProcessList
GetDirectoryListing
GetHostname
GetUsername
TakeScreenshot
```

## CoreSploit.Enumeration.Network
```
PortScan
Ping
```

## Coresploit.LateralMovement
```
SMBAdminCheck
SMBExecute
WMIAdminCheck
WMIExecute
```

# Credits
* Dennis Panagiotopoulos ([@den_n1s](https://twitter.com/den_n1s)) for the GPO Setting Enumeration code.
* Ryan Cobb ([@cobbr_io](https://twitter.com/cobbr_io)) for the initial SharpSploit project which a lot of this code is heavily based on.
* Matt Graeber ([@mattifestation](https://twitter.com/mattifestation)), Will Schroeder ([@harmj0y](https://twitter.com/harmj0y)), and Ruben ([@FuzzySec](https://twitter.com/fuzzysec)) - For their work on [PowerSploit](https://github.com/PowerShellMafia/PowerSploit).
