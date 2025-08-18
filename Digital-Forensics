# Cybersecurity Digital Forensics Projects

Cybersecurity Blue team tooling for ease of use during triage and investigation tasks. 

## Table of Contents

1. [Memory-Forensics](#Memory-Forensics)
2. [Rootkit Analysis with Volatility v2](#Rootkit Analysis with Volatility v2)
3. [Memory Analysis Using Strings](#Memory Analysis Using Strings)
4. [Practical DF Scenario](#Practical DF Scenario)

---

## Memory-Forensics 

Steps according to [SANS](https://www.sans.org/) for in-memory investigations:

**1. Process Identification and Verification:** Let's begin by identifying all active processes. Malicious software often masquerades as legitimate processes, sometimes with subtle name variations to avoid detection. We need to:

**2. Deep Dive into Process Components:** Once we've flagged potentially rogue processes, our next step is to scrutinize the associated Dynamic Link Libraries (DLLs) and handles. Malware often exploits DLLs to conceal its activities. We should:

**3. Network Activity Analysis:** Many malware strains, especially those that operate in stages, necessitate internet connectivity. They might beacon to Command and Control (C2) servers or exfiltrate data. To uncover these:

**4. Code Injection Detection:** Advanced adversaries often employ techniques like process hollowing or utilize unmapped memory sections. To counter this, we should:

**5. Rootkit Discovery: ** Achieving stealth and persistence is a common goal for adversaries. Rootkits, which embed deep within the OS, grant threat actors continuous, often elevated, system access while evading detection. To tackle this:

**6. Extraction of Suspicious Elements: After pinpointing suspicious processes, drivers, or executables, we need to isolate them for in-depth analysis. This involves:

### The Volatility Framework

The preferred tool for conducting memory forensics is [Volatility](https://volatilityfoundation.org/).

Some commonly used modules include:

**pslist**: Lists the running processes.
**cmdline**: Displays process command-line arguments
**netscan**: Scans for network connections and open ports.
**malfind**: Scans for potentially malicious code injected into processes.
**handles**: Scans for open handles
**svcscan**: Lists Windows services.
**dlllist**: Lists loaded DLLs (Dynamic-link Libraries) in a process.
**hivelist**: Lists the registry hives in memory.

Volatility offers extensive documentation. You can find modules and their associated documentation using the following links:

**Volatility v2**: https://github.com/volatilityfoundation/volatility/wiki/Command-Reference
**Volatility v3**: https://volatility3.readthedocs.io/en/latest/index.html
A useful Volatility (v2 & v3) cheatsheet can be found here: https://blog.onfvp.com/post/volatility-cheatsheet/


### Identifying the Profile

To determine the profile that matches the operating system of the memory dump we can use the imageinfo plugin as follows.

```bash
rickyjojo@htb[/htb]$ vol.py -f /home/htb-student/MemoryDumps/Win7-2515534d.vmem imageinfo
````

### Identifying Running Processes

Let's see if the suggested Win7SP1x64 profile is correct by trying to list running process via the pslist plugin.

```bash
rickyjojo@htb[/htb]$ vol.py -f /home/htb-student/MemoryDumps/Win7-2515534d.vmem --profile=Win7SP1x64 pslist
```

### Identifying Network Artifacts

The netscan plugin can be used to scan for network artifacts as follows.

```bash
rickyjojo@htb[/htb]$ vol.py -f /home/htb-student/MemoryDumps/Win7-2515534d.vmem --profile=Win7SP1x64 netscan
```
NOTE:To find _TCPT_OBJECT structures using pool tag scanning, use the connscan command. This can find artifacts from previous connections that have since been terminated, in addition to the active ones.

### Identifying Injected Code

The malfind plugin can be used to identify and extract injected code and malicious payloads from the memory of a running process as follows.

```bash
rickyjojo@htb[/htb]$ vol.py -f /home/htb-student/MemoryDumps/Win7-2515534d.vmem --profile=Win7SP1x64 malfind --pid=608
```

### Identifying Handles

The handles plugin in Volatility is used for analyzing the handles (file and object references) held by a specific process within a memory dump.

```bash
rickyjojo@htb[/htb]$ vol.py -f /home/htb-student/MemoryDumps/Win7-2515534d.vmem --profile=Win7SP1x64 handles -p 1512 --object-type=Key
```

```bash
rickyjojo@htb[/htb]$ vol.py -f /home/htb-student/MemoryDumps/Win7-2515534d.vmem --profile=Win7SP1x64 handles -p 1512 --object-type=File
```

```bash
rickyjojo@htb[/htb]$ vol.py -f /home/htb-student/MemoryDumps/Win7-2515534d.vmem --profile=Win7SP1x64 handles -p 1512 --object-type=Process
```


### Identifying Windows Services

The svcscan plugin in Volatility is used for listing and analyzing Windows services running on a system within a memory dump. Here's how to use the svcscan plugin.

```bash
rickyjojo@htb[/htb]$ vol.py -f /home/htb-student/MemoryDumps/Win7-2515534d.vmem --profile=Win7SP1x64 svcscan | more
```


### Identifying Loaded DLLs

The dlllist plugin in Volatility is used for listing the dynamic link libraries (DLLs) loaded into the address space of a specific process within a memory dump.

```bash
rickyjojo@htb[/htb]$ vol.py -f /home/htb-student/MemoryDumps/Win7-2515534d.vmem --profile=Win7SP1x64 dlllist -p 1512
```

### Identifying Hives

The hivelist plugin in Volatility is used for listing the hives (registry files) present in the memory dump of a Windows system. 

```bash
rickyjojo@htb[/htb]$ vol.py -f /home/htb-student/MemoryDumps/Win7-2515534d.vmem --profile=Win7SP1x64 hivelist
```



## Rootkit Analysis with Volatility v2

Rootkits modify process data structures like EPROCESS by removing the FLINK and BLINK pointers on a EPROCESS doubly linked list to hide malicious processses, drives, files and other artifacts.

### Identifying Rootkit Signs

The psscan plugin is used to enumerate running processes. It scans the memory pool tags associated with each process's EPROCESS structure.

```bash
rickyjojo@htb[/htb]$ vol.py -f /home/htb-student/MemoryDumps/rootkit.vmem psscan
```

NOTE: On ocasions pslist plugin can't find the malware process which was hidden my a rootkit, but the psscan plugin will.


## Memory Analysis Using Strings

### Identifying IPv4 Addresses

We can either use the [Strings](https://learn.microsoft.com/en-us/sysinternals/downloads/strings) tool from the Sysinternals suite if our system is Windows-based, or the strings command from Binutils, if our system is Linux-based.

```bash
rickyjojo@htb[/htb]$ strings /home/htb-student/MemoryDumps/Win7-2515534d.vmem | grep -E "\\b([0-9]{1,3}\\.){3}[0-9]{1,3}\\b"
```

### Identifying Email Addresses

```bash
rickyjojo@htb[/htb]$ strings /home/htb-student/MemoryDumps/Win7-2515534d.vmem | grep -oE "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,4}\\b"
```

### Identifying Command Prompt or PowerShell Artifacts

```bash
rickyjojo@htb[/htb]$ strings /home/htb-student/MemoryDumps/Win7-2515534d.vmem | grep -E "(cmd|powershell|bash)[^\\s]+"
```

## Rapid Triage Examination & Analysis Tools

For a comprehensive list of these tools, check out: https://ericzimmerman.github.io/#!index.md

## Practical DF Scenario

Volatility's windows.malfind plugin can then be used to list process memory ranges that potentially contain injected code as follows.
```bash
C:\\Users\\johndoe\\Desktop\\volatility3-develop>python vol.py -q -f ..\\memdump\\PhysicalMemory.raw windows.malfind
```
