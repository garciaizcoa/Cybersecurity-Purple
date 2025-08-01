# Developing YARA Rules:

### How to Developing a YARA Rule Through [yarGen](https://github.com/Neo23x0/yarGen):

```bash
 python3 yarGen.py -m <pathtoscan> -o htb_sample.yar
```
### Run a YARA at a Directory:

```bash
yara htb_sample.yar /home/htb-student/Samples/YARASigma
```
### Calculating Imphash using imphash_calc.py

```bash
python3 imphash_calc.py /home/htb-student/Samples/YARASigma/legit.exe
```
###  .NET "reversing" using [monodis](https://www.mono-project.com/docs/tools+libraries/tools/monodis/)

```bash
monodis --output=code Microsoft.Exchange.Service.exe
```
**Note**: A better reversing solution would be to load the .NET assembly (Microsoft.Exchange.Service.exe) into a .NET debugger and assembly editor like [dnSpy](https://github.com/dnSpy/dnSpy).

### YARA rule for Stonedrill malware:

Encrypted/compressed/obfuscated in PE files usually means high entropy. We can use the entropy_pe_section.py script that resides in the /home/htb-student directory of this section's target to check if our sample's resource section contains anything encrypted/compressed as follows.
```bash
python3 entropy_pe_section.py -f /home/htb-student/Samples/YARASigma/sham2.exe
```
### YARA on Windows:

```bash
yara64.exe -s C:\\Rules\\yara\\dharma_ransomware.yar C:\\Samples\\YARASigma\\ -r 2>null
```

Scanning every active system process:
```bash
Get-Process | ForEach-Object { "Scanning with Yara for meterpreter shellcode on PID "+$_.id; & "yara64.exe" "C:\\Rules\\yara\\meterpreter_shellcode.yar" $_.id }
```

YARA scab on a specific PID:
```bash
yara64.exe C:\\Rules\\yara\\meterpreter_shellcode.yar 9084 --print-strings
```
**Note**: Using HxD to analyze hexdumps from executables on windows might help create string matching for hexcodes...

### YARA on Linux

#### Steps for Hunting for Evil Within Memory Images with YARA
YARA's memory image scanning mirrors its disk-based counterpart. Let's map out the process:

-**Create YARA Rules**: Either develop bespoke YARA rules or lean on existing ones that target memory-based malware traits or dubious behaviors.

-**Compile YARA Rules**: Compile the YARA rules into a binary format using the yarac tool (YARA Compiler). This step creates a file containing the compiled YARA rules with a .yrc extension. This step is optional, as we can use the normal rules in text format as well. While it is possible to use YARA in its human-readable format, compiling the rules is a best practice when deploying YARA-based detection systems or working with a large number of rules to ensure optimal performance and effectiveness. Also, compiling rules provides some level of protection by converting them into binary format, making it harder for others to view the actual rule content.

-**Obtain Memory Image**: Capture a memory image using tools such as [DumpIt](https://www.magnetforensics.com/resources/magnet-dumpit-for-windows/), [MemDump](http://www.nirsoft.net/utils/nircmd.html), [Belkasoft RAM Capturer](https://belkasoft.com/ram-capturer), [Magnet RAM Capture](https://www.magnetforensics.com/resources/magnet-ram-capture/), [FTK Imager](https://www.exterro.com/ftk-imager), and [LiME (Linux Memory Extractor)](https://github.com/504ensicsLabs/LiME).

-**Memory Image Scanning with YARA**: Use the yara tool and the compiled YARA rules to scan the memory image for possible matches.

### Using yarascan volatility plugin 
The [Volatility framework](https://www.volatilityfoundation.org/releases) is a powerful open-source memory forensics tool used to analyze memory images from various operating systems. YARA can be integrated into the Volatility framework as a plugin called yarascan allowing for the application of YARA rules to memory analysis.
```bash
vol.py -f /home/htb-student/MemoryDumps/compromised_system.raw yarascan -U "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"
```
**NOTE**: In summary, the -U option allows us to directly specify a YARA rule string within the command-line, while the -y option is used to specify the path to a file containing one or more YARA rules. The choice between the two options depends on our specific requirements and whether we have a single rule or a set of rules to apply during the analysis.

### YARA for Web 
[Unpac.Me](https://unpac.me/) is tool tailored for malware unpacking.




