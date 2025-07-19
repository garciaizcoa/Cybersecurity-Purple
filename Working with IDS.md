
# Working with IDS/IPS 

## Sections
- [Suricata](#suricata-fundamentals)
- [Snort](#snort-fundamentals)
- [Zeek](#zeek-fundamentals)


## Suricata Fundamentals 


Each rule usually involves specific variables, such as $HOME_NET and $EXTERNAL_NET. The rule examines traffic from the IP addresses specified in the $HOME_NET variable heading towards the IP addresses in the $EXTERNAL_NET variable.

These variables can be defined in the suricata.yaml configuration file.

```bash 
rickyjojo@htb[/htb]$ more /etc/suricata/suricata.yaml
```

Finally, to configure Suricata to load signatures from a custom rules file, such as local.rules in the /home/htb-student directory, we would execute the below.

```bash 
rickyjojo@htb[/htb]$ sudo vim /etc/suricata/suricata.yaml
```

For live input, we can try Suricata’s (Live) LibPCAP mode as follows.

```bash 
rickyjojo@htb[/htb]$ ifconfig
ens160: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
    inet 10.129.205.193  netmask 255.255.0.0  broadcast 10.129.255.255
    inet6 dead:beef::250:56ff:feb9:68dc  prefixlen 64  scopeid 0x0<global>
    inet6 fe80::250:56ff:feb9:68dc  prefixlen 64  scopeid 0x20<link>
    ether 00:50:56:b9:68:dc  txqueuelen 1000  (Ethernet)
    RX packets 281625  bytes 84557478 (84.5 MB)
    RX errors 0  dropped 0  overruns 0  frame 0
    TX packets 62276  bytes 23518127 (23.5 MB)
    TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
    inet 127.0.0.1  netmask 255.0.0.0
    inet6 ::1  prefixlen 128  scopeid 0x10<host>
    loop  txqueuelen 1000  (Local Loopback)
    RX packets 888  bytes 64466 (64.4 KB)
    RX errors 0  dropped 0  overruns 0  frame 0
    TX packets 888  bytes 64466 (64.4 KB)
    TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
rickyjojo@htb[/htb]$ sudo suricata --pcap=ens160 -vv
```

If we wish to identify the earliest DNS event, for example, we can utilize the jq command-line JSON processor as follows.

```bash 
rickyjojo@htb[/htb]$ cat /var/log/suricata/old_eve.json | jq -c 'select(.event_type == "dn
```

### Suricata Config File-Store

We start by making changes to the Suricata configuration file (suricata.yaml). In this file, we'll find a section named file-store. This is where we tell Suricata how to handle the files it extracts. Specifically, we need to set version to 2, enabled to yes, and the force-filestore option also to yes. The resulting section should look something like this.

```bash 
file-store:
  version: 2
  enabled: yes
  force-filestore: yes
```

The simplest rule we can add to our local.rules file to experiment with file extraction is the following.
```bash 
alert http any any -> any any (msg:"FILE store all"; filestore; sid:2; rev:1;)
```

### Suricata Key Features

Key features that bolster Suricata's effectiveness include:

+ Deep packet inspection and packet capture logging
+ Anomaly detection and Network Security Monitoring
+ Intrusion Detection and Prevention, with a hybrid mode available
+ Lua scripting
+ Geographic IP identification (GeoIP)
+ Full IPv4 and IPv6 support
+ IP reputation
+ File extraction
+ Advanced protocol inspection
+ Multitenancy

---

### Suricata Rule Development Example 1: Detecting PowerShell Empire


```bash 
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET MALWARE Possible PowerShell Empire Activity Outbound"; flow:established,to_server; content:"GET"; http_method; content:"/"; http_uri; depth:1; pcre:"/^(?:login\/process|admin\/get|news)\.php$/RU"; content:"session="; http_cookie; pcre:"/^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=|[A-Z0-9+/]{4})$/CRi"; content:"Mozilla|2f|5.0|20 28|Windows|20|NT|20|6.1"; http_user_agent; http_start; content:".php|20|HTTP|2f|1.1|0d 0a|Cookie|3a 20|session="; fast_pattern; http_header_names; content:!"Referer"; content:!"Cache"; content:!"Accept"; sid:2027512; rev:1;)
```

The Suricata rule above is designed to detect possible outbound activity from [PowerShell Empire](https://github.com/EmpireProject/Empire)


### Suricata Rule Development Example 2: Detecting Covenant


```bash 
alert tcp any any -> $HOME_NET any (msg:"detected by body"; content:"<title>Hello World!</title>"; detection_filter: track by_src, count 4 , seconds 10; priority:1; sid:3000011;)
```

Rule source: Signature-based IDS for Encrypted C2 Traffic Detection - Eduardo Macedo

The (inefficient) Suricata rule above is designed to detect certain variations of [Covenant](https://github.com/cobbr/Covenant)


### Suricata Rule Development Example 3: Detecting Covenant (Using Analytics)

```bash 
alert tcp $HOME_NET any -> any any (msg:"detected by size and counter"; dsize:312; detection_filter: track by_src, count 3 , seconds 10; priority:1; sid:3000001;)
```

The local.rules file also contains the above rule for detecting Covenant


Running Suricata on pcap files:
```bash
sudo suricata -r /home/htb-student/pcaps/psempire.pcap -l . -k none

cat fast.log
```

### Suricata Rule Development Example 4: Detecting Sliver

```bash 
alert tcp any any -> any any (msg:"Sliver C2 Implant Detected"; content:"POST"; pcre:"/\/(php|api|upload|actions|rest|v1|oauth2callback|authenticate|oauth2|oauth|auth|database|db|namespaces)(.*?)((login|signin|api|samples|rpc|index|admin|register|sign-up)\.php)\?[a-z_]{1,2}=[a-z0-9]{1,10}/i"; sid:1000007; rev:1;)
```

Rule source: https://www.bilibili.com/read/cv19510951/

The Suricata rule above is designed to detect certain variations of [Sliver](https://github.com/BishopFox/sliver)


```bash 
alert tcp any any -> any any (msg:"Sliver C2 Implant Detected - Cookie"; content:"Set-Cookie"; pcre:"/(PHPSESSID|SID|SSID|APISID|csrf-state|AWSALBCORS)\=[a-z0-9]{32}\;/"; sid:1000003; rev:1;)
```
Let's break down the important parts of this rule to understand its workings.

```bash
content:"Set-Cookie";: This option instructs Suricata to look for TCP traffic containing the string Set-Cookie.

pcre:"/(PHPSESSID|SID|SSID|APISID|csrf-state|AWSALBCORS)\=[a-z0-9]{32}\;/";: This is a regular expression used to identify specific cookie-setting patterns in the traffic. It matches the Set-Cookie header when it's setting specific cookie names (PHPSESSID, SID, SSID, APISID, csrf-state, AWSALBCORS) with a value that's a 32-character alphanumeric string.
```


### Suricata Rule Development Example 5: Detecting Dridex (TLS Encrypted)

```bash
alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"ET MALWARE ABUSE.CH SSL Blacklist Malicious SSL certificate detected (Dridex)"; flow:established,from_server; content:"|16|"; content:"|0b|"; within:8; byte_test:3,<,1200,0,relative; content:"|03 02 01 02 02 09 00|"; fast_pattern; content:"|30 09 06 03 55 04 06 13 02|"; distance:0; pcre:"/^[A-Z]{2}/R"; content:"|55 04 07|"; distance:0; content:"|55 04 0a|"; distance:0; pcre:"/^.{2}[A-Z][a-z]{3,}\s(?:[A-Z][a-z]{3,}\s)?(?:[A-Z](?:[A-Za-z]{0,4}?[A-Z]|(?:\.[A-Za-z]){1,3})|[A-Z]?[a-z]+|[a-z](?:\.[A-Za-z]){1,3})\.?[01]/Rs"; content:"|55 04 03|"; distance:0; byte_test:1,>,13,1,relative; content:!"www."; distance:2; within:4; pcre:"/^.{2}(?P<CN>(?:(?:\d?[A-Z]?|[A-Z]?\d?)(?:[a-z]{3,20}|[a-z]{3,6}[0-9_][a-z]{3,6})\.){0,2}?(?:\d?[A-Z]?|[A-Z]?\d?)[a-z]{3,}(?:[0-9_-][a-z]{3,})?\.(?!com|org|net|tv)[a-z]{2,9})[01].*?(?P=CN)[01]/Rs"; content:!"|2a 86 48 86 f7 0d 01 09 01|"; content:!"GoDaddy"; sid:2023476; rev:5;)
```

### Suricata Rule Development Example 6: Detecting Sliver (TLS Encrypted)

```bash
alert tls any any -> any any (msg:"Sliver C2 SSL"; ja3.hash; content:"473cd7cb9faa642487833865d516e578"; sid:1002; rev:1;)
```

The Suricata rule above is designed to detect certain variations of Sliver whenever it identifies a TLS connection with a specific JA3 hash.

---

## Snort Fundamentals

Let's browse the snort.lua file residing in this section's target as follows.

```bash
rickyjojo@htb[/htb]$ sudo more /root/snorty/etc/snort/snort.lua
```

Enabling and fine-tuning Snort modules is a significant aspect of the configuration process. To explore the complete list and get a brief description of all Snort 3 modules, you can use the following command.

```bash
rickyjojo@htb[/htb]$ snort --help-modules
```

Passing (and validating) configuration files to Snort can be done as follows.

```bash
rickyjojo@htb[/htb]$ snort -c /root/snorty/etc/snort/snort.lua --daq-dir /usr/local/lib/daq
```


### Snort Inputs

To observe Snort in action, the easiest method is to execute it against a packet capture file. By providing the name of the pcap file as an argument to the -r option in the command line, Snort will process the file accordingly.

```bash
rickyjojo@htb[/htb]$ sudo snort -c /root/snorty/etc/snort/snort.lua --daq-dir /usr/local/lib/daq -r /home/htb-student/pcaps/icmp.pcap
```

Snort also has the capability to listen on active network interfaces. To specify this behavior, you can utilize the -i option followed by the names of the interfaces on which Snort should run.

```bash
rickyjojo@htb[/htb]$ sudo snort -c /root/snorty/etc/snort/snort.lua --daq-dir /usr/local/lib/daq -i ens160
```

### Configurating Snort 

In Snort deployments, we have flexibility in managing rules. It's possible to place rules (for example, local.rules residing at /home/htb-student) directly within the snort.lua configuration file using the ips module as follows.

```bash
rickyjojo@htb[/htb]$ sudo vim /root/snorty/etc/snort/snort.lua
```

Alerts: When rules are configured, it is necessary to enable alerting (using the -A option) to view the details of detection events. There are multiple types of alert outputs available, including:

-A cmg: This option combines -A fast -d -e and displays alert information along with packet headers and payload.
-A u2: This option is equivalent to -A unified2 and logs events and triggering packets in a binary file, which can be used for post-processing with other tools.
-A csv: This option outputs fields in comma-separated value format, providing customization options and facilitating pcap analysis.
To discover the available alert types, we can execute the following command.

```bash
rickyjojo@htb[/htb]$ snort --list-plugins | grep logger
```

The same command but using a .rules files that may not be "included" in snort.lua is the following.

```bash
rickyjojo@htb[/htb]$ sudo snort -c /root/snorty/etc/snort/snort.lua --daq-dir /usr/local/lib/daq -r /home/htb-student/pcaps/icmp.pcap -R /home/htb-student/local.rules -A cmg
```

### Snort Rule Development Example 1: Detecting Ursnif (Inefficiently)

```bash
alert tcp any any -> any any (msg:"Possible Ursnif C2 Activity"; flow:established,to_server; content:"/images/", depth 12; content:"_2F"; content:"_2B"; content:"User-Agent|3a 20|Mozilla/4.0 (compatible|3b| MSIE 8.0|3b| Windows NT"; content:!"Accept"; content:!"Cookie|3a|"; content:!"Referer|3a|"; sid:1000002; rev:1;)
```

The Snort rule above is designed to detect certain variations of Ursnif malware.

The above rule is already incorporated in the local.rules file found in the /home/htb-student directory of this section's target. To test it, first, you need to uncomment the rule. Then, execute Snort on the ursnif.pcap file, which is located in the /home/htb-student/pcaps directory.

```bash
rickyjojo@htb[/htb]$ sudo snort -c /root/snorty/etc/snort/snort.lua --daq-dir /usr/local/lib/daq -R /home/htb-student/local.rules -r /home/htb-student/pcaps/ursnif.pcap -A cmg
```

### Snort Rule Development Example 2: Detecting Cerber

```bash
alert udp $HOME_NET any -> $EXTERNAL_NET any (msg:"Possible Cerber Check-in"; dsize:9; content:"hi", depth 2, fast_pattern; pcre:"/^[af0-9]{7}$/R"; detection_filter:track by_src, count 1, seconds 60; sid:2816763; rev:4;)
```

### Snort Rule Development Example 3: Detecting Patchwork

```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"OISF TROJAN Targeted AutoIt FileStealer/Downloader CnC Beacon"; flow:established,to_server; http_method; content:"POST"; http_uri; content:".php?profile="; http_client_body; content:"ddager=", depth 7; http_client_body; content:"&r1=", distance 0; http_header; content:!"Accept"; http_header; content:!"Referer|3a|"; sid:10000006; rev:1;)
The Snort rule above is designed to detect certain variations of malware used by the Patchwork APT.
```

### Snort Rule Development Example 4: Detecting Patchwork (SSL)

```bash
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"Patchwork SSL Cert Detected"; flow:established,from_server; content:"|55 04 03|"; content:"|08|toigetgf", distance 1, within 9; classtype:trojan-activity; sid:10000008; rev:1;)
```


---


## Zeek Fundamentals

### Zeek's Operation Modes

Zeek operates in the following modes:

+ Fully passive traffic analysis
+ libpcap interface for packet capture
+ Real-time and offline (e.g., PCAP-based) analysis
+ Cluster support for large-scale deployments


For a more exhaustive list of common Zeek logs and their respective fields, refer to the following resource: 
https://docs.zeek.org/en/master/logs/index.html

For a quick start guide to Zeek, refer to the following link: https://docs.zeek.org/en/stable/quickstart/index.html

### Zeek Key Features

Key features that bolster Zeek's effectiveness include:

- Comprehensive logging of network activities
- Analysis of application-layer protocols (irrespective of the port, covering protocols like HTTP, DNS, FTP, SMTP, SSH, SSL, etc.)
- Ability to inspect file content exchanged over application-layer protocols
- IPv6 support
- Tunnel detection and analysis
- Capability to conduct sanity checks during protocol analysis
- IDS-like pattern matching
- Powerful, domain-aware scripting language that allows for expressing arbitrary analysis tasks and managing network state over time
- Interfacing that outputs to well-structured ASCII logs by default and offers alternative backends for ElasticSearch and DataSeries
- Real-time integration of external input into analyses
- External C library for sharing Zeek events with external programs
- Capability to trigger arbitrary external processes from within the scripting language


### Intrusion Detection With Zeek Example 1: Detecting Beaconing Malware

```bash
rickyjojo@htb[/htb]$ /usr/local/zeek/bin/zeek -C -r /home/htb-student/pcaps/psempire.pcap
```


```bash
rickyjojo@htb[/htb]$ cat conn.log
```

### Intrusion Detection With Zeek Example 2: Detecting DNS Exfiltration

Furthermore, Zeek’s ability to reassemble files transferred over the network (regardless of the protocol used) can assist in identifying the nature of the data being exfiltrated.

```bash
rickyjojo@htb[/htb]$ /usr/local/zeek/bin/zeek -C -r /home/htb-student/pcaps/dnsexfil.pcapng

rickyjojo@htb[/htb]$ cat dns.log
```

Let's focus on the requested (sub)domains by leveraging zeek-cut as follows.

```bash
cat dns.log | /usr/local/zeek/bin/zeek-cut query | cut -d . -f1-7
```

### Intrusion Detection With Zeek Example 3: Detecting TLS Exfiltration

PCAP credits to: Oleh Levytskyi and Bogdan Vennyk

Let's now go over an example of detecting data exfiltration over TLS.

```bash
rickyjojo@htb[/htb]$ /usr/local/zeek/bin/zeek -C -r /home/htb-student/pcaps/tlsexfil.pcap
rickyjojo@htb[/htb]$ cat conn.log
```

The output is a bit tricky to analyze. Let's narrow things down by using zeek-cut one more time.

One-liner source: activecountermeasures

```bash
rickyjojo@htb[/htb]$ cat conn.log | /usr/local/zeek/bin/zeek-cut id.orig_h id.resp_h orig_bytes | sort | grep -v -e '^$' | grep -v '-' | datamash -g 1,2 sum 3 | sort -k 3 -rn | head -10

```

### Intrusion Detection With Zeek Example 4: Detecting PsExec

We can identify SMB transfers and the typical use of PsExec using Zeek's smb_files.log, dce_rpc.log, and smb_mapping.log as follows.

PCAP source: 401TRG

```bash
rickyjojo@htb[/htb]$ /usr/local/zeek/bin/zeek -C -r /home/htb-student/pcaps/psexec_add_user.pcap
rickyjojo@htb[/htb]$ cat smb_files.log
rickyjojo@htb[/htb]$ cat dce_rpc.log
rickyjojo@htb[/htb]$ cat smb_mapping.log
```















