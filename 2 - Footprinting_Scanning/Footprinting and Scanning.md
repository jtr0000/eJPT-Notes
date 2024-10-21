#### Table of Contents

 [Networking Fundamentals ](Footprinting%20and%20Scanning.md#networking)

 [Network Mapping ](Footprinting%20and%20Scanning.md#networking-mapping)

 [Host Discovery ](Footprinting%20and%20Scanning.md#host-discovery)

 [Ping Sweeps](Footprinting%20and%20Scanning.md#ping-sweeps)

 [Host Discovery with Nmap ](Footprinting%20and%20Scanning.md#host-discovery-with-nmap)

 [Port Scanning with Nmap ](Footprinting%20and%20Scanning.md#port-scanning-with-nmap)

 [Evasion, Scan Performance and Output](Footprinting%20and%20Scanning.md#evasion-performance-output)

----
### Networking

In networking, devices (or hosts) communicate using network protocols, which are essential for ensuring that different hardware and software systems can work together. Data is sent in packets—streams of bits that represent the information being exchanged. Each packet has two parts: a header, which includes protocol-specific details, and a payload, which contains the actual data being sent, like an email or file.

**OSI Model**

The OSI model (Open Systems Interconnection) is a framework created to help standardize how network communications work. It's a helpful reference, not a strict set of rules, for understanding how different protocols and processes interact. The OSI model breaks communication down into seven layers:

- **Layer 1 (Physical Layer):** Deals with physical connections (e.g., cables, switches).
- **Layer 2 (Data Link Layer):** Manages access to the physical medium and performs error checking.
- **Layer 3 (Network Layer):** Handles logical addressing and routing across networks.
- **Layer 4 (Transport Layer):** Ensures reliable communication between hosts.
- **Layer 5 (Session Layer):** Manages and controls sessions between applications.
- **Layer 6 (Presentation Layer):** Ensures data is in the correct format for different applications.
- **Layer 7 (Application Layer):** Provides network services to the user (e.g., web browsers, email).

**Internet Protocol (IP)**

IP, which operates at the network layer (Layer 3), is the backbone of how the internet works. It handles logical addressing, routing, and packet reassembly. There are two main versions of IP:

- **IPv4:** Uses 32-bit addresses and is the most common version of IP.
- **IPv6:** Uses 128-bit addresses and was created to provide more address space.

IP addresses are hierarchical and help uniquely identify devices on a network. An IP packet’s header includes the source and destination addresses, and the payload carries the actual data. IP also allows large packets to be fragmented into smaller pieces for transmission.

Two important protocols work with IP:

- **ICMP:** Used for error reporting and network diagnostics (e.g., ping).
- **DHCP:** Automatically assigns IP addresses to devices, making configuration easier.

**IPv4 Packet Structure and Addressing**

An IPv4 address is 32 bits (four bytes) and is usually written as four numbers separated by dots. IPv4 packets have key fields in their headers, such as:

- **Source/Destination IP:** Identifies the sender and receiver.
- **Time-to-Live (TTL):** Limits how long a packet can stay on the network.
- **Protocol:** Specifies what type of data is being transmitted (e.g., TCP or UDP).

Certain IP address ranges are reserved for specific uses, such as 0.0.0.0 and 127.0.0.0, as defined in RFC5735.

**Transport Layer and Protocols**

The transport layer (Layer 4) is responsible for ensuring that data is reliably sent between devices. It manages error detection, flow control, and segmentation. Two key protocols operate here:

- **Transmission Control Protocol (TCP):** This is connection-oriented, meaning it establishes a connection before sending data. It guarantees reliable delivery and makes sure that data arrives in the correct order. TCP uses a three-way handshake (SYN, SYN-ACK, ACK) to establish connections.
    
    - **TCP Header:** Includes source and destination ports to identify which applications are communicating.
    - **TCP Ports:** Ports are divided into:
        - Well-Known Ports (0-1023): Used for standard services (e.g., HTTP on port 80).
        - Registered Ports (1024-49151): Assigned to specific applications.
        - Dynamic/Private Ports (49152-65535): Temporary or private connections.

- **User Datagram Protocol (UDP):** UDP is connectionless and doesn’t guarantee reliable delivery. It’s faster but less reliable, often used for streaming or gaming. Its header is smaller than TCP’s, meaning less overhead.
- 
#### TCP vs. UDP

TCP is best for applications where reliable, ordered data transmission is critical, like web browsing or file transfers. UDP is faster and better for applications like live video or gaming, where speed matters more than reliability. While TCP ensures that data arrives correctly, UDP trades reliability for lower latency.

##### TCP Three-way Handshake

The three-way handshake is a process used by TCP to establish a connection between devices, involving the exchange of SYN, SYN-ACK, and ACK packets:

1. **SYN** (Synchronize | “Hello”) => The initiating device (often referred to as the client) sends a TCP packet with the SYN flag set to the destination device (often referred to as the server). This initial packet indicates the desire to establish a connection and includes an initial sequence number.

2.  **SYN ACK** packet (Synchronize-Acknowledge | “Hello Back”) => After receiving the SYN packet, the destination device responds with a TCP packet that has both the SYN and **ACK** (acknowledge) flags set. This packet acknowledges the connection request and also includes its own initial sequence number.

3. **ACK** (Acknowledge) => Finally, the initiating device acknowledges the SYN-ACK packet by sending an ACK packet back to the destination. This packet establishes the connection and typically contains an incremented sequence number.

Once the three-way handshake is complete, the connection is established, and both devices are ready to exchange data. The sequence numbers exchanged during the handshake are used to ensure that data is transmitted and received in the correct order.

### Networking-Mapping

Network mapping is a critical phase in penetration testing following the passive information gathering phase, where the tester actively gathers information about the target network including:
1. Which hosts in a network are online
2. Their IP addresses
3. Open ports/services they are running
4. The operating systems they use

The key objectives of network mapping include:
- **Discovery of Live Hosts:** Identifying active devices and hosts by detecting IP addresses in use.
- **Identification of Open Ports and Services:** Understanding the services running on discovered hosts and the attack surface they present.
- **Network Topology Mapping:** Creating a map of the network’s layout, including routers, switches, and other infrastructure elements.
- **Operating System Fingerprinting:** Identifying the OS running on hosts to tailor attacks to potential vulnerabilities.
- **Service Version Detection:** Pinpointing the versions of services to discover vulnerabilities associated with specific versions.
- **Identifying Security Measures:** Detecting firewalls, intrusion prevention systems, and other defenses to strategize testing.

#### Nmap

Nmap (Network Mapper) is an open-source tool for scanning networks to discover hosts, open ports, and potential vulnerabilities. It is a standard tool for security professionals and penetration testers due to its versatility and range of features:

- **Host Discovery:** Identifies live hosts using techniques like ICMP, ARP, or TCP/UDP probes.
- **Port Scanning:** Discovers open ports on target hosts to assess network exposure.
- **Service Version Detection:** Determines the versions of services running on open ports to identify vulnerabilities.
- **Operating System Fingerprinting:** Attempts to identify the operating system of target hosts based on scan data.
### Host-Discovery

Host discovery is identifying live hosts on a network before moving on to vulnerability assessments. Different techniques are used depending on the network's characteristics, stealth requirements, and the test's objectives.

**Host Discovery Techniques:**

- **Ping Sweeps (ICMP Echo Requests):** Sends ICMP Echo Requests (pings) to a range of IP addresses to detect live hosts. While this method is quick and widely supported, it can be easily blocked by firewalls or host configurations and is often detectable by network defenses.
- **ARP Scanning:** Uses Address Resolution Protocol (ARP) to discover hosts on local networks within the same broadcast domain. This method is highly effective for local networks but is limited to local subnets and cannot be used across different networks.
- **TCP SYN Ping (Half-Open Scan):** Sends TCP SYN packets (often to port 80) to check if a host responds with a SYN-ACK, indicating it is alive. This technique is stealthier than ICMP ping and can bypass some firewalls that allow outbound connections. However, some hosts may not respond due to security measures like firewalls.
- **UDP Ping:** Sends UDP packets to specific ports to check for a response, useful for detecting hosts that do not respond to ICMP or TCP probes. The effectiveness of this method can be limited by firewalls, which may block or filter UDP traffic.
- **TCP ACK Ping:** Sends TCP ACK packets to a host, and if a TCP RST (reset) is received, the host is confirmed to be alive. This method is useful when ICMP is blocked, but its success can depend on the network's security configuration.
- **SYN-ACK Ping:** Similar to TCP ACK Ping but sends SYN-ACK packets. A TCP RST response indicates the host is active. This method can be useful when other discovery methods are blocked, but it may be less reliable if security configurations are strict.

The choice of technique depends on the network's defenses and the specific goals of the penetration test. Factors like firewall configurations, security devices, and network characteristics will influence the effectiveness of each method.

### Ping-Sweeps

A ping sweep is a network scanning technique used to identify live hosts (such as computers or servers) within a specific IP address range by sending ICMP Echo Request (ping) messages. The goal is to observe which IP addresses respond to determine which devices are active on the network.

Ping sweeps work by sending ICMP Echo Requests (Type 8) to the target addresses. 
- If a host is online, it responds with an ICMP Echo Reply (Type 0), confirming its presence. 
- If no reply is received, it could indicate the host is offline or unreachable. However, this lack of response could also result from firewalls blocking ICMP traffic, network congestion, or temporary unavailability.

While ping sweeps are a simple way to check host reachability, results should be interpreted in the context of the network's conditions and security settings.
### Host-Discovery-with-Nmap

Nmap usually begins with a ping scan for host discovery followed by a port scan. To disable the port scan and only perform host discovery, you can use the `-sn` option.

```
nmap -sn target
```

 By default, Nmap's host discovery sends TCP SYN to port 443, TCP ACK to port 80, and an ICMP timestamp request. Some scans require admin privileges depending on the type of packets used. The main limitation of Nmap's ping scan is that it still relies on ICMP, which may be blocked or limited by some networks.
 
#### TCP SYN Ping - Host Discovery Scan  | `-PS` 

For the `-sn` host discovery scan, you can override what kind of packets you send with the `-P...` option. The `-PS` option will send SYN packets to the target. By default, it will send the SYN packets to port 80 to determine if the target is online, unless a different port is  specified. 
- <u>If the port is open</u>, the target will respond with a SYN-ACK packet. 
- <u>If the port is closed</u>, the target will respond with an RST packet, indicating the system is alive.
- <u>If no response is received</u>, this could indicate the host is offline or that a firewall is blocking the packets. Some firewalls drop outgoing/incoming SYN-ACK or RST packets, affecting the accuracy of this method.

```
nmap -sn -PS target_ip
```

#### TCP ACK Ping - Host Discovery Scan  |  `-PA` 
            
The `-PA` option will send ACK packets. The normal TCP process is ‘`SYN > SYN ACK > ACK`’ if you send just the ACK packet this the target should respond with a RST reset packet. Not recommended since ACK packets are typically blocked and RST packets are generally blocked by firewalls so the results of the scan isn’t entirely reliable. _However, this scan can be used to tell if a firewall is present_
```
nmap -sn -PA target_ip
```

#### ICMP Echo - Host Discovery Scan  | `-PE` | 

The `-PE` option will send will send ICMP echo requests, also not really recommended.
```
nmap -sn -PE target_ip
```


### Customizing Host Discovery Scans

- **Specify certain number of IPs and not a range**: Just have a space between each IP
```
nmap target1 target2
```

- **Scan IPs using a list** | Use `-iL` to pull the targets from a file.This can be a txt file and the target IPs need to be listed line-by-line:
```
nmap -sn iL file.txt
```
    
- **SYN Discovery using a custom port** | Instead of using port 80, you can use another port
```
 nmap -sn -PS[port_num] target
```
		
- **Specify a range of ports to try SYN packets on** | Recommended since this can work with ports from windows and linux can be found in a range of 1-1000
```
nmap -sn -PS[port_start] - [port_end] target
```
		
- **Specify specific ports**
```
nmap -sn -PS<port1>, <port2>, <port3>… <target>
```

- **Disable ARP** : Even if you use `-PS` (which sends TCP SYN packets to probe hosts), NMap can also perform an **ARP ping scan** automatically for host discovery. This happens when scanning a local subnet, because ARP is the most effective way to detect active hosts on local networks. So you can include `--disable-arp-ping` to prevent that if you want but `--send-ip` should also accomplish this.

```
nmap -sn target --disable-arp-ping
```

---
#### Host Discovery Methodology:

1. First run an initial host discovery scan for a general sweep of the network:
```
nmap -sn -v -T4 <target>
```
- `-v` = Increases verbosity and includes a rationale
- `-T4` = Increases scanning speed/number of packets

2. If you find a set of IPs, you can reiterate through the process and perform as TCP SYN ping scan again on some common Windows/Linux ports to try to identify any systems that might be blocked icmp packets/Echo requests like Windows

```
nmap -sn -PS21,22,25,80,445,3389,8080 -PU137,138 -T4 <target>
```
- `21` = FTP
- `22` = SSH
- `25` = SMTP
- `445` = SMB
- `3389` = RDP
- `8080` = Webserver stuff but not 100% where on windows, maybe file explorer
- `UDP137 & 138` = Windows Netbios

---
### Port-Scanning-with-Nmap

Port scanning helps identify active services and their states on target systems. By default, before performing the port scan, Nmap will first perform host discovery by sending ping probes to check if hosts are online. These probes use ICMP traffic, but Windows firewalls often block ICMP by default. Preventing the ping probes will effectively just be the port scan.

#### Port Scan without Ping Probes | `-Pn`

To skip the host discovery, use the `-Pn` option so that Nmap goes straight into the port scan and doesn't send any ping probes.

```
nmap -Pn <target_ip>
```

### Port Scan Types

 Nmap has a range of port scan types designed for different needs and situations. Each type interacts with the target's ports in its own way.

##### TCP SYN Scan (Stealth/Half Open) | `-sS` 

The TCP SYN scan is a port scanning technique that exploits the TCP three-way handshake to determine the status of ports on a target. Nmap will first send a SYN packet to a specified port and awaits a response. If the target port is open, the target will reply with a SYN-ACK packet, indicating readiness to establish a connection. However, instead of completing the handshake by sending an ACK packet, Nmap responds with a RST (reset) packet terminating the connection attempt. 

User accounts with elevated privileges can run the TCP SYN Scan with the `-sS` option, but it's also ran by default if Nmap is running under root/admin account. Elevated privileges are necessary to execute the scan since since sending SYN packets and receiving responses for TCP connections typically requires raw socket access, which is restricted to privileged users.

The SYN scan is recommended since SYN packets are common to see on the network so it doesn’t raise any alarms. Also, since the SYN scan doesn’t complete the three-way handshake, it prevents creation of connection logs entries on the target system.

```
nmap -Pn -sS 10.4.24.205
```

##### TCP CONNECT Port Scan (_Not Recommended_) | `-sT` 

This works about the same as the TCP SYN scan but Nmap would complete the three-way handshake by responding with an ACK on open ports to which would initiate a TCP connection. This scan is the default option for non-privileged users. This is not recommended because most OS/IDS systems log established tcp connections and is likely will create connection log entries. This can be slightly more reliable but only used when there’s no concern for the noise on the network.
```
nmap -Pn -sT 10.4.24.205
```

**UDP Scan:** Specify `-sU` to do UDP ports | Nmap uses TCP by default, you can do all of the same options as far the the number of ports you want to scan here as well.

```
nmap -Pn -sU 10.4.26.17
```

##### Port States

The port states are either `Open`, `Closed`, or `Filtered`:

- `Open` would mean that a SYN-ACK response was returned from the target on that port. Nmap would return an RST packet to terminate the TCP connection.
- `Closed` state would mean the target responded with an RST packet which would let nmap know that either 1.) there isn’t any rules configured on that port or 2.)  a stateful firewall ( like windows firewall) isn’t active.
- `Filtered` state means that the target didn’t respond with either a SYN-ACK or RST packet, so nmap couldn’t conclusively determine if its open or not. _This would likely mean target has a stateful host-based firewall like windows firewall configured_.

#### Scan for all (certain) TCP ports

By default, when Nmap performs a port scan without any extra options, it scans the top 1,000 most commonly used ports, based on Nmap's internal database. You can use the `-p...`  option to adjust the ports you can scan, you can choose to include spaces but its optional:

- Scan a Port ⇒ `-p`
```
nmap -Pn -p 80 10.4.26.17
```
- Scan more than one port ⇒ `-p <Port1>, <Port2> …`
```
nmap -Pn -p 80, 445, 3389 10.4.26.17
```
- Scan a port range ⇒ `-<Port1> - <Port2>` 
```
nmap -Pn -p1-65635 10.4.26.17
```

- All TCP Ports ⇒ `-p-`  =  This scans all 65,535 TCP ports
```
nmap -Pn -p- 10.4.26.17
```

- Scan top 100 tcp ports ⇒ `-F` (Fast Scan)
```
nmap -Pn -F 10.4.26.17
```


**Port Scanning Methodology:**

1. Whenever doing a pentest, you can start with a fast scan (`-F` | top 100 tcp ports) to see what you’re dealing with like services, the operating system.
- `nmap -Pn -F <target>`
2. After that you can perform a scan of the entire TCP port range using `-p-`. This can take a while you can you can adjust the scanning speed with the timing template with T4 or T5.

- `nmap -Pn -p- -T4 <target>`

Tip: Never assumed each windows or linux system is configured the same.

---

### Nmap Service Version and Operating System Detection

Extracting more information on the operating system and services available on open ports. This is helpful with vulnerability assessments and threat modeling. Can find misconfigured services, look for ways in, services affected by vulnerability, unpatched systems etc:
##### Service Version Detection

- **Check Service Versions:** Include `-sV` flag to get the name & version of services. This can take slightly longer since there needs to be enumeration on each service and port. This information needs to be taken down so it can later be used in the exploitation phase to search vulnerabilities check if any of these services is misconfigured or susceptible to any known vulnerability.

```
nmap -sS -sV -p- -T4 192.239.101.3
```

- **More Aggressive Service Versions Scan**: Include `--version-intensity <num>` | This performs more enumeration on the services to be more conclusive if necessary. This option controls how many probes Nmap sends during service version detection, with `<num>` ranging from 0 to 9. Lower numbers (like 0 or 1) make Nmap send fewer probes for quicker, less intrusive scans with potentially less accurate results, while higher numbers (closer to 9) send more probes for slower, more thorough scans that are more likely to accurately detect the service version. Nmap is generally accurate with the services/version so it might not be any different from the normal `-sV` scan. 

##### Operating Systems Detection 

- **Check Operating Systems:** Include `-O` flag to try to find the operating system. This is not always conclusive/accurate:
```
nmap -sS -sV -O -p- -T4 192.168.101.3
```

- **More aggressive Operations Scan**: The  `--osscan-guess` option performs a more aggressive scan to try to guess the operating system if the basic operation system scan `-O` doesn’t return conclusive results. For linux systems, this will return the linux kernel being used and not a specific distribution. For windows, it should return the Windows version and its build number.

---

### Nmap Scripting Engine (NSE)

Nmap Scripting Engine allows users to write scripts and automate certain tasks like port scanning, vulnerability scanning etc. The script engine has been around for a while and there has been a lot of NSE written in the LUA language that has been created and shared in the community. 

##### Where to find/search NSE Scripts: 

The  pre-packaged NSE scripts are found in the `/usr/share/nmap/scripts` directory. The pre-packaged NSE scripts generally have the service mentioned in the scripts name, so you could search for it using something like piping the `ls` command to the `grep`  command:

```
ls -al /usr/share/nmap/scripts | grep -e “http”
```
- The `ls` command is used to list the scripts directory and the `grep` command is filtering out for script related to 'http' (in this case)

**Lookup a particular NSE script:** Use `--script-help=<script_name>` to lookup nmap scripts to get a description and tell if a script is safe for using without affecting the system. 

```
nmap --script-help=mongodb-databases
```

**Run specific Nmap script** | Use `--script=<script_name>` to run a specific script. You don’t need to provide the nse extension, include the equal sign or scan all the TCP ports. You can bring it down to just the port that the service was observed on. Multiple scripts can be ran by using commas to separate them.

```
nmap --script=mongodb-databases 10.10.50.49
```
- **Perform multiple scans off a keyword** | Wildcard `*` character | You can use the wildcard character after a keyword to run all of the scripts under that keyword

---

**Nmap Script Scan Categories:**

These NSE scripts are categorized to serve a particular purpose, from authentication mechanisms and brute-force attacks to providing basic but useful information about open services on the network: 

- **Auth**: Scripts for authentication mechanisms/credential specific scripts
- **Broadcast**: Used to facilitate broadcast/multicast to help discover host on the network
- **Brute**: Brute Force attempts

**Default**: Nmap has a library of default NSE scripts that it can safely be run against targets without negatively impacting the target system. You can run these scripts using the `-sC` option which  will run the relevant scripts against the target given open ports/services. This way, you can gather useful information on the target without engaging the target in the dangerous way.

```
nmap -sS -sV -sC -p- 192.168.101.3
```

#### Aggressive Scan 

The Agressive scan `-A`  is the  operating system (`-O`), service version (`-sV`) and default script scan (`-sC`) combined into one option.

```
nmap -Pn -F -A 10.4.26.17
```

---
**Pentesting Tips**

- You can get a lot of information from services which can help you learn about the underlying system involved.
- **Tip on Misconfiguration**: In some cases where we perform these scans, we could find potential attack vectors like a service that doesn't require authentication.

### Evasion-Performance-Output


**Firewall and IDS Detection**

**Check for stateful firewalls (especially for Windows systems)**: Can use the ACK port scan with nmap (`-sA`) , if the ports return ‘filtered’ then this is likely due to a host based firewall especially on windows systems. Results with ‘unfiltered’ would mean its likely that there isn’t any stateful firewall (or Windows FW isn’t active). Don’t need to scan every port, you can scan a few here.

```
nmap -Pn -p445 -sA target
```

**Evade IDS | Use fragmented packets** | `-f` | Fragmentation would take the packets that nmap sends and make them smaller packets and make them smaller so that IDS systems cant tell from analyzing each fragment what exactly is going on. IE TCP SYN/ACK packets. Most recommend. the returned packets from the target are not fragmented.

```
nmap -Pn -sS -f target
```
	
    
**Fragment with custom MTU** | `-f <opt_mtu_val>` | Minimum Transmission Unit (MTU) refers to the maximum size of the **payload** (or data) that can be transmitted in a single packet at the network without needing to be fragmented. The total size of the packet will include:
- **IP header**: Typically 20 bytes for IPv4.
- **TCP/UDP header**: Typically 20 bytes for TCP or 8 bytes for UDP.
- **Payload**: Based on the custom MTU. In IPv4, the standard MTU is 1500 bytes for Ethernet.

Using a custom MTU in Nmap allows you to send packets with a specified size. This can help bypass security measures that inspect packets based on standard sizes, or don’t properly reassemble/ inspect fragmented traffic.

---

**Spoofing/Decoys**

Spoofing is disguising/obscuring the true origin of the scan. This can involve manipulating IP addresses, headers, or packet attributes to mimic legitimate traffic or to introduce noise that makes analysis more difficult. Spoofing typically requires being on the same network as the spoofed address to ensure packets can flow correctly.

- **Using Decoy IPs for Scans** |  `-D <IP_Address>`  = This option adds multiple decoy IP addresses as the src of the scan. While the decoys send packets, the actual responses from the target are returned to your real IP, exposing the actual scanning system if monitored closely.
- **Changing TTL for Packets** | `--ttl <value>`  = Modifying the TTL value helps mimic the behavior of other systems by altering how long a packet stays in transit before it expires. This can create more plausible decoys by making the packets resemble those from a different type of network environment.
- **Changing Packet Data Lengths** | `--data-length <value>`  = This option assigns random or specified data lengths to packets, which can confuse intrusion detection systems by making your scan traffic seem irregular or less predictable.
- **Preventing DNS Resolution** | `-n`  = By default, Nmap tries to resolve hostnames to IPs and vice versa, which could reveal scanning activity through DNS lookups. The `-n` flag prevents DNS resolution, helping you stay stealthier.
- **Using a Different Source Port** | `-g <port>`  = This option allows you to specify the source port from which the scan appears to originate. For example, setting it to `53` could make the scan look like legitimate DNS traffic, as DNS typically uses port 53. This method can bypass firewalls or intrusion detection systems configured to allow traffic on certain ports.

---

**Optimizing Nmap Scans**

- **Host timeout** = `--host-timeout <time>` = Amount of time before nmap gives up on the target, can be useful for scans on a large number of IPs (Can use around 30s for large networks). Should be used carefully as you can miss systems if you give too little time here.
- **Space out the scan probes** = `--scan-delay` = Spaces out the sent scanning probes in seconds/milliseconds. Try setting the scan delay to 15 secs if stealth is the goal but remember that this will increase the time to complete scan.
- **Speed up/Slow down scans (Timing Templates)**: Use timing template ranges from `-T0 → -T5` to adjust the scanning speed . Higher is faster, lower is slower. Slow is good to evade IDS detection, slowing down scans can make network activity less suspicious. The faster timing templates is good for getting scan results faster.
	- `-T0` = (paranoid)
	- `-T1` = (sneaky)
	- `-T2` = (polite)
	- `-T3` = (normal)
	- `-T4` = (aggressive) = Assumed to be on faster/reliable network
	- `-T5` = (insane) = Not recommended in production environment as it can lead to stressing a network and possibly causing a DoS.

---

**NMAP SCANNING METHODOLOGY**

1. If the goal is to make the scans appear as covert as possible, common options to use in conjunction:
	- Scan delays `--scan-delay` or Slow Timing Templates `-T0 → -T1`
	- Decoy IPs > `-D <IP_Address>`
	- Fragmentation | `-f <opt_mtu_val>`
2. If you’re not considering the stealth of the scan you can use `-T3 or -T4` timing templates to increase the speed and accuracy of scans.

---
#### Nmap Output Formats

You can specify different types of outputs of nmap scan results to save. Regardless of the output, the terminal will still display the nmap scan output:

- **Normal Output** | `-oN` > `-oN file_name.txt` | Same format in the terminal screen, this normally saved in txt format.
	
- **XML Output** | `-oX` > `-oX file_name.xml` | This format can be imported to a framework like Metasploit which would include host,ports,etc that can be added to a Metasploit database. This allows you to keep a centralized location for all of the hosts, you can refer back to individual hosts, so even if you lose your scan they’re saved in the metasploit database that you can refer back to. You can make workspaces within Metasploit for pentests and create new workspaces for each pentest. This can be helpful for looking at previous pentes
			
- Greppable | `-oG` > `.txt , .grep , or other similar format` = Allows the information to be used with Grep and potentially used for automation purposes
- `-oS` | Script Kiddle = Not used often
- `-oA` | All in one output of `-oN` ,`-oX`, and `-oG` outputs.
- `-v` | Increases verbosity
- `--reason` | Displays the reason a port is in a particular state



- **Importing Nmap xml Scan to Metasploit:**
	
	1. Make sure postgresql is started, this is what metasploit uses
		
		1. `service postgresql start`
			
			
	2. Start Metasploit = `msfconsole`
	
		
	3. Create a new workspace = `workspace -a <workspace_name>`
				
	
	**Make sure that metasploit is connected to postgresql = `db_status`
			
	1. Import the Nmap XML File: `db_import filename.xml`
		
		
	
	**Done!** You can view the hosts using hosts in the metasploit console
	
	- View the hosts using `hosts` , if you had an nmap scan that returns Operating system information it will all so populated into metasploit
		
	- View the open services using `services`
					
	- Or perform nmap scans from metasploit using db_nmap. The nmap scans from here will automatically be updated in metasploit
			




---

**NMAP SCAN OUTPUT METHODOLOGY**

In normal circumstances, the Normal Output (`-oN file_name.txt` ) is what you’re generally going to use.