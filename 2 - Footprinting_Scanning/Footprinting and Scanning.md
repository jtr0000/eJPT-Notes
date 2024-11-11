#### Table of Contents

1. [Networking Fundamentals ](Footprinting%20and%20Scanning.md#networking)
2. [Network Mapping (What is Nmap) ](Footprinting%20and%20Scanning.md#networking-mapping)
3. [Host Discovery ](Footprinting%20and%20Scanning.md#host-discovery)
4. [Ping Sweeps](Footprinting%20and%20Scanning.md#ping-sweeps)
5. [Host Discovery with Nmap ](Footprinting%20and%20Scanning.md#host-discovery-with-nmap)
6. [Port Scanning with Nmap ](Footprinting%20and%20Scanning.md#port-scanning-with-nmap)
7. [Evasion, Scan Performance and Output](Footprinting%20and%20Scanning.md#evasion-performance-output)
----

## Networking

In computer networks, hosts use network protocols to communicate with each other. These protocols make sure different systems—regardless of hardware or software—can interact effectively. Different network protocols tailored for specific services and objectives. Communication between hosts via protocols is managed through packets.

#### Packets

At its core, networking is about moving information between computers using packets. Packets are streams of bits sent as electric signals over physical connections like Ethernet or wireless connections like Wi-Fi. These signals get translated into bits (0s and 1s) that carry the data. Each packet has two main parts: a header and a payload. The header follows a specific format to help the receiving system figure out how to handle the packet, while the payload contains the actual data, like part of an email or a chunk of a file.

### OSI Model

The OSI model, short for Open Systems Interconnection, is a framework developed by the ISO to make network communication easier to understand and manage. It breaks down the process into seven layers, each handling a specific part of the communication. This layered approach helps simplify the design, implementation, and troubleshooting of network systems.

1. **Physical Layer** (Cables/Cat6/ Anything that plugs in): Handles the actual transmission of raw data bits over a physical medium, like Ethernet cables or fiber optics, and defines hardware specifications such as electrical signals and data rates.
2. **Data Link Layer** (MAC Addresses/Switching): Manages the transfer of data frames between connected devices, ensuring reliable communication through error detection and flow control. It also handles MAC addresses and media access, using protocols like Ethernet and Wi-Fi.
3. **Network Layer** (IP Addresses, Routing): Manages logical addressing and routes data across networks, making sure packets take the best path to their destination. Key protocols include IP (Internet Protocol) for routing.
4. **Transport Layer** (TCP/UDP): Ensures reliable data transfer between systems, breaking data into segments, handling flow control, and providing error recovery. This layer includes protocols like TCP and UDP.
5. **Session Layer** (Session Management): Manages and controls communication sessions, establishing, maintaining, and terminating connections between applications.
6. **Presentation Layer**(WMV/JPEG/MOV): Translates data formats, handling encryption, compression, and formatting so that data is presented in a way the receiving system can understand. 
7. **Application Layer** (HTTP/SMTP/DNS/ Apps): The closest layer to the end-user, providing services like web browsing, email, and file transfer. 
    
### Network Layer  
The Network Layer, or Layer 3 of the OSI model, handles logical addressing, routing, and the forwarding of data packets across different networks. Its main objective is to determine the best path for data transmission from source to destination, even if they are on separate networks. This layer abstracts the underlying physical networks to create a cohesive internetwork.

**Network Layer Protocols**  
The Network Layer uses several important protocols, including:

- **Internet Protocol (IP)**: Central to internet communication, IP manages logical addressing, routing, and packet fragmentation and reassembly. Two major versions are in use:
    - **IPv4**: Uses 32-bit addresses, forming the backbone of current internet communication. However, its limited address space has necessitated the development of IPv6.
    - **IPv6**: Uses 128-bit addresses to provide a vastly expanded address space, represented in hexadecimal notation.
- **Internet Control Message Protocol (ICMP)**: Used for error reporting and diagnostics, ICMP supports utilities like ping and traceroute for network testing.

### Internet Protocol (IP)
The Internet Protocol (IP) is the backbone of internet communication, operating at Layer 3/Network Layer of the OSI Model. It assigns logical addresses to devices, enabling communication across different networks. IP also handles fragmentation, breaking large packets into smaller pieces to accommodate varying Maximum Transmission Unit (MTU) sizes across networks, and ensures they are reassembled correctly at the destination.

####  IP Addresses
An IP address is a unique logical identifier for network interfaces of devices on a network, typically written as four numbers separated by dots, like 192.168.1.100. In IPv4, these addresses consist of four octets (or bytes), each ranging from 0 to 255, forming a 32-bit structure. IPv4 supports around 4 billion unique addresses, which are managed by routers to direct traffic efficiently. However, due to the rapid growth of connected devices, IPv6 was introduced. IPv6 uses a 128-bit format, vastly increasing the number of available addresses to meet future demands. Both IPv4 and IPv6 are essential protocols that ensure reliable and efficient network communication worldwide. They are structured using subnets, network classes, and CIDR (Classless Inter-Domain Routing) notation. 

#### Reserved IP Addresses
Reserved IP addresses are special ranges set aside for specific purposes within networks. Unlike regular IP addresses, these addresses aren’t routable on the public internet and serve specific functions like local network communication, testing, and network management. The purposes of each reserved range are defined by standards, including RFC5735. Key reserved IPv4 address ranges include:
- **0.0.0.0 – 0.255.255.255**: Refers to “this” network, often used in routing configurations.
- **127.0.0.0 – 127.255.255.255 (Loopback)**: Used for local host communication; commonly for testing network software on the local machine, with 127.0.0.1 as the standard loopback address.
- **169.254.0.0 – 169.254.255.255 (Link-Local)**: Automatically assigned to a device when it can’t obtain an IP from a DHCP server, useful for temporary or ad-hoc local connections.
- **224.0.0.0 – 239.255.255.255 (Multicast)**: Used to send data to multiple devices simultaneously within a network, typically for streaming or routing protocols.
- **255.255.255.255 (Broadcast)**: Sends messages to all devices on a local network, often used for network discovery or critical announcements.

#### Private IP Addresses
Private IP addresses are a subset of reserved addresses specifically used for internal networks, like home or office LANs. These addresses aren’t accessible from the internet, providing security and flexibility for internal communication. They are divided into classes that determine the number of available networks and hosts:
- **Class A**: 10.0.0.0 to 10.255.255.255 – Suitable for large networks, common in larger organizations.
- **Class B**: 172.16.0.0 to 172.31.255.255 – Often used in medium-sized networks.
- **Class C**: 192.168.0.0 to 192.168.255.255 – The most common for home and small business networks, supporting up to 254 hosts.

These reserved and private IP ranges play distinct roles in organizing and securing network communication across different environments.

**NAT**

NAT (Network Address Translation) allows multiple devices to be able to share the same public IP address. This is a workaround that allows use to not use all of the public IP addresses available.

**Subnetting**  
Subnetting divides large IP networks into smaller, more manageable sub-networks, improving network efficiency and security.
#### IP Header
The IP header of packets contains essential information like the source and destination IP addresses, packet size, and routing details. This metadata helps routers and devices along the network path understand how to handle the packet. Additionally, the header includes fields for error checking, fragmentation control, and protocol identification, ensuring reliable communication. The IP Header contains:
- **Version (4 bits)**: Indicates the IP version (IPv4 or IPv6).
- **Header Length (4 bits)**: Specifies the length of the header.
- **Type of Service (8 bits)**: Manages packet priority and congestion control.
- **Total Length (16 bits)**: Indicates the total size of the packet.
- **Identification (16 bits)**: Used for reassembling fragmented packets.
- **Flags (3 bits)**: Include fragmentation-related flags like "Don't Fragment" and "More Fragments."
- **Time-to-Live (TTL, 8 bits)**: The maximum number of hops a packet can take before being discarded.
- **Protocol (8 bits)**: Specifies the higher-layer protocol (e.g., TCP, UDP, ICMP).
- **Source and Destination IP Addresses (32 bits each)**: Identifies the sender and recipient.

### Transport Layer  

The Transport Layer, the fourth layer of the OSI model, is essential for facilitating communication between devices across a network. It ensures reliable, end-to-end communication and manages error detection, flow control, and the segmentation of data into smaller units. This layer focuses on the ordered and reliable delivery of data between networked devices.

##### Transport Layer Protocols  

The two primary protocols at this layer are:

- **TCP (Transmission Control Protocol)**: A connection-oriented protocol providing reliable and ordered data transfer. TCP ensures data integrity through mechanisms like acknowledgments and retransmissions.
- **UDP (User Datagram Protocol)**: A connectionless protocol that prioritizes speed and efficiency over reliability and order, suitable for real-time applications like streaming and online gaming.

### TCP (Transmission Control Protocol)  

TCP is a connection-oriented transport layer protocol that provides reliable, ordered, and error-checked delivery of data packets over an IP network. It guarantees that data sent from one device is received correctly by the destination device. TCP achieves this reliability through mechanisms like acknowledgement, retransmission, and flow control. It breaks data into smaller packets, assigns sequence numbers to them, and ensures they are reassembled correctly at the receiving end. 

**TCP Header Fields**  

The TCP header contains essential fields that facilitate reliable data transfer:
- **Source Port (16 bits)**: The port number of the sender.
- **Destination Port (16 bits)**: The port number of the receiver.
- **Sequence Number (32 bits)**: Keeps track of the order of data packets to ensure they are delivered correctly.
- **Acknowledgment Number (32 bits)**: Indicates the next expected sequence number from the sender, used to acknowledge received data.
- **Data Offset (4 bits)**: Specifies the length of the TCP header.
- **Control Flags (9 bits)**: Flags like SYN, ACK, and FIN that control the setup, management, and termination of connections.
- **Window Size (16 bits)**: Determines the amount of data the sender is willing to receive, aiding in flow control.
- **Checksum (16 bits)**: Validates the integrity of the data by checking for errors in the header and payload.
- **Urgent Pointer (16 bits)**: Used when the URG flag is set to indicate that certain data should be prioritized.
- **Options (Variable)**: Optional settings to enhance TCP performance, such as specifying the maximum segment size or adding timestamps.

#### Three-Way-Handshake

TCP uses control flags (SYN, ACK, FIN) to manage connections and ensure reliable communication.  The three-way handshake is a process used by TCP to establish a connection between devices, involving the exchange of SYN, SYN-ACK, and ACK packets:

1. **SYN** (Synchronize | “Hello”) => The initiating device (often referred to as the client) sends a TCP packet with the SYN flag set to the destination device (often referred to as the server). This initial packet indicates the desire to establish a connection and includes an initial sequence number.

2.  **SYN ACK** packet (Synchronize-Acknowledge | “Hello Back”) => After receiving the SYN packet, the destination device responds with a TCP packet that has both the SYN and **ACK** (acknowledge) flags set. This packet acknowledges the connection request and also includes its own initial sequence number.

3. **ACK** (Acknowledge) => Finally, the initiating device acknowledges the SYN-ACK packet by sending an ACK packet back to the destination. This packet establishes the connection and typically contains an incremented sequence number.

Once the three-way handshake is complete, the connection is established, and both devices are ready to exchange data. The sequence numbers exchanged during the handshake are used to ensure that data is transmitted and received in the correct order.


**UDP (User Datagram Protocol)**  

UDP is a connectionless transport layer protocol that does not provide the same level of reliability as TCP. It is simpler, faster and more lightweight, making it suitable for applications that can tolerate some data loss or delay. UDP does not establish a connection or guarantee delivery of packets. It simply sends data packets from one device to another without waiting for acknowledgements or retransmissions.

**TCP vs. UDP**  

TCP is reliable and connection-oriented, making it ideal for applications requiring data integrity, like HTTP and email. UDP, in contrast, is faster and suitable for real-time applications, despite lacking reliability. Examples include DNS, DHCP, and voice communication.

### TCP/UDP Ports and Protocols

The **TCP Port Range** divides ports into:

- **Well-Known Ports (0-1023)**: Reserved for standard services (e.g., HTTP on port 80, HTTPS on port 443).
- **Registered Ports (1024-49151)**: Used by specific applications (e.g., RDP on port 3389, MySQL on port 3306).

Some common TCP/UDP Ports: 

1. **File Transfer**
	- FTP: Port 21 (TCP) – Transfers files between a client and server.
	- FTPS: Port 990 (TCP) – Secure file transfer using encryption.
	- TFTP: Port 69 (UDP) – Simplified, unsecured file transfer.
	- SMB: Ports 139/445 (TCP) – File and printer sharing. SMB exploits are extremely important for pentesting
2. **Remote Access**
	- SSH: Port 22 (TCP) – Encrypted version of telnet for remote access.
	- Telnet: Port 23 (TCP) – Unencrypted (clear text) remote login to devices.
	- RDP: Port 3389 (TCP) – Remote desktop access to Windows machines.
3. **Web Traffic**
	- HTTP: Port 80 (TCP) – Non-secure web traffic.
	- HTTPS: Port 443 (TCP) – Encrypted web traffic.
4. **Email Services**
	- SMTP: Port 25 (TCP) – Sends and routes email.
	- POP3: Port 110 (TCP) – Receives email, downloads to a device.
	- IMAP: Port 143 (TCP) – Accesses and manages email on a server.
5. **Network Services**
	- DNS: Port 53 (TCP/UDP) – Resolves domain names to IP addresses.
	- DHCP: Ports 67/68 (UDP) – Assigns IP addresses dynamically.
	- NTP: Port 123 (UDP) – Synchronizes system time.
	- SNMP: Port 161 (UDP) – Collects and manages network data.
	- LDAP: Port 389 (TCP/UDP) – Accesses and maintains directory information.
6. **Database**
	- MySQL: Port 3306 (TCP) – Connects to a MySQL database.

---

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


#### Firewall and IDS Detection

**Check for stateful firewalls (especially for Windows systems)**: Can use the ACK port scan with nmap (`-sA`) , if the ports return ‘filtered’ then this is likely due to a host based firewall especially on windows systems. Results with ‘unfiltered’ would mean its likely that there isn’t any stateful firewall (or Windows FW isn’t active). Don’t need to scan every port, you can scan a few here.
```
nmap -Pn -p445 -sA target
```

**Evade IDS | Use fragmented packets** | `-f` | Fragmentation would take the packets that nmap sends make them smaller so that IDS systems cant tell from analyzing each fragment what exactly is going on (IE TCP SYN/ACK packets).  The returned packets from the target are not fragmented. This method is recommended for evading IDS systems. 
```
nmap -Pn -sS -f target
```
    
**Fragment with custom MTU** | `-f <opt_mtu_val>` | Minimum Transmission Unit (MTU) refers to the maximum size of the **payload** (or data) that can be transmitted in a single packet at the network without needing to be fragmented. The total size of the packet will include:
- **IP header**: Typically 20 bytes for IPv4.
- **TCP/UDP header**: Typically 20 bytes for TCP or 8 bytes for UDP.
- **Payload**: Based on the custom MTU. In IPv4, the standard MTU is 1500 bytes for Ethernet.

Using a custom MTU in Nmap allows you to send packets with a specified size. This can help bypass security measures that inspect packets based on standard sizes, or don’t properly reassemble/ inspect fragmented traffic.

---

#### Spoofing/Decoys

Spoofing is disguising/obscuring the true origin of the scan which can involve manipulating IP addresses, headers, or packet attributes to mimic legitimate traffic or to introduce noise that makes analysis more difficult. Spoofing typically requires being on the same network as the spoofed address to ensure packets can flow correctly.

- **Using Decoy IPs for Scans** |  `-D <IP_Address>`  = Nmap’s decoy feature works by sending packets that appear to originate from multiple IP addresses, achieved by spoofing the source address in the packet headers. It transmits identical packets using both the real IP and the decoy IPs. These decoy IPs don’t have to be part of the local network or even valid addresses. Since the decoy IPs are fake, they won't receive responses from the target. However, because the real source IP is included among the decoys, any replies from the target will be sent back to the scanning machine. Even with decoys in place, a target system with logging or IDS mechanisms might still identify the real IP by observing which address receives and processes the responses.
```
nmap -D 192.168.1.100,192.168.1.101,192.168.1.102 target
```

- **Changing TTL for Packets** | `--ttl <value>`  = Modifying the TTL value helps mimic the behavior of other systems by altering how long a packet stays in transit before it expires. This can create more plausible decoys by making the packets resemble those from a different type of network environment.
```
nmap --ttl 64 target
```

- **Changing Packet Data Lengths** | `--data-length <value>`  = This option assigns random or specified data lengths of bytes to packets, which can confuse intrusion detection systems by making your scan traffic seem irregular or less predictable.
```
nmap --data-length 20 target
```

- **Preventing DNS Resolution** | `-n`  = By default, Nmap tries to resolve hostnames to IPs and vice versa, which could reveal scanning activity through DNS lookups. The `-n` flag prevents DNS resolution, helping you stay stealthier.
```
nmap -n target
```

- **Using a Different Source Port** | `-g <port>`  = This option allows you to specify the source port from which the scan appears to originate. For example, setting it to `53` could make the scan look like legitimate DNS traffic, as DNS typically uses port 53. This method can bypass firewalls or intrusion detection systems configured to allow traffic on certain ports.
```
nmap -g 53 target.com
```

---

#### Optimizing Nmap Scans

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
#### Nmap Output Formats

You can specify different types of outputs of nmap scan results to save. Regardless of the output, the terminal will still display the nmap scan output:

- **Normal Output** | `-oN` > `-oN file_name.txt` | Same format in the terminal screen, this normally saved in txt format.
- **XML Output** | `-oX` > `-oX file_name.xml` | This format can be imported to a framework like Metasploit which would include host,ports,etc that can be added to a Metasploit database. This allows you to keep a centralized location for all of the hosts, you can refer back to individual hosts, so even if you lose your scan they’re saved in the metasploit database that you can refer back to. You can make workspaces within Metasploit for pentests and create new workspaces for each pentest. This can be helpful for looking at previous pentes		
- **Greppable** | `-oG` > `.txt , .grep , or other similar format` = Allows the information to be used with Grep and potentially used for automation purposes
- `-oS` | Script Kiddle = Not used often
- `-oA` | All in one output of `-oN` ,`-oX`, and `-oG` outputs.
- `-v` | Increases verbosity
- `--reason` | Displays the reason a port is in a particular state

#### Importing Nmap xml Scan to Metasploit:
	
1. Start Postgresql and the Metasploit console: You can check if  metasploit is connected to postgresql using the  `db_status` command.
```
service postgresql start && msfconsole
```

2. Create a new workspace = 
```
workspace -a <workspace_name>
```
		
3. Import the Nmap XML File: 

```
db_import filename.xml
```

**Done!** You can view the found system (And OS information) using `hosts` in the metasploit console, open services using `services` etc.  You can perform nmap scans from metasploit using `db_nmap`. The nmap scans from here will automatically be updated in metasploit.
		

---

**NMAP SCANNING METHODOLOGY**

1. If the goal is to make the scans appear as covert as possible, common options to use in conjunction:
	- Scan delays `--scan-delay` or Slow Timing Templates `-T0 → -T1`
	- Decoy IPs > `-D <IP_Address>`
	- Fragmentation | `-f <opt_mtu_val>`
2. If you’re not considering the stealth of the scan you can use `-T3 or -T4` timing templates to increase the speed and accuracy of scans.


**NMAP SCAN OUTPUT METHODOLOGY**

In normal circumstances, the Normal Output (`-oN file_name.txt` ) is what you’re generally going to use.