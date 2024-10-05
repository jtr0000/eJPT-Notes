Table of Contents
- Host Discovery with Nmap
- 

---

## Host Discovery with Nmap

By default, Nmap uses multiple techniques to identify live hosts, including:

- **ICMP Echo Request:** This is the traditional "ping" message used to check if a host is online.
- **TCP SYN to Port 443:** Sends a TCP SYN packet to port 443 (commonly used for HTTPS) to check for a response.
- **TCP ACK to Port 80:** Sends a TCP ACK packet to port 80 (used for HTTP) to detect whether the host is online, even if ICMP is blocked.
- **ICMP Timestamp Request:** Sends a timestamp request as another ICMP-based method for identifying live hosts.
##### A. Default Nmap Host Discovery Scan (`-sn`)

Nmap by default would initially run a ping scan for host discovery before performing a port scan. The `-sn` option in Nmap is used to perform host discovery without a port scan,  referred to as a "ping scan." This means Nmap will identify which hosts are online without scanning ports on those hosts. Nmap's ping scan is that it still relies on ICMP by default, which many firewalls block or filter so this can lead to incomplete results.  

```
nmap -sn <target> 
```

Example: 
```
nmap -sn 10.14.18.0/24
```

Certain scans, including those that involve sending SYN or ACK packets, require administrative privileges (i.e., using `sudo` on Linux or running as an administrator on Windows) because they rely on raw packet manipulation, which interacts directly with the network stack. 
##### B. TCP SYN Ping Scan (`-PS` )

Like the default host discovery, the `-sn` option is included to tell Nmap to skip the port scan and focus only on host discovery. The `-PS` option  overrides the packets that would be sent in the host discovery with TCP SYN packets flag is set.  I think of this as  “**P**ackets with the **S**YN flag”.

```
nmap -sn -PS <target>
```

By default, the option sends SYN packets to port 80 to determine if the target is online unless otherwise specified. 
- <u>If the port is open</u>, the target will respond with a *SYN-ACK* packet.
- <u>If the port is closed</u>, the target will respond with an *RST* packet, indicating the system is alive.
- <u>If no response is received</u>, this could indicate the host is offline or that a firewall is blocking the packets. Some firewalls drop outgoing/incoming SYN-ACK or RST packets, affecting the accuracy of this method.
##### C. TCP ACK Ping Scan (`-PA` )

This is a ping scan that send ACK packets. The normal TCP process is ‘`SYN > SYN ACK > ACK`’ if you send just the ACK packet this the target should respond with a RST reset packet. Not recommended since ACK packets are typically blocked and RST packets are generally blocked by firewalls so the results of the scan isn’t entirely reliable. <u>However, this scan can be used to tell if a firewall is present</u>.

```
nmap -sn -PA <target>
```

##### D. ICMP Echo Ping Scan (`-PE` )

The `-PE`  will send ICMP echo requests for the ping scan,  not really recommended.

```
nmap -sn -PE <target>
```


#### ARP Requests
Even if you use `-PS` (which sends TCP SYN packets to probe hosts), NMap can also perform an **ARP ping scan** automatically. This happens when scanning a local subnet, because ARP is the most effective way to detect active hosts on local networks. So you can include `--disable-arp-ping` to prevent that if you want but `--send-ip` should also accomplish this.


General Syntax:
```
nmap -sn <subnet> --send-ip
```

Example: 
```
nmap -sn 10.14.18.0/24 --send-ip
```



- `--send-ip` = When running Nmap on a local ethernet network, Nmap will use ARP to run host discovery since its efficient at discovery within a local network. The `--send-ip` will override that functionality.



---

# Network Protocols and Packet Structure

In computer networks, hosts communicate by using network protocols, which are crucial for ensuring compatibility between different hardware and software systems. When hosts communicate, they do so through <u>packets</u>—streams of bits representing the data being exchanged. Packets are transmitted over physical media and contain two main components: headers and payloads. The <u>header</u> includes protocol-specific structures, while the <u>payload</u> carries the actual information being sent, such as an email or file.

##### OSI Model

The <u>OSI model </u>(Open Systems Interconnection) is a framework developed by the International Organization for Standardization (ISO) to standardize network functions and improve interoperability. The OSI model serves as a guideline for understanding how different network protocols and communication processes work together. It is not a strict blueprint but provides a useful reference for designing network architectures. It breaks down the process of network communication into seven distinct layers:

1. **Physical Layer (Layer 1)**: Deals with physical connections between devices.
2. **Data Link Layer (Layer 2)**: Manages access to the physical medium and performs error checking.
3. **Network Layer (Layer 3)**: Handles logical addressing and routing across networks.
4. **Transport Layer (Layer 4)**: Ensures reliable, end-to-end communication.
5. **Session Layer (Layer 5)**: Manages sessions between applications.
6. **Presentation Layer (Layer 6)**: Translates data formats for compatibility between applications.
7. **Application Layer (Layer 7)**: Provides network services to end-users. 

##### Internet Protocol

The Internet Protocol operates at the network layer and is foundational to the functioning of the Internet. Its primary roles include logical addressing, routing, and packet reassembly. There are two versions of IP in use:

- **IPv4**: Uses 32-bit addresses and is the most commonly used protocol on the Internet today.
- **IPv6**: Expands the address space with 128-bit addresses, designed to overcome the limitations of IPv4.

IP addresses are structured hierarchically to uniquely identify devices across networks. Each IP packet contains a header, which holds the source and destination IP addresses, and a payload, which contains the actual data being transmitted. IP also supports fragmentation, which allows large packets to be divided into smaller units for transmission.

**Two additional protocols play a key role in IP-based networks:**

- **ICMP** (Internet Control Message Protocol): Used for error reporting and network diagnostics.
- **DHCP** (Dynamic Host Configuration Protocol): Automatically assigns IP addresses to devices, simplifying network configuration.

**IPv4 Packet Structure and Addressing**

An IPv4 address consists of four bytes (32 bits) separated by dots, and it is used to identify devices on a network. IPv4 packets include several important header fields:
- **Source/Destination IP Address**: Identifies the sender and receiver.
- **Time-to-Live (TTL)**: Limits how long a packet can stay on the network before being discarded.
- **Protocol**: Specifies the type of data the packet is carrying, such as TCP or UDP.

Special ranges of IPv4 addresses are reserved for specific purposes. For instance, addresses like 0.0.0.0 and 127.0.0.0 are reserved for special uses, as outlined in RFC5735.

##### Transport Layer and Protocols

The transport layer is the fourth layer in the OSI model and is responsible for managing end-to-end communication between devices. It ensures reliability, error detection, flow control, and segmentation. Two key protocols operate at this layer:

**Transmission Control Protocol (TCP)** is connection-oriented, meaning a connection is established before any data is exchanged. It guarantees reliable data delivery through acknowledgments and ensures that data is delivered in the correct order. TCP's process for establishing a connection is known as the three-way handshake, involving a sequence of SYN, SYN-ACK, and ACK messages.
- **TCP Header Structure**: Includes source and destination ports, which help identify the sending and receiving applications.
- **TCP Ports**: TCP ports are categorized into three ranges:
	- Well-Known Ports (0-1023): Reserved for standard services like HTTP (port 80) and FTP (port 21).
	- Registered Ports (1024-49151): Assigned to specific applications.
	- Dynamic/Private Ports (49152-65535): Used for temporary or private connections.

**User Datagram Protocol (UDP):** Unlike TCP, UDP is connectionless and does not guarantee reliable delivery. It is ideal for real-time applications that prioritize speed over reliability, such as streaming and gaming. UDP has a smaller header size, which results in lower overhead compared to TCP.

TCP vs. UDP

TCP is preferred for applications that require reliable, ordered data transmission, such as web browsing or file transfers. In contrast, UDP is better suited for applications where speed is more important than reliability, such as live video or online gaming. While TCP ensures that data reaches its destination in order and without loss, UDP offers lower latency by foregoing these guarantees.