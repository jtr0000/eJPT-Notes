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


General Syntax:
```
nmap -sn <subnet> --send-ip
```

Example: 
```
nmap -sn 10.14.18.0/24 --send-ip
```



- `--send-ip` = When running Nmap on a local ethernet network, Nmap will use ARP to run host discovery since its efficient at discovery within a local network. The `--send-ip` will override that functionality.