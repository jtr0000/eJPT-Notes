
1. [Introduction (What is Active Information Gathering)](c.%20Active%20Information%20Gathering.md#introduction)
2. [Intro to DNS (Records, Interrogation)](c.%20Active%20Information%20Gathering.md#dns)
<<<<<<< HEAD
3. [DNS Zone Transfers and DNS Zone Transfers ](c.%20Active%20Information%20Gathering.md#dns-zone-transfers)
Footprinting and Scanning
4. f
5. g
6. d
Enumeration
7. r3g
8. g3
9. 5
10. 

=======
3. [DNS Zone Transfers and DNS Zone Transfers ]()
>>>>>>> a6b485cfd619214d11ae884dd77fe02dfc0fbe5f

---
## Introduction

<<<<<<< HEAD
Active information gathering is a phase in penetration testing where the tester directly interacts with the target system or network to collect data and identify vulnerabilities, using techniques like scanning and probing. After passive information gathering, which involves collecting information from public sources, we move to active methods, starting with host discovery to identify network hosts. Next, port scanning is used to find services running on open ports, followed by identifying the operating systems, and finally exploring the Nmap script engine to gather more detailed information.
=======
Active information gathering is a phase in penetration testing where the tester directly interacts with the target system or network to collect data and identify vulnerabilities. This differs from passive reconnaissance, as it involves techniques like scanning, probing, and interacting with network services to gather information.
>>>>>>> a6b485cfd619214d11ae884dd77fe02dfc0fbe5f

---
## DNS

Domain Name System (DNS)  is a protocol that resolves domain names or hostnames to IP addresses, simplifying access to websites by mapping easy-to-remember domain names to their respective IPs. It replaces the need to memorize IP addresses, much like a telephone directory. Public DNS servers like Cloudflare (1.1.1.1) and Google (8.8.8.8) store records of almost all domains on the internet.

**DNS Records**
- `A` (**Address Record**): Resolves a hostname or domain to an IPv4 address.
- `AAAA` (IPv6 Address Record): Resolves a hostname or domain to an IPv6 address.
- `NS` (**Nameserver Record**): Refers to the domain's nameserver, which is responsible for resolving domain names into IP addresses for that domain.
- `MX` (**Mail Exchange Record**): Resolves a domain to a mail server, directing email traffic for a domain to the correct mail server.
- `CNAME` (**Canonical Name Record**): Used for domain aliases, which map one domain to another, allowing multiple domains to point to the same IP or resource.
- `TXT` (**Text Record**): Can be used to include arbitrary text in DNS, commonly for things like verifying domain ownership or providing SPF (Sender Policy Framework) information for email authentication.
- `HINFO` (**Host Information Record**): Specifies general information about the host such as the CPU and OS type, although it's rarely used for security reasons.
- `SOA` (**Start of Authority Record**): Indicates the primary authoritative nameserver for a domain and contains essential metadata such as the domain's serial number and refresh intervals for DNS zone transfers.
- `SRV` (**Service Record**): Specifies the location of services such as VoIP or directory services within a domain by defining the service's hostname and port.
- `PTR` (**Pointer Record**): Resolves an IP address to a hostname, typically used in reverse DNS lookups to map an IP back to a domain name.
<<<<<<< HEAD
##### DNS Interrogation

DNS interrogation involves enumerating DNS records for a specific domain by probing DNS servers. This process can reveal critical information like IP addresses, subdomains, and mail server addresses, aiding in further network exploration.
##### Host File

A **host file** is a  text file on a local computer that maps domain names to specific IP addresses. This file acts as a local DNS resolver, allowing the system to resolve domain names to IP addresses without querying an external DNS server. The host file can be  useful for overriding DNS settings or testing DNS configurations locally. On Linux systems, the host file is located at `/etc/hosts`. Entries in this file will be used by the computer when accessing websites or network resources.

**To modify the host file on Linux:**
- You need to use `sudo` to update this file since it affects the entire system. Entries in the host file are added in the format:
=======

##### DNS Interrogation

DNS interrogation involves enumerating DNS records for a specific domain by probing DNS servers. This process can reveal critical information like IP addresses, subdomains, and mail server addresses, aiding in further network exploration.

##### Host File

A **host file** is a simple text file on a local computer that maps domain names to specific IP addresses. This file acts as a local DNS resolver, allowing the system to resolve domain names to IP addresses without querying an external DNS server. The host file can be particularly useful for overriding DNS settings or testing DNS configurations locally.

On Linux systems, the host file is located at `/etc/hosts`. It works similarly to a DNS server but only at the local level, meaning that any entries in this file will be used by the computer when accessing websites or network resources, but they won't affect other devices or be visible on public DNS servers.

**To modify the host file on Linux:**

1. **File location:** The host file is located at `/etc/hosts`.
    
2. **Permissions:** You need to use `sudo` or be the root user to update this file since it affects the entire system.
    
3. **File format:** Entries in the host file are added in the format:
>>>>>>> a6b485cfd619214d11ae884dd77fe02dfc0fbe5f
    
```
<IP Address> <domain.name>
```

Example:

```
192.168.2.1 router.admin
```
<<<<<<< HEAD
=======

4. **Editing:** You can use any text editor to modify the file. For instance, with `vim`, you would:
    
    - Open the file with `sudo vim /etc/hosts`
    - Press ‘i’ to enter **insert mode** and add your new entry.
    - After editing, press **Esc**, type `:wq` to save and exit.

When you add an entry like `192.168.2.1 router.admin` to the host file, anytime the computer tries to resolve "router.admin," it will use the specified IP address (`192.168.2.1`), bypassing any DNS queries.

---
### DNS Zone Transfers

A DNS zone transfer allows DNS administrators to copy or transfer zone files, which contain DNS records, from one DNS server to another.  When attempting a zone transfer, you'll need to query an authoritative nameserver for the domain which holds the complete zone file. For a zone transfer to work, the DNS server must be configured to allow it, and typically, only authorized servers can request zone transfers for security reasons.

The purpose is typically to synchronize DNS data between primary and secondary DNS servers. If improperly configured, attackers can exploit zone transfers to download the entire zone file. This could expose sensitive internal network details, such as subdomains, internal IP addresses, and server mappings. Key records like `A` and `CNAME` could reveal server addresses and internal services, providing valuable information for further exploration or exploitation of the network.

#### Methods for Performing DNS Zone Transfers:

1. **Dig** (Domain Information Groper) is a versatile DNS querying utility available in Kali Linux that is commonly used for DNS enumeration for IP addresses, mail servers, and name servers but can also perform DNS zone transfers.

General Syntax:

```
dig axfr @ns1.domain.com domain.com
```

- **`axfr`**: Specifies a request for a DNS zone transfer, which attempts to retrieve all DNS records for the domain.
- ```@ns1.domain.com```: The `@` followed by `ns1.example.com` directs the query to a specific nameserver. This nameserver must be authoritative for the domain  to perform a zone transfer successfully.

2. Dnsenum: ```dnsenum``` is a DNS enumeration tool that gathers information like domain names, IPs, subdomains, and mail servers, and can perform tasks such as zone transfers and DNS brute-forcing, making it part of active reconnaissance.

```
dnsenum website.com
```

#### DNS Bruteforcing

DNS brute forcing is an enumeration technique used by attackers to discover subdomains and DNS records by systematically guessing or "brute forcing" possible names such as "mail.example.com" or "vpn.example.com," to find valid DNS records. This method does not rely on any misconfigurations like zone transfers but instead attempts to gather information by trial and error.

1. dnsenum: Mentioned Above
2. Fierce: A DNS reconnaissance scanner in Kali, aiming to discover non-contiguous IP space and map out an organization's network infrastructure. Fierce is primarily used to identify and map domain names, subdomains, and associated IP addresses within a target's network.

```
fierce --domain website.com
```
>>>>>>> a6b485cfd619214d11ae884dd77fe02dfc0fbe5f

4. You can use any text editor to modify the file. For instance, with `vim`, you would:
    - Open the file with `sudo vim /etc/hosts`
    - Press ‘i’ to enter **insert mode** and add your new entry.
    - After editing, press **Esc**, type `:wq` to save and exit.

When you add an entry like `192.168.2.1 router.admin` to the host file, anytime the computer tries to resolve "router.admin," it will use the specified IP address (`192.168.2.1`), bypassing any DNS queries.

---
### DNS-Zone-Transfers

A DNS zone transfer allows DNS administrators to copy or transfer zone files, which contain DNS records, from one DNS server to another. The purpose is typically to synchronize DNS data between primary and secondary DNS servers. Using a tool like `dig` to perform the transfers is mimicking the zone transfer process between DNS servers.  If improperly configured, attackers can exploit zone transfers to download the entire zone file. This could expose sensitive internal details, such as subdomains, IPs, and server mappings, as `A` and `CNAME` records may reveal server addresses and services, aiding further network exploitation.  

For a zone transfer to work...
- You'll need to query an authoritative nameserver for the domain which holds the complete zone file. 
- The DNS server must be configured to allow transfer, and typically, only authorized systems (like secondary DNS servers) can request zone transfers.
##### Methods for Performing DNS Zone Transfers:

1. **Dig** is a DNS querying utility available in Kali that is commonly used for DNS enumeration for IP addresses, mail servers, and name servers but can also perform DNS zone transfers.

	Dig Zone Transfer Syntax:

```
dig axfr @ns1.domain.com domain.com
```

- **`axfr`**: **Asynchronous Full Zone Transfer**, which is the DNS query type used to request the full zone data from a DNS server. 
- ```@ns1.domain.com```: The `@` followed by `ns1.example.com` directs the query to a specific nameserver authoritative for the domain  to perform a zone transfer successfully.

2. Dnsenum: ```dnsenum``` is a DNS enumeration tool that gathers information like domain names, IPs, subdomains, and mail servers, and can perform tasks such as zone transfers and DNS brute-forcing, making it part of active reconnaissance.

```
dnsenum website.com
```
#### DNS Bruteforcing

DNS brute forcing is an enumeration technique used by attackers to discover subdomains and DNS records by systematically guessing or "brute forcing" possible names such as "mail.example.com" or "vpn.example.com," to find valid DNS records. This method does not rely on any misconfigurations like zone transfers but instead attempts to gather information by trial and error.

1. **dnsenum**: *Mentioned Above*
2. **Fierce**: A DNS reconnaissance scanner in Kali, aiming to discover non-contiguous IP space and map out an organization's network infrastructure. Fierce is primarily used to identify and map domain names, subdomains, and associated IP addresses within a target's network.

```
fierce --domain website.com
```

---

