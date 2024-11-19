
1. [Introduction (What is Active Information Gathering)](c.%20Active%20Information%20Gathering.md#introduction)
2. [Intro to DNS (Records, Interrogation)](c.%20Active%20Information%20Gathering.md#dns)
3. [DNS Zone Transfers and DNS Zone Transfers ](c.%20Active%20Information%20Gathering.md#dns-zone-transfers)

---
## Introduction

Active information gathering is a phase in penetration testing where the tester directly interacts with the target system or network to collect data and identify vulnerabilities. This differs from passive reconnaissance, as it involves techniques like scanning, probing, and interacting with network services to gather information.

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
- `SOA` (**Start of Authority Record**): Indicates the primary authoritative nameserver for a domain and contains essential metadata such as the domain's serial number and refresh intervals for DNS zone transfers.
- `SRV` (**Service Record**): Specifies the location of services such as VoIP or directory services within a domain by defining the service's hostname and port.
- `PTR` (**Pointer Record**): Resolves an IP address to a hostname, typically used in reverse DNS lookups to map an IP back to a domain name.

##### Host File

A **host file** is a simple text file on a local computer that maps domain names to specific IP addresses. This file acts as a local DNS resolver, allowing the system to resolve domain names to IP addresses without querying an external DNS server. On Linux systems, the host file is located at `/etc/hosts`. It works similarly to a DNS server but only at the local level, meaning that any entries in this file will be used by the computer when accessing websites or network resources.

**To modify the host file on Linux:**
- You need to use `sudo` to update this file since it affects the entire system. Entries in the host file are added in the format:
    
```
<IP Address> <domain.name>
```

Example:

```
192.168.2.1 router.admin
```

4. You can use any text editor to modify the file. For instance, with `vim`, you would:
    - Open the file with `sudo vim /etc/hosts`
    - Press ‘i’ to enter **insert mode** and add your new entry.
    - After editing, press **Esc**, type `:wq` to save and exit.

When you add an entry like `192.168.2.1 router.admin` to the host file, anytime the computer tries to resolve "router.admin," it will use the specified IP address (`192.168.2.1`), bypassing any DNS queries.
##### DNS Interrogation

DNS interrogation involves enumerating DNS records for a specific domain by probing DNS servers. This process can reveal critical information like IP addresses, subdomains, and mail server addresses, aiding in further network exploration.

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

DNS brute forcing is an active enumeration technique aimed at uncovering subdomains and DNS records by systematically querying potential subdomain names like `mail.example.com` or `vpn.example.com`. When a valid subdomain is found, the DNS server responds with relevant DNS records such as A (IP addresses), MX (mail servers), CNAME (aliases), or TXT (metadata). These records provide crucial insights into the target’s infrastructure, potentially revealing hidden services or network configurations.

DNS brute forcing can be performed using tools like `dnsenum` or `Fierce`, which are designed to automate the discovery process efficiently.

### Fierce

Fierce is a DNS reconnaissance tool included in Kali Linux, used primarily for mapping an organization's network by identifying domain names, subdomains, and their corresponding IP addresses. By default, Fierce uses your system’s DNS servers to resolve queries. It first identifies the authoritative name servers for the target domain and then queries those servers to brute-force potential subdomains. For example, querying a subdomain like vpn.example.com might reveal an A record pointing to a VPN server's IP address, which could serve as a potential entry point.

To brute force subdomains with Fierce, you can specify a target domain and a wordlist. You can specify the wordlist with the Kali Linux provides several wordlists available like `/usr/share/wordlists/dirb/common.txt`, which contains common file/directory names that can be used for subdomain enumeration.

To minimize detection, you can set delays between queries using the `--delay` option, specifying the number of seconds between requests. 

General Syntax:
```
fierce --domain example.com --subdomain-file /path/to/wordlist.txt --delay <seconds>
```

Example:
```
fierce --domain example.com --subdomain-file /usr/share/wordlists/dirb/common.txt --delay 2
```