
#### Table of Contents
1. [Website Recon and Footprinting](b.%20Passive%20Information%20Gathering.md#website-recon-and-footprinting)
2. [WhoIs Enumeration](b.%20Passive%20Information%20Gathering.md#whois-enumeration)
4. [DNS Reconnaissance](b.%20Passive%20Information%20Gathering.md#dns-recon)
5. [WAF with wafw00f](b.%20Passive%20Information%20Gathering.md#WAF)
6. Hunting Subdomains with Sublist3r
7. Google Dorks
8. Email Harvesting with theHarvester
9. Leaked Passwords Databases

---
## Website-Recon-and-Footprinting

- **Lookup an IP address for a website:** Can use the 'host' DNS lookup utility in Kali. If there's multiple IPs associated the site might be using a proxy like Cloudflare.
```
host website.com
```

- **Find pages and directories**: There's some publicly accessible files that can include useful information. Both normally on the root of the website
	1. **robots.txt**  (```https://website/robots.txt```) - Tells search engine web crawlers what they're to crawl or not crawl like hidden directories. 
	2. **sitemap.xml** (```https://website/sitemap.xml```) - Tells search engines pages that they want to index

- Another way to get some information like a name or socials is from navigating through the site itself.
- **Find website technologies** - Websites addons/extensions to get website technologies, frameworks, CMS and programming languages: ^fde421
	- **BuiltWith** ( [https://builtwith.com/](https://builtwith.com/)  | Website and Addon)
	- **Wappalyzer ( [https://addons.mozilla.org/en-US/firefox/addon/wappalyzer/](https://addons.mozilla.org/en-US/firefox/addon/wappalyzer/) | Extension) -** Can show frameworks, CMS and programming languages 
	- **Netcraft** ([https://sitereport.netcraft.com/](https://sitereport.netcraft.com/)): Netcraft has an all-in-one tool that can be used for getting domain information, getting website technologies and any background/network information which will be useful. Can also look at ssl/tls which can tell you when the certificate will resolve.	
	- **whatweb** | https://github.com/urbanadventurer/WhatWeb |- Free built-in website scanner in Kali  

```
whatweb https://www.website.com
```

- **Download a copy of a website** - Use HTTrack Website copier to download the website and linked resources  to view the source code and technologies involved.  Can download the HTTrack package in kali, by default it runs the webserver on port 8080.
```
sudo apt-get install webhttrack
```   

---
## WhoIs-Enumeration

WHOIS is a protocol for querying databases to find ownership details of domain names and IP addresses. You can use this information to get information on individuals like names/phone numbers/locations etc which is good for phishing or to get name servers.  Kali has a ```whois``` utility built-in to Kali:
```
whois company.com
```
Other tools to get WhoIs:
- [virustotal.com](http://virustotal.com)
- [domaintools.com](http://domaintools.com)
---
## DNS-Recon

**Goal:** Identify various DNS records especially A records, MX records for the server IP, TXT, and NS servers to get an idea of how a website is configured. 

1. **DNSRecon** is a python script that can be used enumerate DNS records for a given domain (MX, SOA, NS, A, AAAA, SPF, and TXT. It comes pre-packaged in Kali:

```
dnsrecon -d company.com
```
	
2. **DNSDumpster** ([https://dnsdumpster.com/](https://dnsdumpster.com/)): A free web tool that can find DNS records and possibly live hosts associated with a domain. This tools can perform active and passive reconnaissance through the website. A great thing about the website is that it does a great job mapping the servers/IP with their diagrams.
	- You can find hosts sharing the listed DNS server
	- In some cases, you might find a subdomain which can return a live page.
	- You can export to a diagram which can show IPs associated with whatever company its associated with.
	- You can perform Nmap scans on any observed servers (website) but it will be active

---
## WAF

You can use ```wafw00f``` which comes pre-packaged in Kali linux to check if a website or web application has a WAF solution deployed. This is still passive information gathering. *The only way to confirm if there is a WAF solution is to perform active information gathering like port scanning*. The ```-a``` parameter can look for all instances of WAF solutions

```
wafwoof website.com
```

- Github ([https://github.com/EnableSecurity/wafw00f](https://github.com/EnableSecurity/wafw00f)):
---
