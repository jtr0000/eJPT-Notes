
#### Table of Contents
1. [[Passive Information Gathering#Website Recon & Footprinting|Website Recon & Footprinting]]
	- [[Passive Information Gathering#^1ced6c| Lookup an IP Address for website]]
	- [[Passive Information Gathering#^09bb4d | Find pages and directories]]
	- [[Passive Information Gathering#^fde421 | Find website technologies]]
	- [[Passive Information Gathering#^b443d2 | Download copy of website]]
2. WhoIs Enumeration
Website Footprinting
DNS Reconnaissance
WAF with wafw00f
Hunting Subdomains with Sublist3r
Google Dorks
Email Harvesting with theHarvester
Leaked Passwords Databases

---
### Website Recon & Footprinting

- **Lookup an IP address for a website:** Can use the 'host' DNS lookup utility in Kali. If there's multiple IPs associated the site might be using a proxy like Cloudflare. ^1ced6c
```
host website.com
```

- **Find pages and directories**: There's some publicly accessible files that can include useful information. Both normally on the root of the website ^09bb4d
	1. **robots.txt**  (https://website/robots.txt)  - Tells search engine web crawlers what they're to crawl or not crawl like hidden directories. 
	2. **sitemap.xml** ([https://website.com/sitemap.xml](https://website.com/sitemap.xml)): Tells search engines pages that they want to index

- Another way to get some information like a name or socials is from navigating through the site itself.
- **Find website technologies** - Websites addons/extensions to get website technologies, frameworks, CMS and programming languages: ^fde421
	- **BuiltWith** ( [https://builtwith.com/](https://builtwith.com/)  | Website and Addon)
	- **Wappalyzer ( [https://addons.mozilla.org/en-US/firefox/addon/wappalyzer/](https://addons.mozilla.org/en-US/firefox/addon/wappalyzer/) | Extension) -** Can show frameworks, CMS and programming languages 
	- **whatweb** - Free built-in website scanner in Kali. 

```
whatweb https://www.website.com
```

- **Download a copy of a website** - Use HTTrack Website copier to download the website and linked resources  to view the source code and technologies involved.  Can download the HTTrack package in kali, by default it runs the webserver on port 8080.
    ^b443d2
```
sudo apt-get install webhttrack
```   
---
## WhoIs Enumeration


Get information on inviduals or name like  names/phone numbers/location etc of the domain also helpful to get name servers

WHOIS is a query and response protocol for query databases for assignee of internet resources like domain names, IP address blocks etc.

- **GOAL**: Get information like the contact name/number/location etc of the domain also helpful to get name servers. ** Great for phishing **
- 
    
- Domain lookup: WhoIs tools in kali Linux | eg ‘whois [company.com](http://company.com)’
    
    ** DNSSEC being enabled makes it so that the contact name and location is redacted **
    
    ![2024-03-27_22-00-55.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/2a2789ee-392a-4e7f-bf3d-d30b8b92bc3d/84b60aa7-3191-4298-97b4-e4d4b84a1235/2024-03-27_22-00-55.png)
    
    ![2024-03-27_22-09-38.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/2a2789ee-392a-4e7f-bf3d-d30b8b92bc3d/82e9d489-c5e4-4cf5-b5bc-0c8ce2c39203/2024-03-27_22-09-38.png)
    

Other tools:

- [virustotal.com](http://virustotal.com)
- [domaintools.com](http://domaintools.com)