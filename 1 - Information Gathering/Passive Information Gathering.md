
#### Table of Contents
1. [Website Recon and Footprinting](Passive%20Information%20Gathering.md#Website%20Recon%20and%20Footprinting%20)
2. [WhoIs Enumeration](Passive%20Information%20Gathering#WhoIs%20Enumeration)
3. Website Footprinting
4. DNS Reconnaissance
5. WAF with wafw00f
6. Hunting Subdomains with Sublist3r
7. Google Dorks
8. Email Harvesting with theHarvester
9. Leaked Passwords Databases

---
### Website Recon and Footprinting

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
	- **whatweb** - Free built-in website scanner in Kali. 

```
whatweb https://www.website.com
```

- **Download a copy of a website** - Use HTTrack Website copier to download the website and linked resources  to view the source code and technologies involved.  Can download the HTTrack package in kali, by default it runs the webserver on port 8080.
```
sudo apt-get install webhttrack
```   
---
## WhoIs Enumeration

WHOIS is a protocol for querying databases to find ownership details of domain names and IP addresses. You can use this information to get information on individuals like names/phone numbers/locations etc which is good for phishing or to get name servers.  Kali has a ```WhoIs``` utilty in Kali:
```
whois company.com
```
Other tools to get WhoIs:
- [virustotal.com](http://virustotal.com)
- [domaintools.com](http://domaintools.com)






This ```test``` is a test
```