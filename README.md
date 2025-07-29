# CEH-notes
# CEH-notes


| **#** | **Module Name**                           | **Focus Area**                                                                      |
| ----- | ----------------------------------------- | ----------------------------------------------------------------------------------- |
| 1     | **Introduction to Ethical Hacking**       | Basic concepts, legality, hacker types, phases of hacking                           |
| 2     | **Footprinting and Reconnaissance**       | Information gathering using tools like Whois, Google Dorks, Shodan                  |
| 3     | **Scanning Networks**                     | Network scanning, port scanning (e.g. `sS` stealth scans), Nmap                     |
| 4     | **Enumeration**                           | Gaining more detailed info (users, shares, services) using tools like NetBIOS, SNMP |
| 5     | **Vulnerability Analysis**                | Finding known vulnerabilities using scanners like Nessus, OpenVAS                   |
| 6     | **System Hacking**                        | Password cracking, privilege escalation, keylogging, cover tracks                   |
| 7     | **Malware Threats**                       | Types of malware (trojans, ransomware), malware analysis basics                     |
| 8     | **Sniffing**                              | Packet capturing, MITM attacks, tools like Wireshark                                |
| 9     | **Social Engineering**                    | Phishing, impersonation, baiting, psychological attack vectors                      |
| 10    | **Denial of Service (DoS/DDoS)**          | Tools and techniques for launching or mitigating DoS attacks                        |
| 11    | **Session Hijacking**                     | TCP session hijacking, cookie stealing, countermeasures                             |
| 12    | **Evading IDS, Firewalls, and Honeypots** | Techniques to bypass detection and traps                                            |
| 13    | **Hacking Web Servers**                   | Attacks on web server software and services                                         |
| 14    | **Hacking Web Applications**              | SQLi, XSS, CSRF, and OWASP Top 10 vulnerabilities                                   |
| 15    | **SQL Injection**                         | In-depth coverage of SQLi types and exploitation methods                            |
| 16    | **Hacking Wireless Networks**             | Wi-Fi attacks (WEP/WPA cracking, rogue APs)                                         |
| 17    | **Hacking Mobile Platforms**              | Android/iOS exploitation, mobile malware                                            |
| 18    | **IoT and OT Hacking**                    | Targeting Internet of Things and Operational Tech environments                      |
| 19    | **Cloud Computing**                       | Cloud-specific threats, attacks on AWS/Azure/GCP                                    |
| 20    | **Cryptography**                          | Encryption methods, hashing, cryptanalysis, and attacks on crypto                   |


Disclaimer:- you shoould have kali,window 10,msfconsole for practising all the atatcks of victims and other process realted to CEH







foot printing steps :-
DNS RECORDS
A RECORD 
AAA RECORD
MX RECORD
TXT RECORD
NS RECORD _ servers for dns 
SOA RECORD_ ADMIN 


=============practicals=========
 sudo theHarvester -d craw.in -b all (here b is for all the search engines )

 crosslinked/github 
 git clone(link)
 cd crosslinked
 ls
  pip install -r requirements.txt
  /crosslinked.py -f "{first}{last}@jio.com"jio

  for           DNS
  dig craw.in
  nslookup
  set type=mx
  craw.in

  whois craw.in
   

   GUI tools 
   NSlookup.io
   whois 
   DNS dumpster
   net crat.com (advanced)
   extension wappalyzer
 
 for mail
  hunter.io
  shodan.io
  cenuss.io
    
   ================= day 3 website things +++++++
   httrack (for downloading the whole website at a once for all the content present there)
    (i have been pwned) data leak website ..
   


   ================Network Footprinting================
    ping (to checkout the coonnection build up btw two connection like with website with system with anything to see is it live or not)
    traceroute (victim ip) (find out the ip deatails and hops to connect the another system)

    @subdoomain finder
     
     Subfinder --help
     Subfinder -d craw.in

     @website gathering
     dirb http: /.com(directory buster)
     alternative
     @gobuster

    =================== multipurpose tools =======================

    🛠️ Top Multi-Purpose Tools in CEH
Tool	    Description	Common Uses
Nmap	    Network scanner	Host discovery, port scanning, OS detection
Metasploit	Exploitation framework	Vulnerability scanning, exploit development, post-exploitation
Wireshark	Network protocol analyzer	Packet sniffing, traffic analysis
Burp Suite	Web application security testing	Interception, scanning, fuzzing, exploiting web vulnerabilities
Nessus	    Vulnerability scanner	Network vulnerability assessment
Netcat (nc)	Network utility	Banner grabbing, reverse shell, port scanning
Nikto	    Web server scanner	Detects outdated software, misconfigurations
Hydra	    Brute-force login cracker	Cracking login credentials for services like FTP, SSH, HTTP
John the Ripper	Password cracker	Cracking password hashes (offline)
Aircrack-ng	Wireless network audit suite	Cracking WEP/WPA keys, capturing handshakes
Ettercap	Man-in-the-middle (MITM) tool	Sniffing, spoofing, packet manipulation


dnsrcon --help
dmitry --help


================google dorking==============

🕵️‍♂️ What is Google Dorking?
Google Dorking involves using specific search queries (called dorks) to locate:

Exposed files (e.g., .pdf, .sql, .docx)

Open directories

Vulnerable web applications

Login portals

Error messages with tech info

Misconfigured servers

❗ While Google Dorking is legal when done for ethical purposes, it can uncover sensitive data unintentionally exposed online. Always use it with permission or in authorized environments (e.g., labs, CTFs, pentests).

🔍 Common Google Dorks
Dork	Function
intitle:"index of"	Lists open directories
filetype:sql	Finds exposed SQL database files
inurl:admin	Searches for admin login pages
site:example.com	Limits search to a specific site
intext:"username" filetype:log	Looks for usernames in .log files
"DB_PASSWORD"	Searches for exposed database passwords
`ext:log	ext:txt

🛡️ Example Queries
intitle:"index of" "backup" – Open directories with backups

filetype:env DB_PASSWORD – Environment files with DB credentials

inurl:"/phpmyadmin" – phpMyAdmin panels

site:gov filetype:xls intext:"password" – Government sites with spreadsheets containing "password"

(find out the ceh v13 book by google dorking)


=======================NETWORKING BASICS====================
TOTAL PORTS (65535)
WELL KNOW (1024-4915)
registered port(49152-65535)

some well known ports
| Port | Protocol | Service |
| ---- | -------- | ------- |
| 22   | TCP      | SSH     |
| 80   | TCP      | HTTP    |
| 443  | TCP      | HTTPS   |
| 53   | TCP/UDP  | DNS     |
| 25   | TCP      | SMTP    |
| 3306 | TCP      | MySQL   |


osi/tcp layer

| OSI Layer       | Purpose                 | Example          |
| --------------- | ----------------------- | ---------------- |
| 7. Application  | User-facing services    | HTTP, FTP        |
| 6. Presentation | Data format, encryption | SSL/TLS          |
| 5. Session      | Manage sessions         | NetBIOS, RPC     |
| 4. Transport    | Reliable delivery       | TCP, UDP         |
| 3. Network      | Routing & IP addressing | IP, ICMP         |
| 2. Data Link    | MAC addressing          | Ethernet         |
| 1. Physical     | Hardware transmission   | Cables, switches |


================scanning networks======================

--CLI---
nmap
rust map
msfconsole
enum 4 linux
netdiscover 

--gui base---
 zenmap
 Angry ip scanner

 nmap(the biggest and very helpful tool)
  some cmnds of nmap 

arp-scan -l > to scan network and active host
nmap ip
nmap -sS > stealth scan (to avoid firewall this scan is used )
nmap -sV  version scan
nmap -sC to find vulnerability in the ports 
-sX  three flags  push,urgent,finish (udp)
-sF  fo bypassing the firewall while scanning
 
 YOU CAN FIND ALL THE COMMANDS USING THE nmap -h with this cmnd u can seee the all possible action which can be done with nmap


 ===================BRUTE FORCE ===========

 | Tool                    | Target                            | Notes                                             |
| ----------------------- | --------------------------------- | ------------------------------------------------- |
| **Hydra**               | SSH, FTP, HTTP, RDP               | Fast and flexible, supports parallel attacks      |
| **Medusa**              | Similar to Hydra                  | Highly parallel, good for large-scale brute force |
| **John the Ripper**     | Hashes (e.g., from `/etc/shadow`) | Offline brute force on password hashes            |
| **Hashcat**             | GPU-based hash cracking           | Extremely fast, supports hybrid attacks           |
| **Burp Suite Intruder** | Web logins                        | Great for testing web forms and APIs              |
| **Ncrack**              | SSH, RDP, SMB                     | Designed for high-speed brute force               |

exmaple ===() hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.100

here you can give ur specific path which helps to reduce the tiimming or using such tools that create the paswords according to your given information


=================windows passowrd breaker or offline window hacking ======

learn about lm ,ntlm(new technology lab manager)
kerbos authentication 
kdc 
TGS
AS

where  the passwords are stored in the linux(shadow)

SAM -- SECURITY ACCOUNT MANAGER 

safe mode can open the sam file only to eneter the safe mode you have to go into BIOS SETTINF WITH THE HELP OF USB  
some USb pendrive that are helpful into crackiing the system without the lost of the data..

1. hirenboot
2. konboot
3.  Gandalf’s, Strelec’s, Medicat USB (most use cases option)

after you go into the safe mode you can copy the files like ( SECURITY, SAM FILE)
ALL PROGRAMS--SECURITY--PASSWORDS--NT WIERD


==============FOR LINUX BASED SYSTEM ========
 
 HERE YOU HAVE TO GO TO THE GRUB MODE TO GO IN THAT MODE FOLLOW THE STEPS

 1. RESTART 
 2. PRESS E FOR SOMETIME 
 3. SEE THE LINUX WORD IN THE GRUB MODE FIND  splash quiet , rw somthing like this words
  than just rewrite things like you have to do some changes like remove (splash quiet o  change with rw init=/bin/bash)and then press ctrl+x and it will go into the repairaing mode 
  here find out the home directory and find user 
  then write some commands like
  ls
  home
  ls
  kali
  passwd kali
  1234
  1234
  reboot -f 
  this process will change the password for the user you choose and help to get into the linux system without losing data



SNIFFING

BETTER CAP
ETTER CAP (for capturing packets)
MACOF  (to use flood attack)
mac -i s <attacker ip>


to change the mac address of the device
macchanger -r eth0

techtetnium MAC changer windows(HW)

ARPSPOOF(hw)

DHCP (dynamic host configuration protocol)
in the network ip is given by dhcp DORA process is used to send fake packets and server has limited requests so dhcp server become down so the all user connected to the internet they become disconnected DHCP starvation.

Tool (yersinia)
yersinia -I 


