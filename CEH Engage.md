# **CEH Engage**  
  
## Part 1  
  
### Challenge 1:  
An attacker conducted footprinting on a web application and saved the resulting report Dumpster.xlsx in the documents folder of EH Workstation-1. Your task is to analyze this report and identify the hostname associated with the IP address 173.245.59.176. (Format: aaaaa.aa.aaaaaaaaaa.aaa)  
  
![Pasted Graphic 36.png](Attachments/Pasted%20Graphic%2036.png)  
  
[henry.ns.cloudflare.com](http://henry.ns.cloudflare.com)  
  
**Challenge 2**:  
Identify the number of live machines excluding the gateway in 192.168.10.0/24 subnet. (Format: N)  
  
![[attacker@parrot]-[~]](Attachments/Pasted%20Graphic%2038.png)  
  
192.168.10.1: 		53, 80  
192.168.10.101:  	21, 22, 80, 135, 139, 445, 3389 (RDP)  
192.168.10.111:  	21, 22, 80  
192.168.10.144:	21, 80. 135, 139, 445, 1433 (mssql)  
192.168.10.222: 	21, 80, 135, 445 (microsoft-ds), 3389 (RDP)  
  
=> 5  
  
**Challenge 3**:  
Identify the IP address of a Linux-based machine with port 22 open in the target network 192.168.10.0/24 (Format: NNN.NNN.NN.NNN).  
  
![$sudo nmap -p 22 -0 192.168.10.1, 101, 111, 144, 222 -vv =-open|](Attachments/Pasted%20Graphic%2037.png)  
  
192.168.10.101:  	OpenSSH for Windows 8.1 (protocol 2.0)  
192.168.10.111:  	OpenSSH 8.9p1 3Ubuntu0.10  
  
=> 192.168.10.111  
  
**Challenge 4**:  
Find the IP address of the Domain Controller machine in 192.168.0.0/24. (Format: NNN.NNN.N.NNN  
  
![- (attacker@parrot)-(~)](Attachments/Pasted%20Graphic%2039.png)  
  
Ports:   
  
53 —> DNS  
88 —> Kerberos  
137-139 —> Netbios  
389 —> LDAP  
445 —> SMB  
  
nmap -sV -p 53, 88, 389, 445 192.168.0.0/24  
  
192.168.0.1   
192.168.0.222  Domain: SKILL.CEH.com0, workgroup SKILL.ceh, Site: Default-First-Name  
  
  
**Challenge 5**:  
Perform a host discovery scanning and identify the NetBIOS_Domain_Name of the host at 192.168.0.222. (Format: AAAAA.AAA)  
  
  
![(1)-[attackereparrot) -()](Attachments/Pasted%20Graphic%2040.png)  
![Host script results:](Attachments/Pasted%20Graphic%2041.png)  
  
  
Siehe Challenge 4 => SKILL.ceh  
  
**Challenge 6**:  
Perform an intense scan on 192.168.0.222 and find out the DNS_Tree_Name of the machine in the network. (Format: AAAAA.AAA.aaa)  
  
  
![-(attackereparrot)-|-](Attachments/Pasted%20Graphic%2044.png)  
  
  
**Challenge 7**:  
While performing a security assessment against the CEHORG network, you came to know that one machine in the network is running OpenSSH and is vulnerable. Identify the version of the OpenSSH running on the machine. Note: Target network 192.168.10.0/24. (Format: N.NaN)  
  
Siehe Challenge 3  
  
![•[attacker@parrot]-(~)|](Attachments/Pasted%20Graphic%2045.png)  
  
192.168.10.111:  	OpenSSH 8.9p1 3Ubuntu0.10  
  
**Challenge 8**:  
During a security assessment, it was found that a server was hosting a website that was susceptible to blind SQL injection attacks. Further investigation revealed that the underlying database management system of the site was MySQL. Determine the machine OS that hosted the database. Note: Target network 172.30.10.0/24 (Format: Aaaaaa)  
  
![Kaw packets senil.](Attachments/Pasted%20Graphic.png)  
  
Service mysql läuft auf 172.30.10.99.  
Keine direkte Aussage zum OS möglich.   
Nmap identifiziert nur Linux  
  
![-[attacker@parrot]-[~)](Attachments/Pasted%20Graphic%201.png)  
![Discovered open port 80/tcp on 172.30.10.99](Attachments/Pasted%20Graphic%203.png)  
  
![STATE SERVICE REASON](Attachments/Pasted%20Graphic%202.png)  
  
Ermittlung OS nur über weiteren Scan möglich.  
  
**Challenge 9**:  
Perform an intense scan on target subnet 192.168.10.0/24 and determine the IP address of the machine hosting the MSSQL database service. (Format: NNN.NNN.NN.NNN)  
  
Siehe Challenge 1  
  
192.168.10.144:	21, 80. 135, 139, 445, 1433 (mssql)  
  
![- Snap -p 1433 --open 192.168.10.0/24 -vv](Attachments/Pasted%20Graphic%2046.png)  
  
![Host is up, received syn-ack (0.00089s latency).](Attachments/Pasted%20Graphic%2047.png)  
  
**Challenge 10**:  
Perform a DNS enumeration on www.certifiedhacker.com and find out the name servers used by the domain. (Format: aaN.aaaaaaaa.aaa, aaN.aaaaaaaa.aaa)  
![- (attacker@parrot) - (~)](Attachments/Pasted%20Graphic%2048.png)  
  
![atracker partor -|~](Attachments/Pasted%20Graphic%204.png)  
  
**Challenge 11**:  
Find the IP address of the machine running SMTP service on the 172.30.10.0/24 network. (Format: NNN.NN.NN.NNN)  
  
![• Srmap -p 25 =-open 172.38.10.0/24 -w](Attachments/Pasted%20Graphic%2049.png)  
  
![TRACEROUTE (using port 25/tcp)|](Attachments/Pasted%20Graphic%205.png)  
  
**Challenge 12**:  
Perform an SMB Enumeration on 172.30.10.200 and check whether the Message signing feature is required. Give your response as Yes/No.  
  
![• Snmap -p 445 •-script smb* 172.30.10.200 -vv -TS](Attachments/Pasted%20Graphic%207.png)  
  
![receive bytes: ERROR](Attachments/Pasted%20Graphic%206.png)  
  
![- Snap -p 445 -- script smb* 172.30.10.200 --open --w | grep signing](Attachments/Pasted%20Graphic%2050.png)  
  
  
**Challenge 13**:  
Conduct a Common Weakness Enumeration on the Weakness ID 276 and identify the name associated with the ID. (Format: Aaaaaaaaa Aaaaaaa Aaaaaaaaaaa)  
  
CWE 276  
  
[https://cwe.mitre.org/data/definitions/276.html](https://cwe.mitre.org/data/definitions/276.html)  
  
![Q](Attachments/Pasted%20Graphic%2051.png)  
  
**Incorrect Default Permissions**  
  
**Challenge 14**:  
Perform vulnerability scanning for the Linux host in the 192.168.10.0/24 network using OpenVAS and find the QoD percentage of vulnerabilitiy with severity level as medium. (Format: NN)  
  
**docker run -d -p 443:443 --name openvas mikesplain/openvas**  
  
![New Task](Attachments/Pasted%20Graphic%208.png)  
  
**Challenge 15**:  
Perform a vulnerability scan on the host at 192.168.10.144 using OpenVAS and identify any FTP-related vulnerability. (Format: AAA Aaaaaaaaa Aaaaaaaaa Aaaaa )  
  
  
## Part 2   
  
**Challenge 1**:  
You are assigned to perform brute-force attack on a linux machine from 192.168.10.0/24 subnet and crack the FTP credentials of user nick. An exploitation information file is saved in the home directory of the FTP server. Determine the Vendor homepage of the FTP vulnerability specified in the file. (Format: aaaaa://aaa.aaaaaaaa.aaa/)  
  
  
Siehe Part 1 - Challenge 1  
  
  
192.168.10.101:  	21, 22, 80, 135, 139, 445, 3389 (RDP)  
192.168.10.111:  	21, 22, 80  
192.168.10.144:	21, 80. 135, 139, 445, 1433 (mssql)  
192.168.10.222: 	21, 80, 135, 445 (microsoft-ds), 3389 (RDP)  
  
![(x)-[attacker@parrot) -(~/Desktop]](Attachments/Pasted%20Graphic%209.png)  
  
![w-TW-T--](Attachments/Pasted%20Graphic%2010.png)  
  
![# Date: 2024-84-30](Attachments/Pasted%20Graphic%2011.png)  
  
**Challenge 2**:  
An intruder performed network sniffing on a machine from 192.168.10.0/24 subnet and obtained login credentials of the user for moviescope.com website using remote packet capture in wireshark. You are assigned to analyse the Mscredremote.pcapng file located in Downloads folder of EH Workstation-1 and determine the credentials obtained. (Format: aaaa/aaaaa)  
  
![Pasted Graphic 53.png](Attachments/Pasted%20Graphic%2053.png)  
![Pasted Graphic 52.png](Attachments/Pasted%20Graphic%2052.png)  
![V HTN. Form URL Encoded: a0lication/x-wxx-form-urlencoded](Attachments/Pasted%20Graphic%2054.png)  
  
**Challenge 3**:  
You are assigned to analyse a packet capture file ServerDoS.pcapng located in Downloads folder of EH Workstation-2 machine. Determine the UDP based application layer protocol which attacker employed to flood the machine in targeted network.  
Note: Check for target Destination port. (Format: Aaaaa Aaaaaaa Aaaaaaaa)  
  
![192-168.10.131,](Attachments/Pasted%20Graphic%2055.png)  
  
Quake Network Protocol  
  
**Challenge 4**:  
A severe DDoS attack is occurred in an organization, degrading the performance of a ubuntu server machine in the SKILL.CEH network. You are assigned to analyse the DD_attack.pcapng file stored in Documents folder of EH workstation -2 and determine the IP address of the attacker trying to attack the target server through UDP. (Format: NNN.NNN.NN.NNN)  
  
![9 9 1](Attachments/Pasted%20Graphic%2056.png)  
  
192.168.10.144  
  
**Challenge 5**:  
You are assigned to analyse PyD_attack.pcapng file stored in Downloads folder of EH Workstation -2 machine. Determine the attacker IP machine which is targeting the RPC service of the target machine. (Format: NNN.NN.NN.NN)  
  
tcp.port == 135 || udp.port == 111  
  
![tep-port = - 135](Attachments/Pasted%20Graphic%2057.png)  
  
172.30.10.99  
  
  
  
**Challenge 7**:  
You are assigned to analyse the domain controller from the target subnet and perform AS-REP roasting attack on the user accounts and determine the password of the vulnerable user whose credentials are obtained. Note: use users.txt and rockyou.txt files stored in attacker home directory while cracking the credentials. (Format: aNaaN*NNN)  
  
   
![-(x)-[attacker@parrot)-[~/Desktop]](Attachments/Pasted%20Graphic%2013.png)  
![Scat asrep_hashes. txt](Attachments/Pasted%20Graphic%2012.png)  
  
![0.0.6, SEE, IS PC 080 Platon Tee pot propel SPR LA](Attachments/Pasted%20Graphic%2014.png)  
  
![The wordlist or mask that you are using is too small.](Attachments/Pasted%20Graphic%2015.png)  
  
**Challenge 8**:  
A client machine under the target domain controller has a misconfigured SQL server vulnerability. Your task is to exploit this vulnerability, retrieve the MSS.txt file located in the Public Downloads folder on the client machine and determine its size in bytes as answer. Note: use users.txt and rockyou.txt files stored in attacker home directory while cracking the credentials. (Format: N)  
  
IP 192.168.0.144  
  
![- Shydra -L users.txt -P rockyou. Ext nssql: //192.168.10.144](Attachments/Pasted%20Graphic%2018.png)  
  
![Simpacket-nssqlclient Server_nssrv:Spidy@192.168.10.144](Attachments/Pasted%20Graphic%2020.png)  
  
![- Simpacket-assqlclient Server_mssrv:Spidy@192.168.10.144](Attachments/Pasted%20Graphic%2058.png)  
  
![(* INFO(SQL SIVISQLEXPRESS): Line 196: Configuration option "xp cdshell' chang](Attachments/Pasted%20Graphic%2059.png)  
  
![SQL> xp_cmdshell dir c:\sers\Public\Downloads\](Attachments/Pasted%20Graphic%2060.png)  
	  
![SQL> EXEC xp_cndshell type c: \Users\Public|Downloads\MSS.txt':](Attachments/Pasted%20Graphic%2021.png)  
  
  
**Challenge 9**:  
You are assigned to crack RDP credentials of user Maurice from the target subnet 192.168.10.0/24 and determine the password as answer. Note: use Note: use users.txt and rockyou.txt files stored in attacker home directory while cracking the credentials. (Format: Aaaaaaa@NNNN)  
  
192.168.10.222  
  
![(attacker@parrot) -[~)](Attachments/Pasted%20Graphic%2022.png)  
  
![- Shydra - 1 Maurice -P rockyou. Ext rdp: //192.168.10.222](Attachments/Pasted%20Graphic%2023.png)  
  
**Challenge 10**:  
You are assigned to perform malware scanning on a malware file Tools.rar stored in Downloads folder of EH workstation-2 machine and determine the last four digits of the file’s SHA-256 hash value. (Format: aNNN)  
  
![- [attacker@parrot)-[~/Downloads]](Attachments/Pasted%20Graphic%2024.png)  
  
**Challenge 11**:  
You are assigned to monitor a suspicious process running in a machine whose log file Logfile.PML is saved in Pictures folder of the EH Workstation -2. Analyse the logfile and determine the Parent PID of the malicious file H3ll0.exe process from the log file. (Format: NNNN)  
  
![8688 fSetEndO/Flein... C. sers Admin Acol sta\Rosnina Mi. SUCCESS](Attachments/Pasted%20Graphic%2061.png)  
![Pasted Graphic 62.png](Attachments/Pasted%20Graphic%2062.png)  
![Vitunised](Attachments/Pasted%20Graphic%2063.png)  
  
**Challenge 12**:  
You are tasked with analyzing the ELF executable file named Tornado.elf, located in the Downloads folder of EH Workstation-2. Determine the entropy value of the file up to two decimal places. (Format: N*NN)  
  
![•[attacker@parrot)-[~/Downloads]](Attachments/Pasted%20Graphic%2064.png)  
  
![¡attackereparrot -~/Downloads](Attachments/Pasted%20Graphic%2065.png)  
  
![@ upgraded, e newly installed, 0 to remove and 480 not upgraded.](Attachments/Pasted%20Graphic%2067.png)  
  
**Challenge 13**:  
You are assigned to scan the target subnets to identify the remote packet capture feature that is enabled to analyse the traffic on the target machine remotetly. Scan the target subnets and determine the IP address using rpcap service. (Format: NNN.NNN.NN.NNN)  
  
![- Snap -p 2002 192.168.10.0/24 --open](Attachments/Pasted%20Graphic%2025.png)  
  
**Challenge 14**:  
An insider attack occurred in an organization and the confidential data regarding an upcoming event is sniffed and encrypted in a image file stealth.jpeg stored in Desktop of EH Workstation -2 machine. You are assigned to extract the hidden data inside the cover file using steghide tool and determine the tender quotation value. (Use azerty@123 for passphrase) (Format: NNNNNNN)  
  
![OpenVAS.desktop](Attachments/Pasted%20Graphic%2026.png)  
**Challenge 15**:  
Perform vulnerability search using searchsploit tool and determine the path of AirDrop 2.0 vulnerability. (Format: aaaaaaa/aaa/NNNNN.a)  
  
![searchsploit airdrop](Attachments/Pasted%20Graphic%2027.png)  
  
## **Part III**  
  
**Challenge 1**:  
An attacker tried to perform session hijacking on a machine from 172.30.10.0/24 subnet. An incident handler found a packet capture file $_Jack.pcapng obtained from the victim machine which is stored in Documents folder of EH Workstation -1. You are assigned to analyse the packet capture file and determine the IP of the victim machine targeted by the attacker. (Format: NNN.NN.NN.NNN)  
  
![Pasted Graphic 68.png](Attachments/Pasted%20Graphic%2068.png)  
  
**Challenge 2**:  
An attacker tried to intercept a login session by intercepting the http traffic from the victim machine. The security analyst captured the traffic and stored it in Downloads folder of EH Workstation -1 as Intercep_$niffer.pcapng. Analyse the pcap file and determine the credentials captured by the attacker. (Format: aaa/aaaa)  
  
![Pasted Graphic 69.png](Attachments/Pasted%20Graphic%2069.png)  
  
![Pasted Graphic 70.png](Attachments/Pasted%20Graphic%2070.png)  
  
**Challenge 3**:  
A honeypot has been set up on a machine within the 192.168.10.0/24 subnet to monitor and detect malicious network activity. Your task is to analyze the honeypot log file, cowrie.log, located in the Downloads folder of EH Workstation -2, and determine the attacker IP trying to access the target machine. (Format: NNN*NN*NN*NN)  
  
![222024-09-11701:29:11.9343162 (HoneyPotSSHtramsport.2.172.30.10.991 SSH client hassh fincerprint:](Attachments/Pasted%20Graphic%2071.png)  
![PuTTY_Release_0.76](Attachments/Pasted%20Graphic%2073.png)  
  
**Challenge 4**:  
Conduct a footprinting analysis on the target website www.certifiedhacker.com to identify the web server technology used by the site.(Format: Aaaaaa)  
  
![[attacker@parrot]-[~/Downloads]](Attachments/Pasted%20Graphic%2074.png)  
  
**Challenge 5**:  
You’re a cybersecurity investigator assigned to a high-priority case. Martin is suspected of engaging in illegal crypto activities, and it’s believed that he has stored his crypto account password in a file named $ollers.txt. Your mission is to crack the SSH credentials for Martin’s machine within the 192.168.10.0/24 subnet and retrieve the password from the $ollers.txt file. (Hint: Search in the folders present on the Desktop to find the target file) (Format: aNaa**NNNNNAA*)  
  
  
192.168.10.101:  	21, 22, 80, 135, 139, 445, 3389 (RDP)  
192.168.10.111:  	21, 22, 80  
  
![[attacker@parrot)(~)](Attachments/Pasted%20Graphic%2028.png)  
![• Sesh martin 192.168.18.181](Attachments/Pasted%20Graphic%2029.png)  
![Directory of C: \Users \Martin\Desktop](Attachments/Pasted%20Graphic%2030.png)  
  
**Challenge 6**:  
Attackers have identified a vulnerable website and stored the details of this website on one of the machines within the 192.168.10.0/24 subnet. As a cybersecurity investigator you have been tasked to crack the FTP credentials of user nick and determine the ID of the domain. The information you need has been gathered and stored in the w_domain.txt file. (Format: NNNNNNNNNN)  
  
![-(attacker@parrot) -(~1](Attachments/Pasted%20Graphic%2075.png)  
  
![[attacker@parrot|-|~)](Attachments/Pasted%20Graphic%2076.png)  
  
![• Sftp 192.168.10.111](Attachments/Pasted%20Graphic%2077.png)  
  
![226 Directory send OK.](Attachments/Pasted%20Graphic%2078.png)  
  
**Challenge 7**:  
You have identified a vulnerable web application on a Linux server at port 8080. Exploit the web application vulnerability, gain access to the server and enter the content of RootFlag.txt as the answer. (Format: Aa*aaNNNN)  
  
  
![-[attacker@parrot) -(~)](Attachments/Pasted%20Graphic.png)  
![Nato scan report for 172.30.10.90](Attachments/Pasted%20Graphic%202.png)  
![jdk-8u202-linux-x64.tar.gz/](Attachments/Pasted%20Graphic%203.png)  
  
![› tar -xf jdk-8u20-linux-x64.tar.gz](Attachments/Pasted%20Graphic%204.png)  
  
![[!] CVE: CVE-2021-44228](Attachments/Pasted%20Graphic%205.png)  
  
![[attacker@parrot]-[~/1og4j-shell-poc]](Attachments/Pasted%20Graphic%206.png)  
![Hello Again!](Attachments/Pasted%20Graphic%207.png)  
  
Ch@mp2022  
  
**Challenge 8**:  
You are a penetration tester assigned to a new task. A list of websites is stored in the webpent.txt file on the target machine with the IP address 192.168.10.101. Your objective is to find the Meta-Author of the website that is highlighted in the list. (Hint: Use SMB service) (Format: AA-Aaaaaaa)  
  
![- Shydra -L users.ext -Prockyou,txt seb://192.168.10.101](Attachments/Pasted%20Graphic%208.png)  
  
![-[attacker@parrot)-(~]](Attachments/Pasted%20Graphic%209.png)  
  
**Challenge 9**:  
You have recently joined GoodShopping Inc. as a web application security administrator. Eager to understand the security landscape of the company’s website, www.goodshopping.com, you decide to investigate the security updates that have been made over time. Your specific task is to identify the attack category of the oldest Common Vulnerabilities and Exposures (CVEs) affected the website. (Format: aaaaa*aaaa aaaaaaaaaa (AAA) )  
  
cross-site scripting (XSS)  
  
![seta hito cautya Content yod](Attachments/Pasted%20Graphic%2020.png)  
  
![reent Security Polcy (CSP) Header Not Set (51|](Attachments/Pasted%20Graphic%2021.png)  
![Vulnerable IS Ubrary](Attachments/Pasted%20Graphic%2079.png)  
**Challenge 10**:  
You are a web penetration tester hired to assess the security of the website www.goodshopping.com. Your primary task is to identify the type of security policies is missing to detect and mitigate Cross-Site Scripting (XSS) and SQL Injection attacks. (Format: Aaaaaaa Aaaaaaaa Aaaaaa)  
  
![Pecto te pren pe hali el attec apelorins chet you hare been](Attachments/Pasted%20Graphic%2080.png)  
  
Content Security Policy  
  
  
**Challenge 14**:  
Perform a SQL Injection attack on www.moviescope.com and find out the number of users available in the database. (Format: N)  
  
![+ > ×](Attachments/Pasted%20Graphic%2012.png)  
![Project](Attachments/Pasted%20Graphic%2013.png)  
  
![r(attacker@parrot)-(~1](Attachments/Pasted%20Graphic%2014.png)  
  
![(attacker@parrot) -(](Attachments/Pasted%20Graphic%2015.png)  
![101:31:541 TINFO) adjusting time delay to i second due to good response times](Attachments/Pasted%20Graphic%2016.png)  
![[*) ending e 01:37:59 /2825-89-88/](Attachments/Pasted%20Graphic%2017.png)  
![Pasted Graphic 18.png](Attachments/Pasted%20Graphic%2018.png)  
  
![[01:49:22]](Attachments/Pasted%20Graphic%2019.png)  
  
  
> 1. sqlmap -r request.txt --dbs --batch --threads=5 --level=3 --risk=2  
> 
> 2. sqlmap -r request.txt -D moviescope --tables --batch --threads=5 --level=3 --risk=2  
> 
> 3. sqlmap -r request.txt -D moviescope -T User_Login --columns --batch  
> 
> 4. sqlmap -r request.txt -D moviescope -T User_Login -C username,password --dump --batch  
  
  
**Challenge 15**:  
Perform a SQL Injection vulnerability scan on the target website www.moviescope.com and determine the WASC ID for SQL Injection (Format: NN)  
  
19  
  
![ed Session - OWASP ZAP 2.0.6](Attachments/Pasted%20Graphic%2011.png)  
🧩** 1. WASC – *Web Application Security Consortium***  
**→ Kategorie: Klassifizierungssystem (Taxonomie)** **→ Fokus:** Web-Schwachstellen allgemein  
  
🧩** 2. CWE – *Common Weakness Enumeration***  
**→ Kategorie: Schwachstellenursache (Code- oder Designfehler)** **→ Fokus:** Programmierfehler, die zu Sicherheitslücken führen können  
  
🧩** 3. CVE – *Common Vulnerabilities and Exposures***  
**→ Kategorie: Konkrete Sicherheitslücke (individuell identifiziert)** **→ Fokus:** Einzelne Schwachstellen in spezifischen Produkten oder Versionen  
  
**Challenge 11**:  
As part of an internal vulnerability assessment, a potentially misconfigured website was identified within the organization's network. A security scan was conducted using smart scanner tool, and the resulting report w_report.pdf was stored on a Windows Server 2019 machine within the 192.168.10.0/24 subnet. Your objective is to access the target server, retrieve the scan report, and analyze its contents to determine the total number of directory listing entries identified on the scanned website. (Format: NN)  
  
![(attackereparrot -(~)](Attachments/Pasted%20Graphic.png)  
![Nimap scan report for 192.168.10.101](Attachments/Pasted%20Graphic%201.png)  
![Nmap scan report for 192.168.10.144](Attachments/Pasted%20Graphic%202.png)  
![map scan report for 192.168.10.222](Attachments/Pasted%20Graphic%203.png)  
![-(attacker@parrot) -(~)](Attachments/Pasted%20Graphic%204.png)  
![- (attacker@parrot)-(~)](Attachments/Pasted%20Graphic%205.png)  
  
![ftp> ge w_report.pdf](Attachments/Pasted%20Graphic%206.png)  
  
  
  
  
**Challenge 12**:  
Perform a bruteforce attack on www.cehorg.com and find the password of user adam. (Format: aaaaaaNNNN)  
![5-09-09 19:13:412)](Attachments/Pasted%20Graphic%2024.png)  
![3790/tcp](Attachments/Pasted%20Graphic%2025.png)  
![(INFO] Reduced number of tasks to 1 (smb does not like parallel connections)](Attachments/Pasted%20Graphic%2028.png)  
![Shydra +L users.txt -P passwords.txt tdp://cehorg.com](Attachments/Pasted%20Graphic%2026.png)  
![Forbidden](Attachments/Pasted%20Graphic%2022.png)  
  
![Wampserver](Attachments/Pasted%20Graphic%2023.png)  
Wichtigste Infos im Bild:   
* Version: ha(64‑bit), Sprache/Theme wählbar.  
* Server Configuration:  
    * Apache 2.4.59, läuft auf Port 8080 (statt 80).  
    * PHP 8.2.18 (weitere PHP-Versionen via FCGI: 7.4.33, 8.0.30, 8.1.28, 8.2.18, 8.3.6).  
    * MySQL 8.3.0 auf Port 3306 (Standard‑DBMS).  
    * MariaDB 11.3.2 auf Port 3307.  
*    
* Tools: Links zu phpinfo(), xdebug_info(), PhpSysInfo und “Add a Virtual Host”.  
* Your Projects: CEH und DVWA (liegen im Ordner c:/wamp64/www).  
* Your Aliases: adminer 4.8.1 und PhpMyAdmin 5.2.1.  
* Your VirtualHost: localhost.  
  
![• Log In « VLydpress -W x](Attachments/Pasted%20Graphic%2029.png)  
![[attacker@parrot) - [~]](Attachments/Pasted%20Graphic%2030.png)  
![[• Pertorning password attack on no Login against 1 user/?](Attachments/Pasted%20Graphic%2031.png)  
  
**Challenge 13**:  
As a cybersecurity analyst, your task is to identify potential vulnerabilities on the moviescope.com website. Your manager has requested a specific number of risk categories. The required HTML file is located on EH Workstation 1. (Format: N)  
  
![O "movie)](Attachments/Pasted%20Graphic%207.png)  
  
![Wapiti vulnerability report](Attachments/Pasted%20Graphic%208.png)  
##   
## **CEH Engage - Part IV**  
  
**Challenge 1**:  
An employee's mobile device within CEHORG has been compromised, leading to an encrypted message BCtetx.txt being placed on the Android operating system. The password needed to decrypt the file is saved on EH-workstation-1. As an ethical hacker, your task is to decrypt the file using the password and input the extracted information. (note: the password file pawned.txt is stored in documents folder). (Format: *aaaaAN*NaN )  
![Personal](Attachments/Pasted%20Graphic%2011.png)  
![Nmap scan report for 192.168.10.121](Attachments/Pasted%20Graphic%2010.png)  
![- (attacker@parrot) -(-](Attachments/Pasted%20Graphic%2012.png)  
  
![- [attacker@parrot)-(~)](Attachments/Pasted%20Graphic%2013.png)  
![-(attackereparrot)-(~]](Attachments/Pasted%20Graphic%2014.png)  
  
!["Cryptography Tools > BCTextEncoder](Attachments/Pasted%20Graphic%2015.png)  
  
  
  
  
  
  
![package:/system/app/WallpaperPicker/Wa](Attachments/Pasted%20Graphic%2016.png)  
  
**Challenge 3**:  
A ZIP archive encompassing redundant images of a physical signature has been compromised signature.zip and stored in Documents folder of EH Workstation-1 machine. Your role as an ethical hacker involves a forensic examination of the archive's contents to pinpoint the image file associated with an MD5 hash value ends with sequence "24CCB". Determine the original signature file name as answer. (Format: aN*aaa)  
  
**Windows (PowerShell) — empfohlen**  
Einzeldatei:  
  
> Get-FileHash -Path "C:\Pfad\zu\k1.jpg" -Algorithm MD5  
  
  
**Linux / macOS (Terminal)**  
Einzeldatei (Linux):  
  
> md5sum k1.jpg  
  
  
![•k2.png](Attachments/Pasted%20Graphic%2017.png)  
  
![C:Nusers Wdmin\Documents\sigeature krish)](Attachments/Pasted%20Graphic%2018.png)  
  
k4.png  
  
  
**Challenge 2**:  
A compromised Android device is suspected of containing malicious applications. As an ethical hacker, you are tasked with identifying and extracting all installed APK files. Within these APKs, you must locate and extract a specific CRC value ends with "614c" . This CRC value is believed to be a crucial component of a larger security breach investigation. Determine the complete CRC value as answer. (Format: NNaaNNNa)  
![- attacker parrot "~]](Attachments/Pasted%20Graphic%2022.png)  
  
![•Sadb shell pa path con.cxinventor.file.explorer](Attachments/Pasted%20Graphic%2023.png)  
  
**Challenge 5**:  
An employee's mobile device has reportedly been compromised and is suspected of being used to launch a Denial of Service (DoS) attack against one of the company's internal servers. Your assignment is to conduct a thorough analysis of the network capture file "And_Dos.pcapng" located in the Documents directory of EH workstation-2 machine and identify the severity level/potential impact of the attack performed. (perform deep down Expert Info analysis). (Format: Aaaaaaa)  
![EH Workstation - 2 v](Attachments/Pasted%20Graphic%2025.png)  
  
![This frame is a loupected) out-of-order seement](Attachments/Pasted%20Graphic%2024.png)  
**Challenge 6**:  
CEHORG manages multiple IoT devices and sensors to oversee its supply chain fleet. You are tasked with examining the file "MQTT.pcapng," located in the Home directory of the EH Workstation - 2 machine. Analyze the packet containing the "High_humidity" message and determine the alert percentage specified in the message. (Format: NN )  
  
![192. 30.10.20](Attachments/Pasted%20Graphic%2026.png)  
  
![Al Publiah. Raleste (i2](Attachments/Pasted%20Graphic%2027.png)  
  
![E Workstation - 2 v](Attachments/Pasted%20Graphic%2028.png)  
  
**Challenge 7**:  
An attacker had sent a file cryt-128-06encr.hex containing ransom file password, which is located in documents folder of EH-workstation-2. You are assigned a task to decrypt the file using cryp tool. Perform cryptanalysis, Identify the algorithm used for file encryption and hidden text. Note: check filename for key length and hex characters. (Format: Aaaaaaa/**aa**aA*a)  
  
![Symmetric (carsid](Attachments/Pasted%20Graphic%2029.png)  
  
**Challenge 8**:  
A VeraCrypt volume file "MyVeracrypt" is stored on the Document folder of the EH Workstation – 1 machine. You are an ethical hacker working with CEHORG; you have been tasked to decrypt the encrypted volume and determine the number of files stored in the volume folder. (Hint: Password: veratest). (Format: N )  
  
4  
  
File mit Veracrypt mounted —> Passwort lautet *veratest*  
  
**Challenge 9**:  
An ex-employee of CEHORG is suspected of performing an insider attack. You are assigned a task to retrieve the contacts dump from the employee's Android phone. Using PhoneSploit, find the country code of the contact named "Maddy." (Note: Use option 'N' in PhoneSploit for next page.). (Format: NN )  
  
  
![[Main Menu] Enter](Attachments/Pasted%20Graphic%2030.png)  
![• contacts_dump-2025-9-23-15-36-2.txt x](Attachments/Pasted%20Graphic%2031.png)  
  
**Challenge 11**:  
An ex-employee of CEHORG is suspected to be performing insider attack. You are assigned a task to attain KEYCODE-5 used in the employees' mobile phone. Note: use option N in PhoneSploit for next page. (Format: Aaaaa*Aaaaaa)  
![31. Unlock Device](Attachments/Pasted%20Graphic%2033.png)  
![1. Keyboard Text Input](Attachments/Pasted%20Graphic%2032.png)  
  
**Challenge 12**:  
An employee in CEHORG has secretly acquired Confidential access ID through an application from the company. He has saved this information on the Music folder of his Android mobile phone. You have been assigned a task as an ethical hacker to access the file and delete it covertly. Enter the account information present in the file. Note: Only provide the numeric values in the answer field. (Format: NNNNNNNN)  
  
  
![[attackereparrot](Attachments/Pasted%20Graphic%2034.png)  
  
![20x86_64:/ $ (attacker@parrot)-(~1](Attachments/Pasted%20Graphic%2035.png)  
  
80099889  
  
  
