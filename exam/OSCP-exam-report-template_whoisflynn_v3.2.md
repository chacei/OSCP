---
title: "Offensive Security Certified Professional Exam Report"
author: ["chase622@gmail.com", "OSID: OS-564154"]
date: "2023-05-04"
subject: "Markdown"
keywords: [Markdown, Example]
subtitle: "OSCP Exam Report"
lang: "en"
titlepage: true
titlepage-color: "1E90FF"
titlepage-text-color: "FFFAFA"
titlepage-rule-color: "FFFAFA"
titlepage-rule-height: 2
book: true
classoption: oneside
code-block-font-size: \scriptsize
---
# Offensive Security OSCP Exam Report

## Introduction

The Offensive Security Exam penetration test report contains all efforts that were conducted in order to pass the Offensive Security exam.
This report will be graded from a standpoint of correctness and fullness to all aspects of the exam.
The purpose of this report is to ensure that the student has a full understanding of penetration testing methodologies as well as the technical knowledge to pass the qualifications for the Offensive Security Certified Professional.

## Objective

The objective of this assessment is to perform an internal penetration test against the Offensive Security Exam network.
The student is tasked with following methodical approach in obtaining access to the objective goals.
This test should simulate an actual penetration test and how you would start from beginning to end, including the overall report.
An example page has already been created for you at the latter portions of this document that should give you ample information on what is expected to pass this course.
Use the sample report as a guideline to get you through the reporting.

## Requirements

The student will be required to fill out this penetration testing report fully and to include the following sections:

- Overall High-Level Summary and Recommendations (non-technical)
- Methodology walkthrough and detailed outline of steps taken
- Each finding with included screenshots, walkthrough, sample code, and proof.txt if applicable
- Any additional items that were not included

# High-Level Summary

I was tasked with performing an internal penetration test towards Offensive Security Exam.
An internal penetration test is a dedicated attack against internally connected systems.
The focus of this test is to perform attacks, similar to those of a hacker and attempt to infiltrate Offensive Security's internal exam systems - the OSCP.exam domain.
My overall objective was to evaluate the network, identify systems, and exploit flaws while reporting the findings back to Offensive Security.

When performing the internal penetration test, there were several alarming vulnerabilities that were identified on Offensive Security's network.
When performing the attacks, I was able to gain access to all machines, primarily due to outdated patches and poor security configurations.
During the testing, I had administrative level access to every system.
All systems were successfully exploited and access granted.
These systems as well as a brief description on how access was obtained are listed below:

- 192.168.134.100 (DC01) - WinRM with hard-coded Domain Admin credentials in MS01 web application
- 192.168.134.101 (MS01) - Remote Desktop with credentials harvested from MS02
- 192.168.134.102 (MS02) - SSH using credentials discovered during DC01 LDAP enumeration
- 192.168.134.110 		 - Web application revealed setup scripts with hard-coded MySQL credentials
- 192.168.134.114 		 - FTP server hosted annual security report noting weak passwords
- 192.168.134.126 		 - Web application revealed login and password change logs

## Recommendations

I recommend patching the vulnerabilities identified during the testing to ensure that an attacker cannot exploit these systems in the future.
One thing to remember is that these systems require frequent patching and once patched, should remain on a regular patch program to protect additional vulnerabilities that are discovered at a later date.

# Methodologies

I utilized a widely adopted approach to performing penetration testing that is effective in testing how well the Offensive Security Exam environments is secured.
Below is a breakout of how I was able to identify and exploit the variety of systems and includes all individual vulnerabilities found.

## Information Gathering

The information gathering portion of a penetration test focuses on identifying the scope of the penetration test.
During this penetration test, I was tasked with exploiting the exam network.
The specific IP addresses were:

**Exam Network**

- 192.168.134.100
- 192.168.134.101
- 192.168.134.102
- 192.168.134.110
- 192.168.134.114
- 192.168.134.126

## Penetration

The penetration testing portions of the assessment focus heavily on gaining access to a variety of systems.
During this penetration test, I was able to successfully gain access to **X** out of the **X** systems.

### System IP: 192.168.134.100 (Domain Controller)

#### Service Enumeration

The service enumeration portion of a penetration test focuses on gathering information about what services are alive on a system or systems.
This is valuable for an attacker as it provides detailed information on potential attack vectors into a system.
Understanding what applications are running on the system gives an attacker needed information before performing the actual penetration test.
In some cases, some ports may not be listed.

Server IP Address | Ports Open
------------------|----------------------------------------
192.168.x.x       | **TCP**: 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49667,49673,49674,49676,49691,49770

**Nmap Scan Results:**

Full port scan
```
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49667/tcp open  unknown
49673/tcp open  unknown
49674/tcp open  unknown
49676/tcp open  unknown
49691/tcp open  unknown
49770/tcp open  unknown
```
Targeted port scan
```
53/tcp   open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-05-03 19:56:45Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: oscp.exam0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: oscp.exam0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp open  mc-nmf        .NET Message Framing
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=5/3%Time=6452BC81%P=x86_64-pc-linux-gnu%r(DNSVe
SF:rsionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\x
SF:04bind\0\0\x10\0\x03");
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-05-03T19:59:01
|_  start_date: N/A
```

**Vulnerability Explanation:**
LDAP is not properly configured on the DC, which allows for enumeration of users, groups, and

**Vulnerability Fix:**

**Severity:**

**Proof of Concept Code Here:**

**Local.txt Proof Screenshot**

**Local.txt Contents**

#### Privilege Escalation

*Additional Priv Esc info*

**Vulnerability Exploited:**

**Vulnerability Explanation:**

**Vulnerability Fix:**

**Severity:**

**Exploit Code:**

**Proof Screenshot Here:**

**Proof.txt Contents:**

### System IP: 192.168.x.x

#### Service Enumeration

Server IP Address | Ports Open
------------------|----------------------------------------
192.168.x.x       | **TCP**: 1433,3389\
**UDP**: 1434,161

**Nmap Scan Results:**

*Initial Shell Vulnerability Exploited*

*Additional info about where the initial shell was acquired from*

**Vulnerability Explanation:**

**Vulnerability Fix:**

**Severity:**

**Proof of Concept Code Here:**

**Local.txt Proof Screenshot**

**Local.txt Contents**

#### Privilege Escalation

*Additional Priv Esc info*

**Vulnerability Exploited:**

**Vulnerability Explanation:**

**Vulnerability Fix:**

**Severity:**

**Exploit Code:**

**Proof Screenshot Here:**

**Proof.txt Contents:**

### System IP: 192.168.x.x

#### Service Enumeration

Server IP Address | Ports Open
------------------|----------------------------------------
192.168.x.x       | **TCP**: 1433,3389\
**UDP**: 1434,161

**Nmap Scan Results:**

*Initial Shell Vulnerability Exploited*

*Additional info about where the initial shell was acquired from*

**Vulnerability Explanation:**

**Vulnerability Fix:**

**Severity:**

**Proof of Concept Code Here:**

**Local.txt Proof Screenshot**

**Local.txt Contents**

#### Privilege Escalation

*Additional Priv Esc info*

**Vulnerability Exploited:**

**Vulnerability Explanation:**

**Vulnerability Fix:**

**Severity:**

**Exploit Code:**

**Proof Screenshot Here:**

**Proof.txt Contents:**

### System IP: 192.168.x.x

#### Service Enumeration

Server IP Address | Ports Open
------------------|----------------------------------------
192.168.x.x       | **TCP**: 1433,3389\
**UDP**: 1434,161

**Nmap Scan Results:**

*Initial Shell Vulnerability Exploited*

*Additional info about where the initial shell was acquired from*

**Vulnerability Explanation:**

**Vulnerability Fix:**

**Severity:**

**Proof of Concept Code Here:**

**Local.txt Proof Screenshot**

**Local.txt Contents**

#### Privilege Escalation

*Additional Priv Esc info*

**Vulnerability Exploited:**

**Vulnerability Explanation:**

**Vulnerability Fix:**

**Severity:**

**Exploit Code:**

**Proof Screenshot Here:**

**Proof.txt Contents:**

### System IP: 192.168.x.x

**Vulnerability Exploited: bof**

Fill out this section with BOF NOTES.

**Proof Screenshot:**

**Completed Buffer Overflow Code:**

Please see Appendix 1 for the complete Windows Buffer Overflow code.

## Maintaining Access

Maintaining access to a system is important to us as attackers, ensuring that we can get back into a system after it has been exploited is invaluable.
The maintaining access phase of the penetration test focuses on ensuring that once the focused attack has occurred (i.e. a buffer overflow), we have administrative access over the system again.
Many exploits may only be exploitable once and we may never be able to get back into a system after we have already performed the exploit.

## House Cleaning

The house cleaning portions of the assessment ensures that remnants of the penetration test are removed.
Often fragments of tools or user accounts are left on an organization's computer which can cause security issues down the road.
Ensuring that we are meticulous and no remnants of our penetration test are left over is important.

After collecting trophies from the exam network was completed, I removed all user accounts and passwords as well as the Meterpreter services installed on the system.
Offensive Security should not have to remove any user accounts or services from the system.

# Additional Items

## Appendix - Proof and Local Contents:

IP (Hostname) | Local.txt Contents | Proof.txt Contents
--------------|--------------------|-------------------
192.168.134.100   | *N/A* | d513b963ae8d75d5dbddeb04933d1a49
192.168.134.101   | 84cff16d270fab734043cf27ab014109 | *N/A*
192.168.134.101   | edd330f064ef3da6df495095a04e141f | 4a96bdaf1d8a514623671f8b1df7ef0b
192.168.134.110   | d700e9f4a877412386b37fbf9952b2f3 | c7f1cbc6e8de951f34f4e4ea2eda7d2d
192.168.134.114   | 6b4a79fa6bf204b8ca285a808603a6fb | be1c245d1a35ea9103aea962e10ab98e
192.168.134.126   | d11f162102e5a4be16fc071057a1d352 | 507a3fb2ad3a408faf4483622bc6056c
