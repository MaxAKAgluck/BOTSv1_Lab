# 🕵️‍♂️ BOTSv1 Splunk Challenge — My Progress Log

Welcome to my little corner of investigation chaos 😄  
This repo is for tracking my own journey through BOTSv1 Splunk challenge

Notes: 
1. I didn't want to download BOTS dataset on my own PC and go through the process of spinning up my own Splunk Enterprise instance. I used an online instance with dataset loaded already, see resources for links. 
2. I have almost no experience with such challenges and don't know advanced query language or tricks used by those regularly participating in such challenges.
3. I used hints provided with questions when I got stuck and verified my answers on this writeup: [Writeup](https://medium.com/@sabinaaliy3va/splunk-botsv1-writeup-47b73a2eadac)

---

## 📘 About BOTSv1

**Boss of the SOC (BOTS)** is a blue-team capture-the-flag challenge by Splunk.  
The goal: analyze security data in Splunk to answer questions about a simulated security incident.  

This is a hands-on way to level up threat hunting, detection, and analysis skills.

---

## 🚀 My Goals

- Learn how to navigate and query Splunk 
- Practice real-world investigation and incident response techniques  
- Document my process clearly enough for others (and future me)  
- Add this as a practical project in my security portfolio  

---

## 🛠 Resources
- [Splunk instance](https://splunk.samsclass.info/)
- [Splunk BOTS Questions](https://samsclass.info/50/proj/botsv1.htm)
- [Official BOTSv1 Dataset](https://github.com/splunk/botsv1)
- [Splunk Cheatsheet](https://github.com/splunk/botsv1)

---

## 🧩 Progress Log

| Date       |                              Question                                                              |

 2025-11-04       1 - Find the brand name of the vulnerability scanner, covered by a green box in the image above.   
 
 Solving process:
 First, I wanted to get an overview of what sources we have, there is a useful cquery just for this purpose: "| metadata type=sourcetypes | table sourcetype |". 
 
 We see there are 21 (!) sourcetypes: 
 
'''
WinRegistry
XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
fgt_event
fgt_traffic
fgt_utm
iis
nessus:scan
stream:dhcp
stream:dns
stream:http
stream:icmp
stream:ip
stream:ldap
stream:mapi
stream:sip
stream:smb
stream:snmp
stream:tcp
suricata
syslog
wineventlog
'''
The first question mentions we need to use stream:http and imreallynotbatman.com domain in our search. I also included a regex to search for "Scanning PROHIBITED" and limit results on page since I thought a lot of events will contain data from sec.scanner:

sourcetype = "stream:http" imreallynotbatman.com src_headers="*Scanning PROHIBITED*" | table src_headers | head 30

<img width="1230" height="446" alt="image" src="https://github.com/user-attachments/assets/415d7bab-d61c-4d48-b775-574230e6941a" />

We see answer is Acunetix

2 - Find the attacker's IP address. 

In previous sourcetype (stream:http) there are lots of requests from 40.80.148.42, query all sources with this ip and we find it has lots of events in suricata, then final query is this: 

40.80.148.42 sourcetype="suricata" | stats values(signature)

<img width="1304" height="901" alt="image" src="https://github.com/user-attachments/assets/d981751b-fa04-4831-9534-a69344a0cf06" />

40.80.148.42 is the answer

3 - Find the IP address of the web server serving "imreallynotbatman.com".

Query - sourcetype="stream:http" imreallynotbatman.com | stats values(dest_ip)
There are two hits, 192.168.250.70 is the most frequent destination so it is the server's ip.

4 - Find the name of the file used to deface the web server serving "imreallynotbatman.com". 


_(I'll update this as I go — small wins count!)_

---

## 🧠 Lessons Learned

A few early takeaways:
- Writing clear SPL queries is *half art, half science*  
- Investigations flow better when I tag interesting events early  
- Documentation saves sanity later on  

---

## 📎 Resources & References

- [Splunk SPL Cheatsheet](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/CheatSheet)
- [TryHackMe: Splunk101 Room](https://tryhackme.com/room/splunk101)
- [Splunk BOTS Overview Blog](https://www.splunk.com/en_us/blog.html)

---

**Thanks for reading!**  
If you're also doing BOTSv1, feel free to swap notes or tips — always happy to learn from others.
