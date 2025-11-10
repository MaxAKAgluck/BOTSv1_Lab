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

Query: sourcetype="stream:http" imreallynotbatman.com | stats values(dest_ip)

There are two hits, 192.168.250.70 is the most frequent destination so it is the server's ip.

4 - Find the name of the file used to deface the web server serving "imreallynotbatman.com". 

First get a look at stream:http, we find an interesting field form_data

<img width="801" height="250" alt="image" src="https://github.com/user-attachments/assets/c412610c-f9ef-4619-bacf-3daceb77d03f" />

Then I got stuck :), looking at the hint, I filtered for events: sourcetype="stream:http" c_ip=192.168.250.70 | stats values(uri)

And the answer is seen immediately:

<img width="456" height="152" alt="image" src="https://github.com/user-attachments/assets/e3ad178b-97ac-4c42-be1f-01727affdc3e" />

5 - Find the fully qualified domain name (FQDN) used by the staging server hosting the defacement file. 

Query: sourcetype="stream:http" poisonivy-is-coming-for-you-batman.jpeg

There are only 3 events and scrolling we find a field - site, which contains all we need.

<img width="757" height="160" alt="image" src="https://github.com/user-attachments/assets/4888ac5c-6386-4d58-8c10-1e72b35db90e" />


Answer is prankglassinebracket.jumpingcrab.com:1337.


6 - In Level 1, you found the staging server domain name (used to host the defacement file). Find that server's IP adddress.

The same query, in the same event just looking at dest_ip we see answer is 23.22.63.114.

7 - Couldn't answer that without hint, which gave the answer right away - Alienvault is useful. (Link - https://otx.alienvault.com/indicator/ip/23.22.63.114)

8 - Find the IP address performing a brute force attack against "imreallynotbatman.com".

Tried a generic query in stream:http: sourcetype="stream:http" http_method=GET AND dest_ip=192.168.250.70

<img width="804" height="150" alt="image" src="https://github.com/user-attachments/assets/a4c851f3-c07e-4604-826c-a1978080670a" />

Hint said look for POST requests (also I filtered the Acunetix messages):

Query: sourcetype="stream:http" http_method=POST AND dest_ip=192.168.250.70 AND src_headers!="*PROHIBITED*" AND dest_headers!="*PROHIBITED*" 

<img width="799" height="120" alt="image" src="https://github.com/user-attachments/assets/f74f05da-2391-4c8b-bf50-facd2ca660ef" />

Proceeded to look at requests by 23.22.63.114:

<img width="779" height="417" alt="image" src="https://github.com/user-attachments/assets/2cd33ce5-1c28-487f-8eda-f01585839d81" />


Form_data field had obvious bruteforce patterns.

Answer - 23.22.63.114


9 - 10 Find the name of the executable file the attacker uploaded to the server. Find the MD5 hash of that executable.

Decided to search in same stream:http: sourcetype="stream:http" http_method=POST AND dest_ip=192.168.250.70 AND src_headers!="*PROHIBITED*" AND dest_headers!="*PROHIBITED*" *.exe* 

Found only one event which has directory listing, it was awfull looking at all this chaotic data but I found a 3791.exe, for which I searched suricata logs: sourcetype="suricata" 3791.exe

<img width="1318" height="777" alt="image" src="https://github.com/user-attachments/assets/95c21d15-5fd8-4575-9b17-92702d054a7c" />

 Answer is 3791.exe

Section is called sysmon so its logical to search for MD5 in sysmon events, started with a broad query: sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" 3791.exe

Then noticed that there is "ParentCommandLine" and filtered for CommandLine=*3791.exe* : sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" CommandLine=*3791.exe*

<img width="1989" height="232" alt="image" src="https://github.com/user-attachments/assets/b1ae74d7-e15d-423e-b902-6b7261a35574" />


The hashes are there, we see MD5 is AAE3F5A29935E6ABCC2C2754D12A9AF0 which is the answer.

11 - What was the first brute force password used?

The question is a little vague, but I actually already know where to look - form_data field with username/passwd entries, query: sourcetype="stream:http" http_method=POST AND dest_ip=192.168.250.70 AND src_headers!="*PROHIBITED*" AND dest_headers!="*PROHIBITED*" form_data = "*&passwd=*" | stats values(form_data)

<img width="1229" height="355" alt="image" src="https://github.com/user-attachments/assets/c40e12bd-caf8-405f-a23b-740fe5031dee" />

But this doesn't give us the values in the timely order, so its better to use table: sourcetype="stream:http" http_method=POST AND dest_ip=192.168.250.70 AND src_headers!="*PROHIBITED*" AND dest_headers!="*PROHIBITED*" form_data = "*&passwd=*" | table form_data, timestamp | sort timestamp

We get the passwords in ascending time order and the first one was 12345678.

12 - What was the correct password found in the brute force attack?

Looking in the same place as previous question, we sort in reverse order and find the last attempt was batman and it used a different query and user agent (Mozilla instead of Python urllib which was used for bruteforcing):

<img width="1304" height="549" alt="image" src="https://github.com/user-attachments/assets/49583aec-54cd-45c7-bccc-aed63743244b" />

So we conclude answer is batman.

13 - How many seconds elapsed between the time the brute force password scan identified the correct password and the compromised login? Round to 2 decimal places.

Running the same query, because it identifies 2 events with correct password:

sourcetype="stream:http" http_method=POST AND dest_ip=192.168.250.70 AND src_headers!="*PROHIBITED*" AND dest_headers!="*PROHIBITED*" form_data = "*&passwd=batman*"
| eval epoch_time=strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%6N") 
| stats min(epoch_time) as first max(epoch_time) as second 
| eval diff=round(second - first, 2)

I had to use chatgpt to understand how to get the difference between fields, the answer we get is 98.32. However in writeup this is different because of using the splunk timestamps and not the event timestamps, I'm not sure what is right, technically event timestamps are more accurate.

14 - How many unique passwords were attempted in the brute force attack?

Easiest way is using this query: sourcetype="stream:http" http_method=POST AND dest_ip=192.168.250.70 AND src_headers!="*PROHIBITED*" AND dest_headers!="*PROHIBITED*" form_data = "*&passwd=*"| stats dc(form_data)

However, we need to remember from previous examination that attacker used batman 2 times:

<img width="1352" height="661" alt="image" src="https://github.com/user-attachments/assets/c474b3bb-1c2f-4476-8000-b1d0ad8de1df" />

So a better query is by filtering for Python user agent (again, we identified its the bruteforce tool agent): sourcetype="stream:http" http_method=POST AND dest_ip=192.168.250.70 AND src_headers!="*PROHIBITED*" AND dest_headers!="*PROHIBITED*" form_data = "*&passwd=*" http_user_agent="Python-urllib/2.7"

And we get 411 events which should be the correct answer.

15 - What was the most likely IP address of we8105desk on 24AUG2016?

Used 1:100 sampling for speed and searched for: sourcetype="*" we8105desk, identified 4 sourcetypes, sysmon probably won't help much with IP, so we search in wineventlog, which was probably a deadend (examined fields and no IP), went to smb logs:

<img width="659" height="541" alt="image" src="https://github.com/user-attachments/assets/3caace48-247c-4ed7-8100-7bd1d410e6d8" />

Answer is seen at once - 192.168.250.100

16 - Amongst the Suricata signatures that detected the Cerber malware, which one alerted the fewest number of times? Submit ONLY the signature ID value as the answer. (No punctuation, just 7 integers.)

An easy question - search: *Cerber* sourcetype="suricata", got this:

<img width="1207" height="571" alt="image" src="https://github.com/user-attachments/assets/6e63d90a-7273-490d-b3c7-7aea0f1f3e95" />

Answer is seen immediately - 2816763.

17 - What fully qualified domain name (FQDN) does the Cerber ransomware attempt to direct the user to at the end of its encryption phase? 

 
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
