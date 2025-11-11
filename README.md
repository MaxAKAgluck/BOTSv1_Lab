

---

# 🕵️‍♂️ BOTSv1 Splunk Challenge — My Progress Log

Welcome to my little corner of investigation chaos 😄  
This repo is for tracking my own journey through the BOTSv1 Splunk challenge.

## Notes

1. I didn't want to download the BOTS dataset on my own PC and go through the process of spinning up my own Splunk Enterprise instance. I used an online instance with the dataset already loaded (see Resources for links).
2. I have almost no experience with such challenges and don't know advanced query language or tricks used by those who regularly participate in them.
3. I used hints provided with questions when I got stuck and verified my answers using this [writeup](https://medium.com/@sabinaaliy3va/splunk-botsv1-writeup-47b73a2eadac).

***

## 📘 About BOTSv1

**Boss of the SOC (BOTS)** is a blue-team capture-the-flag challenge by Splunk. The goal: analyze security data in Splunk to answer questions about a simulated security incident.

This is a hands-on way to level up threat hunting, detection, and analysis skills.

---

## 🚀 My Goals

- Learn how to navigate and query Splunk
- Practice real-world investigation and incident response techniques
- Document my process clearly enough for others (and future me)
- Add this as a practical project in my security portfolio

***

## 📎 Resources

- [Splunk instance](https://splunk.samsclass.info/)
- [Splunk BOTS Questions](https://samsclass.info/50/proj/botsv1.htm)
- [Official BOTSv1 Dataset](https://github.com/splunk/botsv1)
- [Splunk SPL Cheatsheet](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/CheatSheet)
- [TryHackMe: Splunk101 Room](https://tryhackme.com/room/splunk101)
- [Splunk Blog](https://www.splunk.com/en_us/blog.html)

***

## 🧩 Progress Log

### Question 1 — Find the brand name of the vulnerability scanner

First, I wanted to get an overview of what sources we have. There's a useful query just for this purpose:

```
| metadata type=sourcetypes | table sourcetype
```

We see there are 21 sourcetypes:

```
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
```

The first question mentions we need to use `stream:http` and `imreallynotbatman.com` domain in our search. I also included a regex to search for "Scanning PROHIBITED" and limit results on the page since a hint suggested a lot of events will contain data from the security scanner:

```
sourcetype="stream:http" imreallynotbatman.com src_headers="*Scanning PROHIBITED*" | table src_headers | head 30
```

<img width="1230" height="446" alt="image" src="https://github.com/user-attachments/assets/415d7bab-d61c-4d48-b775-574230e6941a" />

**Answer:** Acunetix

### Question 2 — Find the attacker's IP address

In the previous sourcetype (`stream:http`) there are lots of requests from `40.80.148.42`. Query all sources with this IP and we find it has lots of events in suricata:

```
40.80.148.42 sourcetype="suricata" | stats values(signature)
```

<img width="1304" height="901" alt="image" src="https://github.com/user-attachments/assets/d981751b-fa04-4831-9534-a69344a0cf06" />

**Answer:** 40.80.148.42

### Question 3 — Find the IP address of the web server serving "imreallynotbatman.com"

Query:

```
sourcetype="stream:http" imreallynotbatman.com | stats values(dest_ip)
```

There are two hits. `192.168.250.70` is the most frequent destination, so it is the server's IP.

**Answer:** 192.168.250.70

### Question 4 — Find the name of the file used to deface the web server

First, I took a look at `stream:http` and found an interesting field called `form_data`.

<img width="801" height="250" alt="image" src="https://github.com/user-attachments/assets/c412610c-f9ef-4619-bacf-3daceb77d03f" />

Then I got stuck 😅. Looking at the hint, I filtered for events:

```
sourcetype="stream:http" c_ip=192.168.250.70 | stats values(uri)
```

The answer is seen immediately:

<img width="456" height="152" alt="image" src="https://github.com/user-attachments/assets/e3ad178b-97ac-4c42-be1f-01727affdc3e" />

**Answer:** poisonivy-is-coming-for-you-batman.jpeg

### Question 5 — Find the FQDN used by the staging server hosting the defacement file

Query:

```
sourcetype="stream:http" poisonivy-is-coming-for-you-batman.jpeg
```

There are only 3 events and scrolling through, I found a field called `site` which contains all we need.

<img width="757" height="160" alt="image" src="https://github.com/user-attachments/assets/4888ac5c-6386-4d58-8c10-1e72b35db90e" />

**Answer:** prankglassinebracket.jumpingcrab.com:1337

### Question 6 — Find the staging server's IP address

Same query as the previous question. In the same event, just looking at `dest_ip`, we see the answer.

**Answer:** 23.22.63.114

### Question 7 — Additional information about the staging server

Couldn't answer this without the hint, which gave the answer right away — Alienvault is useful. ([Link](https://otx.alienvault.com/indicator/ip/23.22.63.114))

### Question 8 — Find the IP address performing a brute force attack

Tried a generic query in `stream:http`:

```
sourcetype="stream:http" http_method=GET AND dest_ip=192.168.250.70
```

<img width="804" height="150" alt="image" src="https://github.com/user-attachments/assets/a4c851f3-c07e-4604-826c-a1978080670a" />

The hint said to look for POST requests (also I filtered out the Acunetix messages):

```
sourcetype="stream:http" http_method=POST AND dest_ip=192.168.250.70 AND src_headers!="*PROHIBITED*" AND dest_headers!="*PROHIBITED*"
```

<img width="799" height="120" alt="image" src="https://github.com/user-attachments/assets/f74f05da-2391-4c8b-bf50-facd2ca660ef" />

Proceeded to look at requests by `23.22.63.114`:

<img width="779" height="417" alt="image" src="https://github.com/user-attachments/assets/2cd33ce5-1c28-487f-8eda-f01585839d81" />

The `form_data` field had obvious brute force patterns.

**Answer:** 23.22.63.114

### Questions 9 & 10 — Find the executable file uploaded and its MD5 hash

Decided to search in the same `stream:http`:

```
sourcetype="stream:http" http_method=POST AND dest_ip=192.168.250.70 AND src_headers!="*PROHIBITED*" AND dest_headers!="*PROHIBITED*" *.exe*
```

Found only one event which has a directory listing. It was awful looking at all this chaotic data, but I found `3791.exe`, for which I searched suricata logs:

```
sourcetype="suricata" 3791.exe
```

<img width="1318" height="777" alt="image" src="https://github.com/user-attachments/assets/95c21d15-5fd8-4575-9b17-92702d054a7c" />

**Answer:** 3791.exe

The section is called sysmon, so it's logical to search for MD5 in sysmon events. Started with a broad query:

```
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" 3791.exe
```

Then noticed there is `ParentCommandLine` and filtered for `CommandLine`:

```
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" CommandLine=*3791.exe*
```

<img width="1989" height="232" alt="image" src="https://github.com/user-attachments/assets/b1ae74d7-e15d-423e-b902-6b7261a35574" />

The hashes are there. We see MD5 is `AAE3F5A29935E6ABCC2C2754D12A9AF0`.

**Answer:** AAE3F5A29935E6ABCC2C2754D12A9AF0

### Question 11 — What was the first brute force password used?

The question is a little vague, but I actually already know where to look — the `form_data` field with username/passwd entries:

```
sourcetype="stream:http" http_method=POST AND dest_ip=192.168.250.70 AND src_headers!="*PROHIBITED*" AND dest_headers!="*PROHIBITED*" form_data="*&passwd=*" | stats values(form_data)
```

<img width="1229" height="355" alt="image" src="https://github.com/user-attachments/assets/c40e12bd-caf8-405f-a23b-740fe5031dee" />

This doesn't give us the values in timely order, so it's better to use table:

```
sourcetype="stream:http" http_method=POST AND dest_ip=192.168.250.70 AND src_headers!="*PROHIBITED*" AND dest_headers!="*PROHIBITED*" form_data="*&passwd=*" | table form_data, timestamp | sort timestamp
```

We get the passwords in ascending time order and the first one was `12345678`.

**Answer:** 12345678

### Question 12 — What was the correct password found in the brute force attack?

Looking in the same place as the previous question, we sort in reverse order and find the last attempt was `batman` and it used a different query and user agent (Mozilla instead of Python urllib which was used for brute forcing):

<img width="1304" height="549" alt="image" src="https://github.com/user-attachments/assets/49583aec-54cd-45c7-bccc-aed63743244b" />

**Answer:** batman

### Question 13 — Time elapsed between password identification and compromised login

Running the same query because it identifies 2 events with the correct password:

```
sourcetype="stream:http" http_method=POST AND dest_ip=192.168.250.70 AND src_headers!="*PROHIBITED*" AND dest_headers!="*PROHIBITED*" form_data="*&passwd=batman*"
| eval epoch_time=strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%6N") 
| stats min(epoch_time) as first max(epoch_time) as second 
| eval diff=round(second - first, 2)
```

I had to use ChatGPT to understand how to get the difference between fields. The answer we get is `98.32`. However, in the writeup this is different because of using the Splunk timestamps and not the event timestamps. I'm not sure what is correct — technically event timestamps are more accurate.

**Answer:** 98.32

### Question 14 — How many unique passwords were attempted?

Easiest way is using this query:

```
sourcetype="stream:http" http_method=POST AND dest_ip=192.168.250.70 AND src_headers!="*PROHIBITED*" AND dest_headers!="*PROHIBITED*" form_data="*&passwd=*" | stats dc(form_data)
```

However, we need to remember from previous examination that the attacker used `batman` 2 times:

<img width="1352" height="661" alt="image" src="https://github.com/user-attachments/assets/c474b3bb-1c2f-4476-8000-b1d0ad8de1df" />

A better query is by filtering for the Python user agent (again, we identified it's the brute force tool agent):

```
sourcetype="stream:http" http_method=POST AND dest_ip=192.168.250.70 AND src_headers!="*PROHIBITED*" AND dest_headers!="*PROHIBITED*" form_data="*&passwd=*" http_user_agent="Python-urllib/2.7"
```

We get 411 events, which should be the correct answer.

**Answer:** 411

### Question 15 — Find the IP address of we8105desk on 24AUG2016

Used 1:100 sampling for speed and searched for:

```
sourcetype="*" we8105desk
```

Identified 4 sourcetypes. Sysmon probably won't help much with IP, so I searched in `wineventlog`, which was probably a dead end (examined fields and no IP). Went to SMB logs:

<img width="659" height="541" alt="image" src="https://github.com/user-attachments/assets/3caace48-247c-4ed7-8100-7bd1d410e6d8" />

The answer is seen at once.

**Answer:** 192.168.250.100

### Question 16 — Suricata signature for Cerber that alerted fewest times

An easy question. Search:

```
*Cerber* sourcetype="suricata"
```

<img width="1207" height="571" alt="image" src="https://github.com/user-attachments/assets/6e63d90a-7273-490d-b3c7-7aea0f1f3e95" />

The answer is seen immediately.

**Answer:** 2816763

### Question 17 — Find the FQDN Cerber ransomware directs users to

Filtering for:

```
sourcetype="suricata" *Cerber* eventtype=suricata_eve_dns
```

7 events with DNS records containing FQDN for Cerber malware:

```json
{"timestamp":"2016-08-24T11:15:12.916218-0600","flow_id":4097325782,"in_iface":"eth1","event_type":"dns","src_ip":"192.168.250.20","src_port":53,"dest_ip":"192.168.250.100","dest_port":49456,"proto":"UDP","dns":{"type":"answer","id":61363,"rcode":"NXDOMAIN","rrname":"cerberhhyed5frqa.xmfir0.win"}}
```

**Answer:** cerberhhyed5frqa.xmfir0.win

### Question 18 — First suspicious domain visited by we8105desk on 24AUG2016

Used suricata logs again and after analyzing a couple of fields, used this query:

```
sourcetype="suricata" src_ip="192.168.250.100" eventtype=suricata_eve_http | table http.hostname, timestamp | uniq | sort timestamp
```

**Answer:** solidaritedeproximite.org

(Although it shows 0 alerts on [VirusTotal](https://www.virustotal.com/gui/url/df2ddbde21a04a0c0cb92c00031111bc7dc9b001e0c5f0243943b0b01f2b7b55). Other domains were obviously not harmful.)

### Questions 19 & 20 — VB script function name and field length

The next 2 questions are too close to separate and they're closely related to the previous one, so I searched for:

```
sourcetype="*" *.vbs* we8105desk
```

Got 16 hits, one of which was the answer. Full query:

```
sourcetype="*" *.vbs* we8105desk | eval length=len(CommandLine) | table CommandLine, length
```

<img width="2554" height="757" alt="image" src="https://github.com/user-attachments/assets/ae59a38e-d328-4233-9f18-39079882c70b" />

**Answers:** FuNCtioN GNbiPp(Pt5SZ1) and 4490

### Question 21 — Name of the USB key inserted by Bob Smith

This required searching for keywords I could use, and I found out `FriendlyName` appears every time you plug in a USB. First query:

```
sourcetype="WinRegistry" *friendlyname*
```

This brought up only 2 events:

<img width="768" height="268" alt="image" src="https://github.com/user-attachments/assets/6ba779bd-c8b2-467b-bbaa-9aff311bfff4" />

**Answer:** MIRANDA_PRI

---

_(I'll update this as I go — small wins count!)_

***

## 🧠 Lessons Learned

A few early takeaways:

- Writing clear SPL queries is half art, half science
- Investigations flow better when I tag interesting events early
- Documentation saves sanity later on

***

**Thanks for reading!**  
If you're also doing BOTSv1, feel free to swap notes or tips — always happy to learn from others.

***
