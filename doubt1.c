[frosty@frosty tryhackme]$ nmap -Pn 10.10.163.140
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-11 21:03 IST
Nmap scan report for 10.10.163.140 (10.10.163.140)
Host is up (0.17s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT     STATE SERVICE
21/tcp   open  ftp
80/tcp   open  http
2222/tcp open  EtherNetIP-1

Nmap done: 1 IP address (1 host up) scanned in 15.00 seconds
[frosty@frosty tryhackme]$ nmap -Pn -p- 10.10.163.140
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-11 21:04 IST
Stats: 0:02:33 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 58.11% done; ETC: 21:09 (0:01:51 remaining)
Stats: 0:02:34 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 58.11% done; ETC: 21:09 (0:01:52 remaining)

[frosty@frosty tryhackme]$ ^C
[frosty@frosty tryhackme]$ ^C
[frosty@frosty tryhackme]$ ^C
[frosty@frosty tryhackme]$ ^C
[frosty@frosty tryhackme]$ ^C
[frosty@frosty tryhackme]$ nmap -Pn -p- -sV -vv --script vuln 10.10.163.140
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-11 21:07 IST
NSE: Loaded 150 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 21:07
NSE Timing: About 50.00% done; ETC: 21:08 (0:00:31 remaining)
Completed NSE at 21:08, 34.18s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 21:08
Completed NSE at 21:08, 0.00s elapsed
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Initiating Parallel DNS resolution of 1 host. at 21:08
Completed Parallel DNS resolution of 1 host. at 21:08, 0.00s elapsed
Initiating Connect Scan at 21:08
Scanning 10.10.163.140 (10.10.163.140) [65535 ports]
Discovered open port 80/tcp on 10.10.163.140
Discovered open port 21/tcp on 10.10.163.140
Connect Scan Timing: About 3.52% done; ETC: 21:23 (0:14:10 remaining)
Connect Scan Timing: About 16.51% done; ETC: 21:14 (0:05:08 remaining)
Connect Scan Timing: About 27.66% done; ETC: 21:14 (0:03:58 remaining)
Connect Scan Timing: About 36.26% done; ETC: 21:15 (0:04:15 remaining)
Connect Scan Timing: About 50.21% done; ETC: 21:14 (0:02:54 remaining)
Connect Scan Timing: About 61.57% done; ETC: 21:15 (0:02:34 remaining)
Connect Scan Timing: About 68.92% done; ETC: 21:15 (0:02:05 remaining)
Connect Scan Timing: About 75.24% done; ETC: 21:15 (0:01:44 remaining)
Discovered open port 2222/tcp on 10.10.163.140
Connect Scan Timing: About 86.36% done; ETC: 21:15 (0:00:55 remaining)
Connect Scan Timing: About 92.90% done; ETC: 21:15 (0:00:31 remaining)
Completed Connect Scan at 21:15, 437.74s elapsed (65535 total ports)
Initiating Service scan at 21:15
Scanning 3 services on 10.10.163.140 (10.10.163.140)
Completed Service scan at 21:15, 6.43s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.163.140.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 21:15
NSE: [firewall-bypass 10.10.163.140] lacks privileges.
NSE Timing: About 99.24% done; ETC: 21:16 (0:00:00 remaining)
NSE Timing: About 99.24% done; ETC: 21:16 (0:00:00 remaining)
NSE Timing: About 99.24% done; ETC: 21:17 (0:00:01 remaining)
NSE Timing: About 99.24% done; ETC: 21:17 (0:00:01 remaining)
NSE Timing: About 99.24% done; ETC: 21:18 (0:00:01 remaining)
NSE Timing: About 99.24% done; ETC: 21:18 (0:00:01 remaining)
NSE Timing: About 99.24% done; ETC: 21:19 (0:00:02 remaining)
NSE Timing: About 99.24% done; ETC: 21:19 (0:00:02 remaining)
NSE Timing: About 99.24% done; ETC: 21:20 (0:00:02 remaining)
NSE Timing: About 99.24% done; ETC: 21:20 (0:00:02 remaining)
Completed NSE at 21:21, 311.94s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 21:21
NSE: [tls-ticketbleed 10.10.163.140:21] Not running due to lack of privileges.
Completed NSE at 21:21, 0.64s elapsed
Nmap scan report for 10.10.163.140 (10.10.163.140)
Host is up, received user-set (0.15s latency).
Scanned at 2023-08-11 21:08:31 IST for 757s
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE REASON  VERSION
21/tcp   open  ftp     syn-ack vsftpd 3.0.3
80/tcp   open  http    syn-ack Apache httpd 2.4.18 ((Ubuntu))
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-jsonp-detection: Couldn't find any JSONP endpoints.
|_http-wordpress-users: [Error] Wordpress installation was not found. We couldn't find wp-login.php
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-litespeed-sourcecode-download: Request with null byte did not work. This web server might not be vulnerable
| vulners: 
|   cpe:/a:apache:http_server:2.4.18: 
|     	PACKETSTORM:171631	7.5	https://vulners.com/packetstorm/PACKETSTORM:171631	*EXPLOIT*
|     	EDB-ID:51193	7.5	https://vulners.com/exploitdb/EDB-ID:51193	*EXPLOIT*
|     	CVE-2023-25690	7.5	https://vulners.com/cve/CVE-2023-25690
|     	CVE-2022-31813	7.5	https://vulners.com/cve/CVE-2022-31813
|     	CVE-2022-23943	7.5	https://vulners.com/cve/CVE-2022-23943
|     	CVE-2022-22720	7.5	https://vulners.com/cve/CVE-2022-22720
|     	CVE-2021-44790	7.5	https://vulners.com/cve/CVE-2021-44790
|     	CVE-2021-39275	7.5	https://vulners.com/cve/CVE-2021-39275
|     	CVE-2021-26691	7.5	https://vulners.com/cve/CVE-2021-26691
|     	CVE-2017-7679	7.5	https://vulners.com/cve/CVE-2017-7679
|     	CVE-2017-3169	7.5	https://vulners.com/cve/CVE-2017-3169
|     	CVE-2017-3167	7.5	https://vulners.com/cve/CVE-2017-3167
|     	CNVD-2022-73123	7.5	https://vulners.com/cnvd/CNVD-2022-73123
|     	CNVD-2022-03225	7.5	https://vulners.com/cnvd/CNVD-2022-03225
|     	CNVD-2021-102386	7.5	https://vulners.com/cnvd/CNVD-2021-102386
|     	5C1BB960-90C1-5EBF-9BEF-F58BFFDFEED9	7.5	https://vulners.com/githubexploit/5C1BB960-90C1-5EBF-9BEF-F58BFFDFEED9	*EXPLOIT*
|     	1337DAY-ID-38427	7.5	https://vulners.com/zdt/1337DAY-ID-38427	*EXPLOIT*
|     	EXPLOITPACK:44C5118F831D55FAF4259C41D8BDA0AB	7.2	https://vulners.com/exploitpack/EXPLOITPACK:44C5118F831D55FAF4259C41D8BDA0AB	*EXPLOIT*
|     	EDB-ID:46676	7.2	https://vulners.com/exploitdb/EDB-ID:46676	*EXPLOIT*
|     	CVE-2019-0211	7.2	https://vulners.com/cve/CVE-2019-0211
|     	1337DAY-ID-32502	7.2	https://vulners.com/zdt/1337DAY-ID-32502	*EXPLOIT*
|     	FDF3DFA1-ED74-5EE2-BF5C-BA752CA34AE8	6.8	https://vulners.com/githubexploit/FDF3DFA1-ED74-5EE2-BF5C-BA752CA34AE8	*EXPLOIT*
|     	CVE-2021-40438	6.8	https://vulners.com/cve/CVE-2021-40438
|     	CVE-2020-35452	6.8	https://vulners.com/cve/CVE-2020-35452
|     	CVE-2018-1312	6.8	https://vulners.com/cve/CVE-2018-1312
|     	CVE-2017-15715	6.8	https://vulners.com/cve/CVE-2017-15715
|     	CVE-2016-5387	6.8	https://vulners.com/cve/CVE-2016-5387
|     	CNVD-2022-03224	6.8	https://vulners.com/cnvd/CNVD-2022-03224
|     	8AFB43C5-ABD4-52AD-BB19-24D7884FF2A2	6.8	https://vulners.com/githubexploit/8AFB43C5-ABD4-52AD-BB19-24D7884FF2A2	*EXPLOIT*
|     	4810E2D9-AC5F-5B08-BFB3-DDAFA2F63332	6.8	https://vulners.com/githubexploit/4810E2D9-AC5F-5B08-BFB3-DDAFA2F63332	*EXPLOIT*
|     	4373C92A-2755-5538-9C91-0469C995AA9B	6.8	https://vulners.com/githubexploit/4373C92A-2755-5538-9C91-0469C995AA9B	*EXPLOIT*
|     	0095E929-7573-5E4A-A7FA-F6598A35E8DE	6.8	https://vulners.com/githubexploit/0095E929-7573-5E4A-A7FA-F6598A35E8DE	*EXPLOIT*
|     	CVE-2022-28615	6.4	https://vulners.com/cve/CVE-2022-28615
|     	CVE-2021-44224	6.4	https://vulners.com/cve/CVE-2021-44224
|     	CVE-2019-10082	6.4	https://vulners.com/cve/CVE-2019-10082
|     	CVE-2017-9788	6.4	https://vulners.com/cve/CVE-2017-9788
|     	CVE-2019-0217	6.0	https://vulners.com/cve/CVE-2019-0217
|     	CVE-2022-22721	5.8	https://vulners.com/cve/CVE-2022-22721
|     	CVE-2020-1927	5.8	https://vulners.com/cve/CVE-2020-1927
|     	CVE-2019-10098	5.8	https://vulners.com/cve/CVE-2019-10098
|     	1337DAY-ID-33577	5.8	https://vulners.com/zdt/1337DAY-ID-33577	*EXPLOIT*
|     	CVE-2022-36760	5.1	https://vulners.com/cve/CVE-2022-36760
|     	SSV:96537	5.0	https://vulners.com/seebug/SSV:96537	*EXPLOIT*
|     	EXPLOITPACK:C8C256BE0BFF5FE1C0405CB0AA9C075D	5.0	https://vulners.com/exploitpack/EXPLOITPACK:C8C256BE0BFF5FE1C0405CB0AA9C075D	*EXPLOIT*
|     	EXPLOITPACK:2666FB0676B4B582D689921651A30355	5.0	https://vulners.com/exploitpack/EXPLOITPACK:2666FB0676B4B582D689921651A30355	*EXPLOIT*
|     	EDB-ID:42745	5.0	https://vulners.com/exploitdb/EDB-ID:42745	*EXPLOIT*
|     	EDB-ID:40909	5.0	https://vulners.com/exploitdb/EDB-ID:40909	*EXPLOIT*
|     	CVE-2022-37436	5.0	https://vulners.com/cve/CVE-2022-37436
|     	CVE-2022-30556	5.0	https://vulners.com/cve/CVE-2022-30556
|     	CVE-2022-29404	5.0	https://vulners.com/cve/CVE-2022-29404
|     	CVE-2022-28614	5.0	https://vulners.com/cve/CVE-2022-28614
|     	CVE-2022-26377	5.0	https://vulners.com/cve/CVE-2022-26377
|     	CVE-2022-22719	5.0	https://vulners.com/cve/CVE-2022-22719
|     	CVE-2021-34798	5.0	https://vulners.com/cve/CVE-2021-34798
|     	CVE-2021-33193	5.0	https://vulners.com/cve/CVE-2021-33193
|     	CVE-2021-26690	5.0	https://vulners.com/cve/CVE-2021-26690
|     	CVE-2020-1934	5.0	https://vulners.com/cve/CVE-2020-1934
|     	CVE-2019-17567	5.0	https://vulners.com/cve/CVE-2019-17567
|     	CVE-2019-0220	5.0	https://vulners.com/cve/CVE-2019-0220
|     	CVE-2019-0196	5.0	https://vulners.com/cve/CVE-2019-0196
|     	CVE-2018-17199	5.0	https://vulners.com/cve/CVE-2018-17199
|     	CVE-2018-17189	5.0	https://vulners.com/cve/CVE-2018-17189
|     	CVE-2018-1333	5.0	https://vulners.com/cve/CVE-2018-1333
|     	CVE-2018-1303	5.0	https://vulners.com/cve/CVE-2018-1303
|     	CVE-2017-9798	5.0	https://vulners.com/cve/CVE-2017-9798
|     	CVE-2017-15710	5.0	https://vulners.com/cve/CVE-2017-15710
|     	CVE-2016-8743	5.0	https://vulners.com/cve/CVE-2016-8743
|     	CVE-2016-8740	5.0	https://vulners.com/cve/CVE-2016-8740
|     	CVE-2016-4979	5.0	https://vulners.com/cve/CVE-2016-4979
|     	CVE-2006-20001	5.0	https://vulners.com/cve/CVE-2006-20001
|     	CNVD-2022-73122	5.0	https://vulners.com/cnvd/CNVD-2022-73122
|     	CNVD-2022-53584	5.0	https://vulners.com/cnvd/CNVD-2022-53584
|     	CNVD-2022-53582	5.0	https://vulners.com/cnvd/CNVD-2022-53582
|     	CNVD-2022-03223	5.0	https://vulners.com/cnvd/CNVD-2022-03223
|     	1337DAY-ID-28573	5.0	https://vulners.com/zdt/1337DAY-ID-28573	*EXPLOIT*
|     	CVE-2020-11985	4.3	https://vulners.com/cve/CVE-2020-11985
|     	CVE-2019-10092	4.3	https://vulners.com/cve/CVE-2019-10092
|     	CVE-2018-1302	4.3	https://vulners.com/cve/CVE-2018-1302
|     	CVE-2018-1301	4.3	https://vulners.com/cve/CVE-2018-1301
|     	CVE-2018-11763	4.3	https://vulners.com/cve/CVE-2018-11763
|     	CVE-2016-4975	4.3	https://vulners.com/cve/CVE-2016-4975
|     	CVE-2016-1546	4.3	https://vulners.com/cve/CVE-2016-1546
|     	4013EC74-B3C1-5D95-938A-54197A58586D	4.3	https://vulners.com/githubexploit/4013EC74-B3C1-5D95-938A-54197A58586D	*EXPLOIT*
|     	1337DAY-ID-33575	4.3	https://vulners.com/zdt/1337DAY-ID-33575	*EXPLOIT*
|     	CVE-2018-1283	3.5	https://vulners.com/cve/CVE-2018-1283
|     	CVE-2016-8612	3.3	https://vulners.com/cve/CVE-2016-8612
|_    	PACKETSTORM:152441	0.0	https://vulners.com/packetstorm/PACKETSTORM:152441	*EXPLOIT*
| http-slowloris-check: 
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|       
|     Disclosure date: 2009-09-17
|     References:
|       http://ha.ckers.org/slowloris/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
| http-enum: 
|_  /robots.txt: Robots file
2222/tcp open  ssh     syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| vulners: 
|   cpe:/a:openbsd:openssh:7.2p2: 
|     	PACKETSTORM:140070	7.8	https://vulners.com/packetstorm/PACKETSTORM:140070	*EXPLOIT*
|     	EXPLOITPACK:5BCA798C6BA71FAE29334297EC0B6A09	7.8	https://vulners.com/exploitpack/EXPLOITPACK:5BCA798C6BA71FAE29334297EC0B6A09	*EXPLOIT*
|     	EDB-ID:40888	7.8	https://vulners.com/exploitdb/EDB-ID:40888	*EXPLOIT*
|     	CVE-2016-8858	7.8	https://vulners.com/cve/CVE-2016-8858
|     	CVE-2016-6515	7.8	https://vulners.com/cve/CVE-2016-6515
|     	1337DAY-ID-26494	7.8	https://vulners.com/zdt/1337DAY-ID-26494	*EXPLOIT*
|     	SSV:92579	7.5	https://vulners.com/seebug/SSV:92579	*EXPLOIT*
|     	PACKETSTORM:173661	7.5	https://vulners.com/packetstorm/PACKETSTORM:173661	*EXPLOIT*
|     	CVE-2023-35784	7.5	https://vulners.com/cve/CVE-2023-35784
|     	CVE-2016-10009	7.5	https://vulners.com/cve/CVE-2016-10009
|     	1337DAY-ID-26576	7.5	https://vulners.com/zdt/1337DAY-ID-26576	*EXPLOIT*
|     	SSV:92582	7.2	https://vulners.com/seebug/SSV:92582	*EXPLOIT*
|     	CVE-2016-10012	7.2	https://vulners.com/cve/CVE-2016-10012
|     	CVE-2015-8325	7.2	https://vulners.com/cve/CVE-2015-8325
|     	SSV:92580	6.9	https://vulners.com/seebug/SSV:92580	*EXPLOIT*
|     	CVE-2016-10010	6.9	https://vulners.com/cve/CVE-2016-10010
|     	1337DAY-ID-26577	6.9	https://vulners.com/zdt/1337DAY-ID-26577	*EXPLOIT*
|     	EXPLOITPACK:98FE96309F9524B8C84C508837551A19	5.8	https://vulners.com/exploitpack/EXPLOITPACK:98FE96309F9524B8C84C508837551A19	*EXPLOIT*
|     	EXPLOITPACK:5330EA02EBDE345BFC9D6DDDD97F9E97	5.8	https://vulners.com/exploitpack/EXPLOITPACK:5330EA02EBDE345BFC9D6DDDD97F9E97	*EXPLOIT*
|     	EDB-ID:46516	5.8	https://vulners.com/exploitdb/EDB-ID:46516	*EXPLOIT*
|     	EDB-ID:46193	5.8	https://vulners.com/exploitdb/EDB-ID:46193	*EXPLOIT*
|     	CVE-2019-6111	5.8	https://vulners.com/cve/CVE-2019-6111
|     	1337DAY-ID-32328	5.8	https://vulners.com/zdt/1337DAY-ID-32328	*EXPLOIT*
|     	1337DAY-ID-32009	5.8	https://vulners.com/zdt/1337DAY-ID-32009	*EXPLOIT*
|     	SSV:91041	5.5	https://vulners.com/seebug/SSV:91041	*EXPLOIT*
|     	PACKETSTORM:140019	5.5	https://vulners.com/packetstorm/PACKETSTORM:140019	*EXPLOIT*
|     	PACKETSTORM:136234	5.5	https://vulners.com/packetstorm/PACKETSTORM:136234	*EXPLOIT*
|     	EXPLOITPACK:F92411A645D85F05BDBD274FD222226F	5.5	https://vulners.com/exploitpack/EXPLOITPACK:F92411A645D85F05BDBD274FD222226F	*EXPLOIT*
|     	EXPLOITPACK:9F2E746846C3C623A27A441281EAD138	5.5	https://vulners.com/exploitpack/EXPLOITPACK:9F2E746846C3C623A27A441281EAD138	*EXPLOIT*
|     	EXPLOITPACK:1902C998CBF9154396911926B4C3B330	5.5	https://vulners.com/exploitpack/EXPLOITPACK:1902C998CBF9154396911926B4C3B330	*EXPLOIT*
|     	EDB-ID:40858	5.5	https://vulners.com/exploitdb/EDB-ID:40858	*EXPLOIT*
|     	EDB-ID:40119	5.5	https://vulners.com/exploitdb/EDB-ID:40119	*EXPLOIT*
|     	EDB-ID:39569	5.5	https://vulners.com/exploitdb/EDB-ID:39569	*EXPLOIT*
|     	CVE-2016-3115	5.5	https://vulners.com/cve/CVE-2016-3115
|     	SSH_ENUM	5.0	https://vulners.com/canvas/SSH_ENUM	*EXPLOIT*
|     	PACKETSTORM:150621	5.0	https://vulners.com/packetstorm/PACKETSTORM:150621	*EXPLOIT*
|     	EXPLOITPACK:F957D7E8A0CC1E23C3C649B764E13FB0	5.0	https://vulners.com/exploitpack/EXPLOITPACK:F957D7E8A0CC1E23C3C649B764E13FB0	*EXPLOIT*
|     	EXPLOITPACK:EBDBC5685E3276D648B4D14B75563283	5.0	https://vulners.com/exploitpack/EXPLOITPACK:EBDBC5685E3276D648B4D14B75563283	*EXPLOIT*
|     	EDB-ID:45939	5.0	https://vulners.com/exploitdb/EDB-ID:45939	*EXPLOIT*
|     	EDB-ID:45233	5.0	https://vulners.com/exploitdb/EDB-ID:45233	*EXPLOIT*
|     	CVE-2018-15919	5.0	https://vulners.com/cve/CVE-2018-15919
|     	CVE-2018-15473	5.0	https://vulners.com/cve/CVE-2018-15473
|     	CVE-2017-15906	5.0	https://vulners.com/cve/CVE-2017-15906
|     	CVE-2016-10708	5.0	https://vulners.com/cve/CVE-2016-10708
|     	1337DAY-ID-31730	5.0	https://vulners.com/zdt/1337DAY-ID-31730	*EXPLOIT*
|     	CVE-2021-41617	4.4	https://vulners.com/cve/CVE-2021-41617
|     	EXPLOITPACK:802AF3229492E147A5F09C7F2B27C6DF	4.3	https://vulners.com/exploitpack/EXPLOITPACK:802AF3229492E147A5F09C7F2B27C6DF	*EXPLOIT*
|     	EXPLOITPACK:5652DDAA7FE452E19AC0DC1CD97BA3EF	4.3	https://vulners.com/exploitpack/EXPLOITPACK:5652DDAA7FE452E19AC0DC1CD97BA3EF	*EXPLOIT*
|     	EDB-ID:40136	4.3	https://vulners.com/exploitdb/EDB-ID:40136	*EXPLOIT*
|     	EDB-ID:40113	4.3	https://vulners.com/exploitdb/EDB-ID:40113	*EXPLOIT*
|     	CVE-2023-29323	4.3	https://vulners.com/cve/CVE-2023-29323
|     	CVE-2020-14145	4.3	https://vulners.com/cve/CVE-2020-14145
|     	CVE-2016-6210	4.3	https://vulners.com/cve/CVE-2016-6210
|     	1337DAY-ID-25440	4.3	https://vulners.com/zdt/1337DAY-ID-25440	*EXPLOIT*
|     	1337DAY-ID-25438	4.3	https://vulners.com/zdt/1337DAY-ID-25438	*EXPLOIT*
|     	CVE-2019-6110	4.0	https://vulners.com/cve/CVE-2019-6110
|     	CVE-2019-6109	4.0	https://vulners.com/cve/CVE-2019-6109
|     	CVE-2018-20685	2.6	https://vulners.com/cve/CVE-2018-20685
|     	SSV:92581	2.1	https://vulners.com/seebug/SSV:92581	*EXPLOIT*
|     	CVE-2016-10011	2.1	https://vulners.com/cve/CVE-2016-10011
|     	PACKETSTORM:151227	0.0	https://vulners.com/packetstorm/PACKETSTORM:151227	*EXPLOIT*
|     	PACKETSTORM:140261	0.0	https://vulners.com/packetstorm/PACKETSTORM:140261	*EXPLOIT*
|     	PACKETSTORM:138006	0.0	https://vulners.com/packetstorm/PACKETSTORM:138006	*EXPLOIT*
|     	PACKETSTORM:137942	0.0	https://vulners.com/packetstorm/PACKETSTORM:137942	*EXPLOIT*
|     	MSF:AUXILIARY-SCANNER-SSH-SSH_ENUMUSERS-	0.0	https://vulners.com/metasploit/MSF:AUXILIARY-SCANNER-SSH-SSH_ENUMUSERS-	*EXPLOIT*
|_    	1337DAY-ID-30937	0.0	https://vulners.com/zdt/1337DAY-ID-30937	*EXPLOIT*
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 21:21
Completed NSE at 21:21, 0.00s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 21:21
Completed NSE at 21:21, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 791.62 seconds
[frosty@frosty tryhackme]$ nmap -p2222 --script vuln 10.10.163.140
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-11 21:30 IST
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 10.10.163.140 (10.10.163.140)
Host is up (0.17s latency).

PORT     STATE SERVICE
2222/tcp open  EtherNetIP-1

Nmap done: 1 IP address (1 host up) scanned in 35.62 seconds
[frosty@frosty tryhackme]$ nmap -Pn -p2222 --script vuln 10.10.163.140
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-11 21:33 IST

[frosty@frosty tryhackme]$ nmap -Pn -p2222 --script vuln 10.10.163.140
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-11 21:33 IST
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|   Hosts that seem down (vulnerable):
|_    224.0.0.251
Nmap scan report for 10.10.163.140 (10.10.163.140)
Host is up (0.21s latency).

PORT     STATE SERVICE
2222/tcp open  EtherNetIP-1

Nmap done: 1 IP address (1 host up) scanned in 36.02 seconds
[frosty@frosty tryhackme]$ nmap -p --script vuln 10.10.163.140

