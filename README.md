# Goscan
A fast portscanner written in Go inspired by the Rustscan project (https://github.com/bee-san/RustScan).

```
./goscan   
Usage of ./goscan:
  -a, --addresses string   Comma-separated list of addresses or CIDR ranges to scan
  -b, --batch-size int     The batch size for port scanning (default 3000)
  -d, --debug              Enable debug output
  -n, --nmap               Run nmap on hosts with open ports
  -N, --nmapargs string    Additional arguments for nmap (e.g., "-sV")
  -p, --ports string       A port range (e.g., 1-1000) or a list of comma separated ports (e.g., 22,80,443) to scan (default "1-65535")
  -r, --retries int        Number of retries for each port scan (default 1)
  -t, --timeout int        Timeout for each port scan (default 1)
```

```
./goscan -a 45.33.32.156 -n -N "-sV" -r 2 -d -p 1-1000
Open 45.33.32.156:80
Open 45.33.32.156:22
45.33.32.156 -> [22,80]
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-05 16:28 EDT
Nmap scan report for scanme.nmap.org (45.33.32.156)
Host is up (0.17s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.47 seconds
```