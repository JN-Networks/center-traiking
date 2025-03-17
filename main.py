import requests
import dns.resolver
import socket
import whois
import sys
import threading
import os
import ssl
import urllib3
from datetime import datetime, timezone
from bs4 import BeautifulSoup
from rich import print
from rich.console import Console
import re
from plugins.ascii import show_main_logo, takeover_logo, portscan_logo, header_logo, whois_logo, dirb_logo, ssl_logo, open_redirect_logo, cors_logo, tech_detect_logo, http_methods_logo
from plugins.ascii import dns_zone_logo, banner_logo, email_logo, ti_logo, vuln_scanner_logo, csp_logo, clickjack_logo, cookie_logo

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()

try:
    from builtwith import builtwith
except ImportError:
    builtwith = None


# Function to clear screen
def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

# Subdomain Takeover Checker
def takeover_check():
    clear()
    takeover_logo()
    domain = input("\n[?] Enter domain to check for subdomain takeover: ")
    print(f"\n[+] Fetching subdomains for {domain} from crt.sh ...")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            print("[!] Error fetching data.")
            return

        data = response.json()
        subdomains = set()
        for entry in data:
            name_value = entry['name_value']
            for sub in name_value.split('\n'):
                if sub.endswith(domain):
                    subdomains.add(sub.strip())
        takeover_ready = []
        for sub in subdomains:
            try:
                answers = dns.resolver.resolve(sub, 'CNAME')
                for rdata in answers:
                    cname = rdata.target.to_text()
                    url = f"http://{cname}"
                    try:
                        resp = requests.get(url, timeout=5)
                        if resp.status_code in [404, 400, 410]:
                            takeover_ready.append((sub, cname))
                    except:
                        takeover_ready.append((sub, cname))
            except:
                continue
        if takeover_ready:
            print("\n🚨 Possible Takeover Subdomains:")
            for sub, cname in takeover_ready:
                print(f"  [+] {sub} → {cname}")
        else:
            print("\n✅ No takeover-vulnerable subdomains found.")
    except Exception as e:
        print(f"[!] Error: {e}")
    input("\n[Press ENTER to return to menu or type 'exit' to quit]: ").lower().strip() == "exit" and sys.exit()

# Port Scanner
def portscanner():
    clear()
    portscan_logo()
    target = input("\n[?] Enter IP or domain for port scan: ")
    ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389]
    print(f"\n[+] Scanning common ports for {target}...")
    
    def scan_port(port):
        try:
            s = socket.socket()
            s.settimeout(1)
            s.connect((target, port))
            print(f"[+] Port {port} open")
            s.close()
        except:
            pass

    threads = []
    for port in ports:
        t = threading.Thread(target=scan_port, args=(port,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    input("\n[Press ENTER to return to menu or type 'exit' to quit]: ").lower().strip() == "exit" and sys.exit()

# HTTP Header Security Check
def header_check():
    clear()
    header_logo()
    url = input("\n[?] Enter URL (include http/https) to check headers: ")
    try:
        resp = requests.get(url, timeout=10, verify=False)
        headers = resp.headers
        print("\n[+] Checking security-related headers:")
        checks = ['Content-Security-Policy', 'X-Frame-Options', 'Strict-Transport-Security', 'X-Content-Type-Options']
        for header in checks:
            if header in headers:
                print(f"[+] {header}: {headers[header]}")
            else:
                print(f"[-] {header} is missing!")

        # ----- WAF Detection -----
        print("\n[+] Checking for possible WAF presence...")

        waf_detected = False
        waf_name = "Unknown"

        # Define known WAF fingerprints (headers or content)
        waf_signatures = {
            "Cloudflare": ["cloudflare", "cf-ray"],
            "Akamai": ["akamai", "X-Akamai-Edgescape"],
            "AWS WAF": ["aws", "X-Amzn-Requestid"],
            "Sucuri": ["sucuri", "X-Sucuri-ID"],
            "SafeLine": ["safeline", "safeline-waf"]
        }

        # Check headers
        for header_key, header_value in headers.items():
            for waf, patterns in waf_signatures.items():
                for pattern in patterns:
                    if pattern.lower() in header_value.lower():
                        waf_detected = True
                        waf_name = waf
                        print(f"[!] WAF detected via header: {header_key}: {header_value}")
                        break

        # Send malicious requests for behavioral detection
        payloads = [
            "/test.php?id=' OR '1'='1",
            "/<script>alert(1)</script>",
            "/../../../etc/passwd"
        ]

        for payload in payloads:
            test_url = url.rstrip('/') + payload
            test_resp = requests.get(test_url, timeout=10, verify=False)
            if test_resp.status_code in [403, 406, 501]:
                print(f"[!] WAF blocking detected on {payload} with status {test_resp.status_code}")
                waf_detected = True
            # Check response content
            for waf, patterns in waf_signatures.items():
                for pattern in patterns:
                    if pattern.lower() in test_resp.text.lower():
                        waf_detected = True
                        waf_name = waf
                        print(f"[!] WAF block page detected: {waf} (pattern: {pattern})")

        if waf_detected:
            print(f"\n🚩 Possible WAF detected: **{waf_name}**")
        else:
            print("[+] No obvious WAF detected.")

    except Exception as e:
        print(f"[!] Error: {e}")

    input("\n[Press ENTER to return to menu or type 'exit' to quit]: ").lower().strip() == "exit" and sys.exit()

# Whois + DNS
def whois_dns():
    clear()
    whois_logo()
    domain = input("\n[?] Enter domain for Whois & DNS lookup: ")
    try:
        w = whois.whois(domain)
        
        # Formatierung der Whois-Daten
        print(f"\n[+] Whois info for {domain}:")
        print(f"  Domain Name: {w.get('domain_name', 'N/A')}")
        print(f"  Registrar: {w.get('registrar', 'N/A')}")
        print(f"  Registrar URL: {', '.join(w.get('registrar_url', [])) if w.get('registrar_url') else 'N/A'}")
        print(f"  Whois Server: {w.get('whois_server', 'N/A')}")
        print(f"  Updated Date: {w.get('updated_date', 'N/A')}")
        print(f"  Creation Date: {w.get('creation_date', 'N/A')}")
        print(f"  Expiration Date: {w.get('expiration_date', 'N/A')}")
        print(f"  Name Servers: {', '.join(w.get('name_servers', [])) if w.get('name_servers') else 'N/A'}")
        print(f"  Status: {w.get('status', 'N/A')}")
        print(f"  Emails: {w.get('emails', 'N/A')}")
        print(f"  DNSSEC: {w.get('dnssec', 'N/A')}")
        print(f"  Registrant Name: {w.get('name', 'N/A')}")
        print(f"  Registrant Organization: {w.get('org', 'N/A')}")
        print(f"  Registrant Address: {w.get('address', 'N/A')}")
        print(f"  Registrant City: {w.get('city', 'N/A')}")
        print(f"  Registrant State: {w.get('state', 'N/A')}")
        print(f"  Registrant Postal Code: {w.get('registrant_postal_code', 'N/A')}")
        print(f"  Registrant Country: {w.get('country', 'N/A')}")
        
        # DNS Lookup
        print(f"\n[+] DNS Records for {domain}:")
        try:
            result = dns.resolver.resolve(domain, 'A')
            for ipval in result:
                print(f"  A Record: {ipval.to_text()}")
        except dns.resolver.NoAnswer:
            print("  No DNS A record found.")
        except dns.resolver.NXDOMAIN:
            print("  Domain does not exist.")
        except Exception as e:
            print(f"  Error retrieving DNS records: {e}")
            
    except Exception as e:
        print(f"[!] Error: {e}")

    input("\n[Press ENTER to return to menu or type 'exit' to quit]: ").lower().strip() == "exit" and sys.exit()

def dir_bruteforce():
    clear()
    dirb_logo()
    url = input("\n[?] Enter target URL (include http/https): ").rstrip('/')
    wordlist = ["admin", "login", "test", "backup", "dev", "uploads", "config", ".git", ".env", "dashboard"]
    found = False
    print(f"\n[+] Starting directory bruteforce on {url}...\n")
    
    for word in wordlist:
        target = f"{url}/{word}"
        try:
            resp = requests.get(target, timeout=8, verify=False, allow_redirects=False)
            if resp.status_code in [200, 301, 302, 403]:
                print(f"[+] Found: {target} (Status: {resp.status_code})")
                found = True
        except Exception as e:
            print(f"[!] Error on {target}: {e}")
            continue
    
    if not found:
        print("[!] No directories found with current wordlist.")

    input("\n[Press ENTER to return to menu or type 'exit' to quit]: ").lower().strip() == "exit" and sys.exit()

def ssl_info():
    clear()
    ssl_logo()
    host = input("\n[?] Enter domain to check SSL Certificate: ").strip()

    # Remove protocol if present
    if host.startswith("https://"):
        host = host.replace("https://", "")
    elif host.startswith("http://"):
        host = host.replace("http://", "")

    port = 443
    try:
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.socket(), server_hostname=host)
        conn.settimeout(5)
        conn.connect((host, port))

        cert = conn.getpeercert()
        tls_version = conn.version()

        print(f"\n[+] SSL Certificate for {host}:")
        
        # Full Issuer Parsing
        issuer = cert.get('issuer', ())
        issuer_str = ", ".join(f"{item[0]}={item[1]}" for part in issuer for item in part)
        print(f"  Issuer: {issuer_str}")

        # Full Subject Parsing
        subject = cert.get('subject', ())
        subject_str = ", ".join(f"{item[0]}={item[1]}" for part in subject for item in part)
        print(f"  Subject: {subject_str}")

        # Validity
        print(f"  Valid From: {cert['notBefore']}")
        print(f"  Valid To: {cert['notAfter']}")

        # Expiry Check (Timezone aware)
        expiry_date = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        days_left = (expiry_date - now).days
        if days_left < 30:
            print(f"  🚨 Certificate expires in {days_left} days!")
        else:
            print(f"  Valid for {days_left} more days.")

        # SANs
        san = cert.get('subjectAltName', [])
        san_list = [entry[1] for entry in san if entry[0] == 'DNS']
        print(f"  SANs: {san_list}")

        # TLS Version
        print(f"  TLS Version used: {tls_version}")

        conn.close()

    except Exception as e:
        print(f"[!] Error: {e}")

    input("\n[Press ENTER to return to menu or type 'exit' to quit]: ").lower().strip() == "exit" and sys.exit()

def open_redirect_checker():
    clear()
    open_redirect_logo()
    console.print("\n[bold cyan]Open Redirect Vulnerability Checker[/bold cyan]\n")
    url = input("[?] Enter target URL (include http/https): ").strip()
    param = input("[?] Enter URL parameter to test (e.g., redirect, url): ").strip()
    payload = "https://evil.com"

    test_url = f"{url}?{param}={payload}"
    console.print(f"\n[+] Testing: [yellow]{test_url}[/yellow]")

    try:
        response = requests.get(test_url, timeout=10, allow_redirects=False, verify=False)
        location = response.headers.get('Location', '')
        if payload in location:
            console.print(f"[bold red]🚨 Open Redirect Vulnerability Detected![/bold red] Redirects to: {location}")
        else:
            console.print("[green]No Open Redirect detected.[/green]")
    except Exception as e:
        console.print(f"[!] Error: {e}")

    input("\n[Press ENTER to return to menu or type 'exit' to quit]: ").lower().strip() == "exit" and sys.exit()

# -------------- CORS Misconfiguration Checker --------------
def cors_checker():
    clear()
    cors_logo()
    console.print("\n[bold cyan]CORS Misconfiguration Checker[/bold cyan]\n")
    url = input("[?] Enter target URL (include http/https): ").strip()

    try:
        response = requests.get(url, timeout=10, verify=False)
        acao = response.headers.get('Access-Control-Allow-Origin', 'Not Set')
        acc = response.headers.get('Access-Control-Allow-Credentials', 'Not Set')
        
        console.print(f"\n[+] Access-Control-Allow-Origin: [yellow]{acao}[/yellow]")
        console.print(f"[+] Access-Control-Allow-Credentials: [yellow]{acc}[/yellow]")

        if acao == '*' or 'null' in acao:
            console.print("[bold red]🚨 Potentially insecure ACAO policy![/bold red]")
        if acc.lower() == 'true' and acao == '*':
            console.print("[bold red]🚨 Insecure CORS configuration detected![/bold red]")
    except Exception as e:
        console.print(f"[!] Error: {e}")

    input("\n[Press ENTER to return to menu or type 'exit' to quit]: ").lower().strip() == "exit" and sys.exit()

# -------------- Technology Detection --------------
def tech_detection():
    clear()
    tech_detect_logo()
    console.print("\n[bold cyan]Technology Detection (like Wappalyzer)[/bold cyan]\n")
    url = input("[?] Enter target URL (include http/https): ").strip()

    if not builtwith:
        console.print("[!] BuiltWith library not installed. Install via: pip install builtwith")
        input("\n[Press ENTER to return to menu or type 'exit' to quit]: ").lower().strip() == "exit" and sys.exit()

    try:
        tech = builtwith(url)
        console.print(f"\n[+] Detected Technologies for {url}:")
        for key, value in tech.items():
            console.print(f"[yellow]{key}:[/yellow] {', '.join(value)}")
    except Exception as e:
        console.print(f"[!] Error: {e}")

    input("\n[Press ENTER to return to menu or type 'exit' to quit]: ").lower().strip() == "exit" and sys.exit()

def http_method_checker():
    clear()
    http_methods_logo()
    console.print("\n[bold cyan]HTTP Method Checker[/bold cyan]\n")
    url = input("[?] Enter target URL (include http/https): ").strip()
    methods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'TRACE', 'CONNECT']
    try:
        for method in methods:
            req = requests.request(method, url, timeout=5, verify=False)
            console.print(f"[+] Method {method}: Status {req.status_code}")
    except Exception as e:
        console.print(f"[!] Error: {e}")
    input("\n[Press ENTER to return to menu or type 'exit' to quit]: ").lower().strip() == "exit" and sys.exit()

def dns_zone_transfer():
    clear()
    dns_zone_logo()
    console.print("\n[bold cyan]DNS Zone Transfer Check[/bold cyan]\n")
    domain = input("[?] Enter domain: ").strip()
    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        for ns in ns_records:
            ns_server = str(ns.target)
            console.print(f"[+] Trying NS: {ns_server}")
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns_server, domain, timeout=5))
                if zone:
                    console.print(f"[bold red]🚨 Zone Transfer successful on {ns_server}![/bold red]")
                    for name, node in zone.nodes.items():
                        console.print(f"[+] {name}")
            except Exception as ex:
                console.print(f"[-] Zone transfer failed on {ns_server}: {ex}")
    except Exception as e:
        console.print(f"[!] Error: {e}")
    input("\n[Press ENTER to return to menu or type 'exit' to quit]: ").lower().strip() == "exit" and sys.exit()

def banner_grabber():
    clear()
    banner_logo()
    console.print("\n[bold cyan]Banner Grabbing & Service Fingerprinting[/bold cyan]\n")
    target = input("[?] Enter IP or domain: ").strip()
    port = int(input("[?] Enter port: "))
    try:
        sock = socket.socket()
        sock.settimeout(5)
        sock.connect((target, port))
        banner = sock.recv(1024).decode().strip()
        console.print(f"[+] Banner: {banner}")
        sock.close()
    except Exception as e:
        console.print(f"[!] Error: {e}")
    input("\n[Press ENTER to return to menu or type 'exit' to quit]: ").lower().strip() == "exit" and sys.exit()

def email_spf_dmarc_check():
    clear()
    email_logo()
    console.print("\n[bold cyan]Email Harvesting, SPF/DMARC & DKIM Check[/bold cyan]\n")
    domain = input("[?] Enter domain: ").strip()

    # MX Records
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        console.print(f"\n[+] MX Records for {domain}:")
        for mx in mx_records:
            console.print(f"  {mx.exchange} (Priority: {mx.preference})")
    except Exception:
        console.print("[!] No MX records found.")

    # SPF Record
    try:
        txt_records = dns.resolver.resolve(domain, 'TXT')
        found_spf = False
        for txt in txt_records:
            txt_str = ''.join([s.decode() for s in txt.strings])
            if 'v=spf1' in txt_str:
                found_spf = True
                console.print(f"\n[+] SPF Record Found: {txt_str}")
                if '-all' in txt_str or '~all' in txt_str:
                    console.print("[green]✔️ SPF policy ends correctly with -all or ~all[/green]")
                else:
                    console.print("[yellow]⚠️ SPF policy may be too permissive (missing -all or ~all)[/yellow]")
                break
        if not found_spf:
            console.print("\n[!] No SPF record found!")
    except Exception:
        console.print("[!] No SPF record found.")

    # DMARC Record
    try:
        dmarc_domain = f"_dmarc.{domain}"
        dmarc_records = dns.resolver.resolve(dmarc_domain, 'TXT')
        found_dmarc = False
        for dmarc in dmarc_records:
            dmarc_str = ''.join([s.decode() for s in dmarc.strings])
            if 'v=DMARC1' in dmarc_str:
                found_dmarc = True
                console.print(f"\n[+] DMARC Record Found: {dmarc_str}")
                break
        if not found_dmarc:
            console.print("\n[!] No DMARC record found!")
    except Exception:
        console.print("[!] No DMARC record found.")

    # DKIM Records (basic selectors)
    selectors = ['default', 'mail', 'google', 'dkim', 'domain', 'selector1', 'selector1', 's1', 's2', 'k1', 'smtp', 'mandrill', 'mailjet', 'sendgrid', 'postmark', 'zoho', 'mx', 'pm', 'arc']
    console.print("\n[+] Checking common DKIM selectors:")
    for selector in selectors:
        dkim_domain = f"{selector}._domainkey.{domain}"
        try:
            dkim_records = dns.resolver.resolve(dkim_domain, 'TXT')
            for dkim in dkim_records:
                dkim_str = ''.join([s.decode() for s in dkim.strings])
                console.print(f"  [green]✔️ DKIM found: {selector} → {dkim_str}[/green]")
                break
        except:
            console.print(f"  [-] No DKIM record for selector: {selector}")

    # Email harvesting attempt
    console.print("\n[+] Attempting to harvest public emails from website homepage...")
    try:
        resp = requests.get(f"http://{domain}", timeout=10, verify=False)
        emails = set(re.findall(r"[\w\.-]+@[\w\.-]+", resp.text))
        if emails:
            console.print("\n[+] Found the following emails:")
            for email in emails:
                console.print(f"  {email}")
        else:
            console.print("[!] No emails found on homepage.")
    except Exception:
        console.print("[!] Could not reach homepage (Timeout or Connection Error).")

    input("\n[Press ENTER to return to menu or type 'exit' to quit]: ").lower().strip() == "exit" and sys.exit()

def threat_intel():
    clear()
    ti_logo()
    console.print("\n[bold cyan]Threat Intelligence DNSBL Check[/bold cyan]\n")
    ip = input("[?] Enter IP to check: ").strip()
    reverse_ip = '.'.join(ip.split('.')[::-1])

    blacklists = [
        'dnsbl.sentraguard.net',
        'bl.spamcop.net',
        'dnsbl.sorbs.net',
        'b.barracudacentral.org',
        'psbl.surriel.com',
        'hostkarma.junkemailfilter.com',
        'dnsbl-1.uceprotect.net'
    ]

    for blacklist in blacklists:
        query = f"{reverse_ip}.{blacklist}"
        try:
            dns.resolver.resolve(query, 'A')
            console.print(f"[bold red]🚨 LISTED in {blacklist}![/bold red]")
        except:
            console.print(f"[green]✔️ NOT listed in {blacklist}[/green]")

    input("\n[Press ENTER to return to menu or type 'exit' to quit]: ").lower().strip() == "exit" and sys.exit()

def vuln_scanner():
    try:
        import os
        os.system('cls' if os.name == 'nt' else 'clear')
    except:
        pass
    
    vuln_scanner_logo()
    console.print("\n[bold cyan]Simple Vulnerability Scanner[/bold cyan]\n")

    target_url = input("[?] Enter Target URL (e.g. https://example.com): ").strip()

    def scan_headers(url):
        console.print("\n[bold yellow][+] Scanning HTTP Headers...[/bold yellow]\n")
        try:
            response = requests.get(url, timeout=10)
            headers = response.headers

            security_headers = [
                "Content-Security-Policy",
                "Strict-Transport-Security",
                "X-Content-Type-Options",
                "X-Frame-Options",
                "X-XSS-Protection",
                "Referrer-Policy"
            ]

            for header in security_headers:
                if header in headers:
                    console.print(f"[green][✔ ] {header}: {headers[header]}[/green]")
                else:
                    console.print(f"[bold red][!] {header} missing![/bold red]")

        except Exception as e:
            console.print(f"[bold red][ERROR] Header scan failed: {e}[/bold red]")

    def scan_directories(url):
        console.print("\n[bold yellow][+] Scanning Common Directories...[/bold yellow]\n")
        common_dirs = ['admin', 'login', 'uploads', 'backup', '.git', 'config']

        for directory in common_dirs:
            full_url = f"{url}/{directory}/"
            try:
                res = requests.get(full_url, timeout=5)
                if res.status_code == 200:
                    console.print(f"[bold red][!] Open: {full_url} (Status: {res.status_code})[/bold red]")
            except:
                pass

    def check_tls_version(domain):
        console.print("\n[bold yellow][+] Checking TLS Version...[/bold yellow]\n")
        try:
            context = ssl.create_default_context()
            conn = context.wrap_socket(
                socket.socket(socket.AF_INET),
                server_hostname=domain,
            )
            conn.settimeout(5)
            conn.connect((domain, 443))
            tls_version = conn.version()
            console.print(f"[green][✔ ] TLS Version: {tls_version}[/green]")
            conn.close()

            if tls_version in ['TLSv1', 'TLSv1.1']:
                console.print("[bold red][!] Outdated/unsecure TLS version detected![/bold red]")
        except Exception as e:
            console.print(f"[bold red][ERROR] TLS Check fehlgeschlagen: {e}[/bold red]")

    console.print(f"\n[bold blue]Target: {target_url}[/bold blue]\n{'-'*50}")
    scan_headers(target_url)
    scan_directories(target_url)

    domain = target_url.replace('https://', '').replace('http://', '').split('/')[0]
    check_tls_version(domain)

    console.print("\n[bold cyan][+] Scan completed![/bold cyan]\n")

    user_input = input("\n[Press ENTER to return to menu or type 'exit' to quit]: ").lower().strip()
    if user_input == "exit":
        sys.exit()

def csp_evaluator():
    try:
        import os
        os.system('cls' if os.name == 'nt' else 'clear')
    except:
        pass

    csp_logo()
    console.print("\n[bold cyan]Content Security Policy Evaluator[/bold cyan]\n")

    target = input("[?] Enter Target URL (e.g. https://example.com): ").strip()

    try:
        response = requests.get(target, timeout=10)
        csp = response.headers.get('Content-Security-Policy', '')

        if not csp:
            console.print("[bold red][!] No CSP policy set![/bold red]")
        else:
            console.print(f"[green][✔ ] CSP found:[/green] {csp}\n")
            if 'unsafe-inline' in csp:
                console.print("[bold red][!] Warning: unsafe-inline used![/bold red]")
            if 'unsafe-eval' in csp:
                console.print("[bold red][!] Warning: unsafe-eval used![/bold red]")
            if "*" in csp:
                console.print("[bold yellow][!] Attention: Wildcards (*) can be risky.[/bold yellow]")

    except Exception as e:
        console.print(f"[bold red][ERROR] Request failed: {e}[/bold red]")

    user_input = input("\n[Press ENTER to return to menu or type 'exit' to quit]: ").lower().strip()
    if user_input == "exit":
        sys.exit()

def clickjacking_test():
    try:
        os.system('cls' if os.name == 'nt' else 'clear')
    except:
        pass

    clickjack_logo()
    console.print("\n[bold cyan]Clickjacking Test[/bold cyan]\n")

    target = input("[?] Enter Target URL (e.g. https://example.com): ").strip()

    try:
        response = requests.get(target, timeout=10)
        xfo = response.headers.get('X-Frame-Options', None)

        if not xfo:
            console.print("[bold red][!] X-Frame-Options header is missing! Page may be vulnerable to Clickjacking![/bold red]")
            output_dir = "clickjack_poc"
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
            filename_part = target.replace("https://", "").replace("http://", "").replace("/", "_").replace(".", "_")
            file_name = f"{output_dir}/clickjack_poc_{filename_part}.html"
            with open(file_name, "w") as f:
                f.write(f"""
<!DOCTYPE html>
<html>
<head>
<title>Clickjacking PoC</title>
</head>
<body>
<h2>Clickjacking Test - {target}</h2>
<iframe src="{target}" width="800" height="600" style="opacity:0.8;"></iframe>
</body>
</html>
""")
            console.print(f"[green][✔] PoC HTML created: {file_name}[/green]")
        else:
            console.print(f"[green][✔] X-Frame-Options is set: {xfo}[/green]")

    except Exception as e:
        console.print(f"[bold red][ERROR] Request failed: {e}[/bold red]")

    user_input = input("\n[Press ENTER to return to menu or type 'exit' to quit]: ").lower().strip()
    if user_input == "exit":
        sys.exit()

def cookie_security_check():
    try:
        import os
        os.system('cls' if os.name == 'nt' else 'clear')
    except:
        pass

    cookie_logo()
    console.print("\n[bold cyan]Cookie Security Check[/bold cyan]\n")

    target = input("[?] Enter Target URL (e.g. https://example.com): ").strip()

    try:
        response = requests.get(target, timeout=10)

        cookies = response.cookies
        if not cookies:
            console.print("[yellow][!] No cookies found![/yellow]")
        else:
            for cookie in cookies:
                console.print(f"\n[green][✔ ] Cookie found:[/green] {cookie.name}")
                if not cookie.secure:
                    console.print(f"[bold red][!] Secure flag missing![/bold red]")
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    console.print(f"[bold red][!] HttpOnly flag missing![/bold red]")
                if not cookie.has_nonstandard_attr('SameSite'):
                    console.print(f"[yellow][!] SameSite attribute missing![/yellow]")
                if cookie.expires is None:
                    console.print(f"[yellow][!] No expiration time set (session cookie)![/yellow]")

    except Exception as e:
        console.print(f"[bold red][ERROR] Request failed: {e}[/bold red]")

    user_input = input("\n[Press ENTER to return to menu or type 'exit' to quit]: ").lower().strip()
    if user_input == "exit":
        sys.exit()

# Main Menu
def main_menu():
    while True:
        clear()
        show_main_logo()
        print("""
[1] Subdomain Takeover Check    [2] Portscanner
[3] HTTP Header Security Check  [4] Whois & DNS Info
[5] Dir Bruteforce              [6] Check SSL Certificate
[7] Open Redirect Checker       [8] CORS Misconfig Checker
[9] Tech Detection              [10] HTTP Method Checker 
[11] DNS Zone Transfer Check    [12] Banner Grabbing
[13] Email & SPF/DMARC Check    [14] Threat Intelligence Check  
[15] Vulnerability Scanner      [16] CSP Evaluator
[17] Clickjacking Test          [18] Cookie Security Check


[0] Exit
""")
        choice = input("[?] Choose an option: ")
        if choice == '1':
            takeover_check()
        elif choice == '2':
            portscanner()
        elif choice == '3':
            header_check()
        elif choice == '4':
            whois_dns()
        elif choice == '5':
            dir_bruteforce()
        elif choice == '6':
            ssl_info()
        elif choice == '7':
            open_redirect_checker()
        elif choice == '8':
            cors_checker()
        elif choice == '9':
            tech_detection()
        elif choice == '10':
            http_method_checker()
        elif choice == '11':
            dns_zone_transfer()
        elif choice == '12':
            banner_grabber()
        elif choice == '13':
            email_spf_dmarc_check()
        elif choice == '14':
            threat_intel()
        elif choice == '15':
            vuln_scanner()
        elif choice == '16':
            csp_evaluator()
        elif choice == '17':
            clickjacking_test()
        elif choice == '18':
            cookie_security_check()
        elif choice == '0':
            print("\n[+] Exiting. Goodbye!")
            sys.exit()
        else:
            continue

if __name__ == "__main__":
    main_menu()
