import argparse
import socket
import ssl
import threading
import subprocess
import json
import csv
import time
import idna
import sys
import os
import random
from datetime import datetime, timezone

try:
    import requests
    from bs4 import BeautifulSoup
    import dns.resolver
    import whois
except ImportError:
    print("[WARN] 'requests', 'beautifulsoup4', 'dnspython', and 'whois' packages are required for full functionality.")
    print("Run: pip install requests beautifulsoup4 dnspython whois\n")
    requests = None
    BeautifulSoup = None

from scapy.all import get_if_list, IP, ICMP, sr1

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

ASCII_ART = f"""
{Colors.HEADER}
       @@
       @@                                                       @@                   @@@@@
                                   @@@@@@@@                     @@                 @@@@   @@
                                   @@    @@@@                   @@               @@@@    @@              @@{Colors.ENDC}
       {Colors.OKBLUE}@@     @@   @@@   @@@       @@     @@@          @@@      @@   @@@        @@@ @@  @@      @@@@@@  @@@@@@@{Colors.ENDC}
       {Colors.OKBLUE}@@@    @@@@  @@@@   @@@     @@     @@@        @@    @@@@   @@@   @@@@     @@ @@@@@@      @          @@{Colors.ENDC}
       {Colors.OKGREEN}@@     @@@    @@@   @@@     @@  @@@        @@      @@@   @@      @@     @@@@@@ @@     @@@@@       @@{Colors.ENDC}
       {Colors.OKGREEN}@@     @@@    @@    @@@     @@    @@@@     @@       @@   @@      @@   @@@ @@  @@@         @@@@@   @@{Colors.ENDC}
       {Colors.WARNING}@@     @@@    @@    @@@     @@      @@@@   @@@     @@    @@@    @@   @@     @@@        @    @@    @@@{Colors.ENDC}
       {Colors.WARNING}@@@    @@     @     @@@@    @@@@      @@@@  @@@@@@        @@@@@      @@   @@@         @@@@@        @@@@{Colors.ENDC}
{Colors.OKCYAN}                                                                             @@@@@{Colors.ENDC}
{Colors.HEADER}New Features: --mynetwork, --checkport, --proxy, --random-ua, --ua, --dev{Colors.ENDC}
"""

def log(msg, level='INFO', verbose=False):
    if level == 'INFO':
        print(f"{Colors.OKGREEN}[INFO]{Colors.ENDC} {msg}")
    elif level == 'WARN':
        print(f"{Colors.WARNING}[WARN]{Colors.ENDC} {msg}")
    elif level == 'ERROR':
        print(f"{Colors.FAIL}[ERROR]{Colors.ENDC} {msg}", file=sys.stderr)
    elif level == 'DEBUG' and verbose:
        print(f"{Colors.OKCYAN}[DEBUG]{Colors.ENDC} {msg}")

def tcp_scan_worker(ip, ports, results, timeout):
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            con = s.connect_ex((ip, port))
            if con == 0:
                results[port] = True
            s.close()
        except Exception as e:
            log(f"Error scanning port {port}: {e}", 'DEBUG')

def banner_grab(ip, port, timeout=3):
    try:
        sock = socket.socket()
        sock.settimeout(timeout)
        sock.connect((ip, port))
        if port == 80:
            sock.sendall(b'HEAD / HTTP/1.0\r\n\r\n')
        elif port == 25:
            sock.recv(1024)
        elif port == 21:
            sock.recv(1024)
        elif port == 22:
            pass
        else:
            sock.sendall(b'\r\n')
        banner = sock.recv(1024).decode(errors='ignore').strip()
        sock.close()
        return banner
    except Exception as e:
        log(f"Error grabbing banner from port {port}: {e}", 'DEBUG')
        return ''

def ssl_check(ip, port=443, timeout=4):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert.get('issuer', []))
                subject = dict(x[0] for x in cert.get('subject', []))
                not_before = cert.get('notBefore')
                not_after = cert.get('notAfter')
                return {
                    'issuer': issuer.get('organizationName', ''),
                    'subject': subject.get('commonName', ''),
                    'valid_from': not_before,
                    'valid_to': not_after
                }
    except Exception as e:
        log(f"Error checking SSL certificate: {e}", 'DEBUG')
        return {}

def ping(ip, count=4):
    param = '-n' if sys.platform.lower() == 'win32' else '-c'
    command = ['ping', param, str(count), ip]
    try:
        output = subprocess.check_output(command, stderr=subprocess.DEVNULL).decode()
        times = []
        for line in output.split('\n'):
            if 'time=' in line.lower():
                m = line.lower().split('time=')[1]
                t = ''
                for c in m:
                    if c.isdigit() or c == '.':
                        t += c
                    else:
                        break
                if t:
                    times.append(float(t))
        avg = sum(times) / len(times) if times else None
        return avg
    except Exception as e:
        log(f"Error pinging target: {e}", 'DEBUG')
        return None

def dns_lookup(domain):
    try:
        records = {}
        for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT']:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                records[rtype] = [r.to_text() for r in answers]
            except Exception:
                records[rtype] = []
        return records
    except ImportError:
        log('dns python module missing. Install with pip install dnspython', 'ERROR')
        return {}

def traceroute(host, max_hops=30, timeout=2):
    results = []
    port = 33434
    for ttl in range(1, max_hops + 1):
        try:
            recv = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            recv.settimeout(timeout)
            recv.bind(("", port))
            send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            send.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
            send.sendto(b"", (host, port))
            start = time.time()
            addr = None
            try:
                data, addr = recv.recvfrom(512)
                elapsed = (time.time() - start) * 1000
                results.append({'ttl': ttl, 'ip': addr[0], 'time_ms': elapsed})
                if addr[0] == host:
                    break
            except socket.timeout:
                results.append({'ttl': ttl, 'ip': '*', 'time_ms': None})
            finally:
                recv.close()
                send.close()
        except Exception as e:
            log(f"Error during traceroute: {e}", 'DEBUG')
            break
    return results

def whois_lookup(domain):
    try:
        return whois.whois(domain)
    except Exception as e:
        log(f'Whois lookup failed: {e}', 'ERROR')
        return {}

def service_detection(ip, port, timeout=3):
    try:
        sock = socket.socket()
        sock.settimeout(timeout)
        sock.connect((ip, port))
        banner = sock.recv(1024).decode(errors='ignore').strip()
        sock.close()
        return banner
    except Exception as e:
        log(f"Error detecting service on port {port}: {e}", 'DEBUG')
        return ''

def geoip_lookup(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        if response.status_code == 200:
            data = response.json()
            if data['status'] == 'success':
                return {
                    'country': data.get('country'),
                    'city': data.get('city'),
                    'latitude': data.get('lat'),
                    'longitude': data.get('lon'),
                    'isp': data.get('isp'),
                    'organization': data.get('org'),
                    'as_number': data.get('as')
                }
            else:
                return {}
        else:
            return {}
    except Exception as e:
        log(f'GeoIP lookup failed: {e}', 'ERROR')
        return {}

def reverse_ip_lookup(ip):
    try:
        url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
        resp = requests.get(url)
        if resp.status_code == 200:
            return resp.text.split('\n')
        else:
            return []
    except Exception as e:
        log(f'Reverse IP lookup failed: {e}', 'ERROR')
        return []

def http_methods_check(url):
    methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS']
    allowed_methods = []
    try:
        for method in methods:
            resp = requests.request(method, url, timeout=5)
            if resp.status_code < 400:
                allowed_methods.append(method)
    except Exception as e:
        log(f'HTTP methods check failed: {e}', 'ERROR')
    return allowed_methods

def cms_detection(url):
    cms_signatures = {
        'WordPress': ['wp-content', 'wp-includes'],
        'Joomla': ['/media/system/js'],
        'Drupal': ['/misc/drupal.js']
    }
    try:
        resp = requests.get(url, timeout=5)
        for cms, signatures in cms_signatures.items():
            for signature in signatures:
                if signature in resp.text:
                    return cms
    except Exception as e:
        log(f'CMS detection failed: {e}', 'ERROR')
    return 'Unknown'

def ssl_vulnerability_scan(ip, port=443, timeout=5):
    import ssl, socket, idna
    from datetime import datetime, timezone
    vulnerabilities = []
    supported_protocols = []
    weak_ciphers_found = []
    no_pfs_ciphers_found = []
    cert_info = {}
    renegotiation_secure = True
    protocols = {
        "TLSv1_2": ssl.TLSVersion.TLSv1_2,
        "TLSv1_3": ssl.TLSVersion.TLSv1_3,
    }
    weak_ciphers_indicators = ["RC4", "DES", "3DES", "NULL", "EXPORT", "MD5", "PSK", "SRP", "DSS"]
    pfs_indicators = ["DHE", "ECDHE"]

    def parse_cert_date(datestr):
        from datetime import datetime
        for fmt in ('%b %d %H:%M:%S %Y %Z', '%Y%m%d%H%M%SZ'):
            try:
                return datetime.strptime(datestr, fmt).replace(tzinfo=timezone.utc)
            except Exception:
                continue
        return None

    def try_connect(proto_name, tls_version):
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.minimum_version = tls_version
            context.maximum_version = tls_version
            context.set_ciphers("ALL")
            hostname = ip
            try:
                hostname = idna.encode(ip).decode()
            except Exception:
                pass
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    proto = ssock.version()
                    cipher = ssock.cipher()
                    cert = ssock.getpeercert()
                    reneg = ssock.get_channel_binding("tls-unique")
                    return proto, cipher, cert, reneg
        except Exception:
            return None

    for name, tls_version in protocols.items():
        res = try_connect(name, tls_version)
        if res:
            supported_protocols.append(name)
            proto_ver, cipher, cert, reneg = res
            cipher_name = cipher[0]
            if any(wc in cipher_name for wc in weak_ciphers_indicators):
                weak_ciphers_found.append(f"{name}: {cipher_name}")
            if name != "TLSv1_3" and not any(pfs in cipher_name for pfs in pfs_indicators):
                no_pfs_ciphers_found.append(f"{name}: {cipher_name}")
            if not cert_info:
                cert_info['subject'] = dict(x[0] for x in cert.get('subject', []))
                cert_info['issuer'] = dict(x[0] for x in cert.get('issuer', []))
                cert_info['notBefore'] = cert.get('notBefore')
                cert_info['notAfter'] = cert.get('notAfter')
                cert_info['subjectAltName'] = cert.get('subjectAltName', [])
            if reneg is None:
                renegotiation_secure = False

    if weak_ciphers_found:
        vulnerabilities.append("Weak cipher suites detected: " + ", ".join(weak_ciphers_found))
    if no_pfs_ciphers_found:
        vulnerabilities.append("Cipher suites without Forward Secrecy detected: " + ", ".join(no_pfs_ciphers_found))
    if not renegotiation_secure:
        vulnerabilities.append("Insecure TLS renegotiation supported (CVE-2009-3555)")
    if cert_info:
        not_before = parse_cert_date(cert_info.get('notBefore', ''))
        not_after = parse_cert_date(cert_info.get('notAfter', ''))
        now = datetime.now(timezone.utc)
        if not_before is None or not_after is None:
            vulnerabilities.append("Failed to parse certificate validity")
        else:
            if now < not_before:
                vulnerabilities.append("Certificate not yet valid")
            if now > not_after:
                vulnerabilities.append("Certificate expired")
            if not cert_info.get('subjectAltName'):
                vulnerabilities.append("Certificate missing Subject Alternative Name (SAN)")
    if not supported_protocols:
        vulnerabilities.append("No supported TLS/SSL protocols detected or connection failed")
    return vulnerabilities

def network_sniffing(interface, count=10):
    try:
        from scapy.all import sniff, Ether, IP, TCP, UDP
        packets = sniff(iface=interface, count=count)
        results = []
        for packet in packets:
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                proto = packet[IP].proto
                results.append({'src_ip': src_ip, 'dst_ip': dst_ip, 'proto': proto})
        return results
    except Exception as e:
        log(f'Network sniffing failed: {e}', 'ERROR')
        return []

def subdomain_enumeration(domain, wordlist):
    subdomains = []
    try:
        with open(wordlist, 'r') as file:
            for line in file:
                subdomain = line.strip()
                full_domain = f"{subdomain}.{domain}"
                try:
                    answers = dns.resolver.resolve(full_domain, 'A')
                    for rdata in answers:
                        subdomains.append((full_domain, rdata.to_text()))
                except Exception as e:
                    log(f"Error resolving subdomain {full_domain}: {e}", 'DEBUG')
    except Exception as e:
        log(f'Subdomain enumeration failed: {e}', 'ERROR')
    return subdomains

def directory_brute_force(url, wordlist):
    directories = []
    try:
        with open(wordlist, 'r') as file:
            for line in file:
                directory = line.strip()
                full_url = f"{url}/{directory}"
                try:
                    resp = requests.get(full_url, timeout=5)
                    if resp.status_code == 200:
                        directories.append(full_url)
                except Exception as e:
                    log(f"Error brute-forcing directory {full_url}: {e}", 'DEBUG')
    except Exception as e:
        log(f'Directory brute-forcing failed: {e}', 'ERROR')
    return directories

def find_admin_panel(domain):
    admin_urls = [
        f"http://admin.{domain}",
        f"https://admin.{domain}",
        f"http://{domain}/admin",
        f"https://{domain}/admin",
        f"http://{domain}/admin.php",
        f"https://{domain}/admin.php",
        f"http://{domain}/admin/login",
        f"https://{domain}/admin/login",
        f"http://{domain}/wp-admin",
        f"https://{domain}/wp-admin",
        f"http://{domain}/administrator",
        f"https://{domain}/administrator"
    ]
    found_urls = []
    for url in admin_urls:
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200:
                found_urls.append(url)
        except Exception as e:
            log(f"Error checking admin panel URL {url}: {e}", 'DEBUG')
    return found_urls

def brute_force_login(url, userlist, wordlist):
    found_credentials = []
    try:
        with open(userlist, 'r') as ufile, open(wordlist, 'r') as wfile:
            users = ufile.read().splitlines()
            passwords = wfile.read().splitlines()
            for user in users:
                for password in passwords:
                    try:
                        resp = requests.post(url, data={'username': user, 'password': password}, timeout=5)
                        if resp.status_code == 200 and "Invalid" not in resp.text:
                            found_credentials.append((user, password))
                    except Exception as e:
                        log(f"Error brute-forcing login with user {user} and password {password}: {e}", 'DEBUG')
    except Exception as e:
        log(f'Brute-force login failed: {e}', 'ERROR')
    return found_credentials

def save_results(data, filename, fmt='json'):
    try:
        if fmt == 'json':
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2)
        elif fmt == 'csv':
            with open(filename, 'w', newline='') as f:
                if isinstance(data, dict):
                    writer = csv.writer(f)
                    for k, v in data.items():
                        writer.writerow([k, v])
                elif isinstance(data, list):
                    if data and isinstance(data[0], dict):
                        keys = data[0].keys()
                        writer = csv.DictWriter(f, keys)
                        writer.writeheader()
                        writer.writerows(data)
                    else:
                        writer = csv.writer(f)
                        writer.writerows(data)
    except Exception as e:
        log(f'Error saving results: {e}', 'ERROR')

def fetch_url(url, timeout=5):
    if not requests:
        log("Requests module not available.", "ERROR")
        return None
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True)
        return resp
    except Exception as e:
        log(f"Failed to fetch URL: {e}", "ERROR")
        return None

def extract_headers(resp):
    return dict(resp.headers) if resp else {}

def extract_cookies(resp):
    return resp.cookies.get_dict() if resp else {}

def extract_links(resp):
    if not resp or not BeautifulSoup:
        return []
    soup = BeautifulSoup(resp.text, 'html.parser')
    links = set()
    for a in soup.find_all('a', href=True):
        links.add(a['href'])
    return list(links)

def extract_forms(resp):
    if not resp or not BeautifulSoup:
        return []
    soup = BeautifulSoup(resp.text, 'html.parser')
    forms = []
    for form in soup.find_all('form'):
        inputs = []
        for input_tag in form.find_all(['input', 'select', 'textarea']):
            input_info = {
                'name': input_tag.get('name'),
                'type': input_tag.get('type'),
                'value': input_tag.get('value')
            }
            inputs.append(input_info)
        forms.append({
            'action': form.get('action'),
            'method': form.get('method', 'get').lower(),
            'inputs': inputs
        })
    return forms

def extract_scripts(resp):
    if not resp or not BeautifulSoup:
        return []
    soup = BeautifulSoup(resp.text, 'html.parser')
    scripts = []
    for script in soup.find_all('script', src=True):
        scripts.append(script['src'])
    return scripts

def extract_status(resp):
    if not resp:
        return None
    return resp.status_code

def extract_robots(domain):
    if not requests:
        return ''
    try:
        url = f"https://{domain}/robots.txt"
        resp = requests.get(url, timeout=3)
        if resp.status_code == 200:
            return resp.text
        else:
            return ''
    except Exception as e:
        log(f"Error fetching robots.txt: {e}", 'DEBUG')
        return ''

def extract_sitemap(domain):
    if not requests:
        return ''
    try:
        url = f"https://{domain}/sitemap.xml"
        resp = requests.get(url, timeout=3)
        if resp.status_code == 200:
            return resp.text
        else:
            return ''
    except Exception as e:
        log(f"Error fetching sitemap.xml: {e}", 'DEBUG')
        return ''

def extract_redirects(resp):
    if not resp:
        return []
    return [str(r.url) for r in resp.history] + [resp.url]

def fingerprint(resp):
    if not resp:
        return {}
    headers = resp.headers
    fp = {}
    server = headers.get('Server')
    powered_by = headers.get('X-Powered-By')
    fp['server'] = server
    fp['x-powered-by'] = powered_by
    return fp

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception as e:
        log(f"Error getting local IP: {e}", 'DEBUG')
        return None

def get_public_ip():
    try:
        resp = requests.get('https://api.ipify.org?format=json', timeout=5)
        if resp.status_code == 200:
            return resp.json().get('ip')
    except Exception as e:
        log(f"Error getting public IP: {e}", 'DEBUG')
        return None

def get_ipv6():
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.connect(("2606:4700:4700::1111", 80))
        ipv6 = s.getsockname()[0]
        s.close()
        return ipv6
    except Exception as e:
        log(f"Error getting IPv6: {e}", 'DEBUG')
        return None

def get_isp(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        if response.status_code == 200:
            data = response.json()
            return data.get('isp')
    except Exception as e:
        log(f'ISP lookup failed: {e}', 'ERROR')
        return None

def check_port(ip, port, timeout=2):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        con = s.connect_ex((ip, port))
        s.close()
        return con == 0
    except Exception as e:
        log(f"Error checking port {port}: {e}", 'DEBUG')
        return False

def use_proxy(proxy):
    proxies = {
        'http': proxy,
        'https': proxy,
    }
    return proxies

def get_random_user_agent(file_path='extra/ua.txt'):
    try:
        with open(file_path, 'r') as file:
            user_agents = file.read().splitlines()
            return random.choice(user_agents)
    except Exception as e:
        log(f"Error reading user agents file: {e}", 'DEBUG')
        return None

def list_interfaces():
    try:
        interfaces = get_if_list()
        return interfaces
    except Exception as e:
        log(f"Error listing interfaces: {e}", 'DEBUG')
        return []

def parse_args():
    parser = argparse.ArgumentParser(description="imRobust network and web reconnaissance tool")
    target_group = parser.add_argument_group('Target options')
    target_group.add_argument('target', nargs='?', help="Target IP or domain")
    target_group.add_argument('--port', '-p', type=int, nargs='+', default=[80, 443], help="Ports to scan")
    target_group.add_argument('--timeout', '-t', type=int, default=2, help="Timeout in seconds")
    target_group.add_argument('--threads', '-T', type=int, default=10, help="Number of threads for scanning")

    network_group = parser.add_argument_group('Network reconnaissance')
    network_group.add_argument('--ping', action='store_true', help="Ping target")
    network_group.add_argument('--dns', action='store_true', help="DNS lookup")
    network_group.add_argument('--whois', action='store_true', help="Whois lookup")
    network_group.add_argument('--trace', action='store_true', help="Traceroute")
    network_group.add_argument('--geoip', action='store_true', help="Get geographical information about an IP address")
    network_group.add_argument('--reverse-ip', action='store_true', help="Find domains hosted on the same server")
    network_group.add_argument('--sniff', action='store_true', help="Basic network sniffing")
    network_group.add_argument('--interface', type=str, default='eth0', help="Network interface for sniffing")
    network_group.add_argument('--mynetwork', '-mn', action='store_true', help="Display local and public network information")
    network_group.add_argument('--checkport', type=str, help="Check if a specific port on an IP is open (format: ip:port)")
    network_group.add_argument('--interfaces', action='store_true', help="List available network interfaces")

    ssl_group = parser.add_argument_group('SSL and certificate info')
    ssl_group.add_argument('--ssl', action='store_true', help="SSL cert info")
    ssl_group.add_argument('--ssl-scan', action='store_true', help="Scan for SSL/TLS vulnerabilities")

    web_group = parser.add_argument_group('Web reconnaissance')
    web_group.add_argument('--url', type=str, help="Analyse HTTP URL (ex: https://example.com)")
    web_group.add_argument('--headers', action='store_true', help="Extract HTTP headers")
    web_group.add_argument('--cookies', action='store_true', help="Extract cookies")
    web_group.add_argument('--links', action='store_true', help="Extract links")
    web_group.add_argument('--forms', action='store_true', help="Extract forms")
    web_group.add_argument('--scripts', action='store_true', help="Extract scripts")
    web_group.add_argument('--status', action='store_true', help="HTTP status code")
    web_group.add_argument('--robots', action='store_true', help="Fetch robots.txt")
    web_group.add_argument('--sitemap', action='store_true', help="Fetch sitemap.xml")
    web_group.add_argument('--fingerprint', action='store_true', help="Fingerprint headers")
    web_group.add_argument('--redirects', action='store_true', help="Show HTTP redirects chain")
    web_group.add_argument('--find-admin', action='store_true', help="Find admin panel URLs")
    web_group.add_argument('--http-methods', action='store_true', help="Check which HTTP methods are allowed")
    web_group.add_argument('--cms-detection', action='store_true', help="Detect the CMS used by a website")

    brute_group = parser.add_argument_group('Brute-forcing')
    brute_group.add_argument('--wordlist', type=str, default='extra/wordlist.txt', help="Wordlist for brute-forcing passwords")
    brute_group.add_argument('--userlist', type=str, default='extra/userlist.txt', help="Userlist for brute-forcing usernames")
    brute_group.add_argument('--subdomains', action='store_true', help="Enumerate subdomains")
    brute_group.add_argument('--subdomains-wordlist', type=str, default='extra/subdomains.txt', help="Wordlist for subdomain enumeration")
    brute_group.add_argument('--dir-brute', action='store_true', help="Brute-force directories")
    brute_group.add_argument('--dir-wordlist', type=str, default='directories.txt', help="Wordlist for directory brute-forcing")

    service_group = parser.add_argument_group('Service detection')
    service_group.add_argument('--service-detection', action='store_true', help="Detect services running on open ports")

    output_group = parser.add_argument_group('Output options')
    output_group.add_argument('--save', type=str, help="Save results (file)")
    output_group.add_argument('--format', choices=['json', 'csv'], default='json', help="Format for saving results")
    output_group.add_argument('--proxy', type=str, help="Use a proxy for each request")
    output_group.add_argument('--random-ua', action='store_true', help="Use a random user agent from a file")
    output_group.add_argument('--ua', type=str, help="Use a specific user agent")
    output_group.add_argument('--dev', action='store_true', help="Display tool information")

    return parser.parse_args()

def main():
    print(ASCII_ART)
    args = parse_args()
    results = {}
    print(f"{Colors.HEADER}{Colors.BOLD}imRobust Reconnaissance Tool{Colors.ENDC}")

    if args.dev:
        print(f"""
----------------------------------------------------
TOOL : imRobust
DEV : Kalom
GITHUB : github.com/kalomdev
VERSION : 4.02
DATE : 2025-08-04
LICENSE : MIT
LANG : Python 3.x
DESC : Advanced Network & Web Reconnaissance Tool
----------------------------------------------------
THIS TOOL IS DEVELOPED FOR LEGAL SECURITY RESEARCH ONLY.
ANY UNAUTHORIZED USE IS STRICTLY PROHIBITED.
IT WAS CREATED FOR AUTHORITIES, CYBERSECURITY RESEARCHERS, AND THOSE WHO WANT TO GET INTO PENTEST, NETWORK ANALYSIS, AND MUCH MORE...
----------------------------------------------------
""")
        return

    if args.mynetwork:
        print(f"{Colors.UNDERLINE}Network Information:{Colors.ENDC}")
        local_ip = get_local_ip()
        public_ip = get_public_ip()
        ipv6 = get_ipv6()
        isp = get_isp(public_ip) if public_ip else None
        print(f"{Colors.OKGREEN}Local IP: {local_ip}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}Public IP: {public_ip}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}IPv6: {ipv6}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}ISP: {isp}{Colors.ENDC}")
        if local_ip:
            open_ports = []
            for port in args.port:
                if check_port(local_ip, port):
                    open_ports.append(port)
            print(f"{Colors.OKGREEN}Open Ports: {', '.join(map(str, open_ports))}{Colors.ENDC}\n")
        return

    if args.interfaces:
        interfaces = list_interfaces()
        print(f"{Colors.UNDERLINE}Available Network Interfaces:{Colors.ENDC}")
        for interface in interfaces:
            print(f"{Colors.OKGREEN}{interface}{Colors.ENDC}")
        return

    if args.checkport:
        try:
            ip, port = args.checkport.split(':')
            port = int(port)
            if check_port(ip, port):
                print(f"{Colors.OKGREEN}Port {port} is OPEN.{Colors.ENDC}")
            else:
                print(f"{Colors.FAIL}Port {port} is CLOSED.{Colors.ENDC}")
        except ValueError:
            print(f"{Colors.FAIL}Invalid format for --checkport. Use ip:port.{Colors.ENDC}")
        return

    if not args.target:
        print(f"{Colors.FAIL}Error: Target is required unless using --dev, --mynetwork, --interfaces, or --checkport.{Colors.ENDC}")
        return

    print(f"Target: {Colors.OKBLUE}{args.target}{Colors.ENDC}\n")

    if args.proxy:
        proxies = use_proxy(args.proxy)
        requests.proxies.update(proxies)

    if args.random_ua:
        user_agent = get_random_user_agent()
        if user_agent:
            headers = {'User-Agent': user_agent}
            requests.headers.update(headers)

    if args.ua:
        headers = {'User-Agent': args.ua}
        requests.headers.update(headers)

    if args.ping:
        print(f"{Colors.UNDERLINE}Ping Test:{Colors.ENDC}")
        avg_time = ping(args.target)
        if avg_time:
            print(f"{Colors.OKGREEN}Average ping time: {avg_time:.2f} ms{Colors.ENDC}\n")
        else:
            print(f"{Colors.FAIL}Ping failed or timed out{Colors.ENDC}\n")

    if args.dns:
        print(f"{Colors.UNDERLINE}DNS Lookup:{Colors.ENDC}")
        dns_records = dns_lookup(args.target)
        for rtype, values in dns_records.items():
            print(f"{Colors.OKCYAN}{rtype}: {Colors.ENDC}{', '.join(values) if values else 'None'}")
        print()
        results['dns'] = dns_records

    if args.whois:
        print(f"{Colors.UNDERLINE}Whois Lookup:{Colors.ENDC}")
        whois_data = whois_lookup(args.target)
        if whois_data:
            print(json.dumps(whois_data, indent=2, default=str))
            results['whois'] = whois_data
        else:
            print(f"{Colors.FAIL}No whois data found or error.{Colors.ENDC}\n")

    if args.trace:
        print(f"{Colors.UNDERLINE}Traceroute:{Colors.ENDC}")
        trace = traceroute(args.target)
        for hop in trace:
            if hop['ip'] != '*':
                print(f"{Colors.OKGREEN}TTL {hop['ttl']}: {hop['ip']} ({hop['time_ms']:.2f} ms){Colors.ENDC}")
            else:
                print(f"{Colors.FAIL}TTL {hop['ttl']}: *{Colors.ENDC}")
        print()
        results['traceroute'] = trace

    if args.port:
        print(f"{Colors.UNDERLINE}Port Scan:{Colors.ENDC}")
        scan_results = {}
        ports = args.port
        threads = []
        ports_chunks = [ports[i::args.threads] for i in range(args.threads)]
        for i in range(args.threads):
            t = threading.Thread(target=tcp_scan_worker, args=(args.target, ports_chunks[i], scan_results, args.timeout))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()
        open_ports = sorted([p for p in scan_results if scan_results[p]])
        if open_ports:
            print(f"{Colors.OKGREEN}Open ports: {Colors.ENDC}{', '.join(map(str, open_ports))}\n")
            results['open_ports'] = open_ports
        else:
            print(f"{Colors.FAIL}No open ports found.{Colors.ENDC}\n")

        if args.service_detection:
            print(f"{Colors.UNDERLINE}Service Detection:{Colors.ENDC}")
            services = {}
            for p in open_ports:
                service = service_detection(args.target, p)
                services[p] = service
                print(f"{Colors.OKBLUE}Port {p}: {Colors.ENDC}{service}")
            print()
            results['services'] = services

    if args.ssl:
        print(f"{Colors.UNDERLINE}SSL Certificate Info:{Colors.ENDC}")
        cert_info = ssl_check(args.target)
        if cert_info:
            for k, v in cert_info.items():
                print(f"{Colors.OKCYAN}{k}: {Colors.ENDC}{v}")
            print()
            results['ssl'] = cert_info
        else:
            print(f"{Colors.FAIL}No SSL certificate info available or connection failed.{Colors.ENDC}\n")

    if args.ssl_scan:
        print(f"{Colors.UNDERLINE}SSL/TLS Vulnerability Scan:{Colors.ENDC}")
        vulnerabilities = ssl_vulnerability_scan(args.target)
        if vulnerabilities:
            for vuln in vulnerabilities:
                print(f"{Colors.FAIL}{vuln}{Colors.ENDC}")
            results['ssl_vulnerabilities'] = vulnerabilities
        else:
            print(f"{Colors.OKGREEN}No SSL/TLS vulnerabilities found.{Colors.ENDC}\n")

    if args.geoip:
        print(f"{Colors.UNDERLINE}GeoIP Lookup:{Colors.ENDC}")
        geo_info = geoip_lookup(args.target)
        if geo_info:
            for k, v in geo_info.items():
                print(f"{Colors.OKCYAN}{k}: {Colors.ENDC}{v}")
            print()
            results['geoip'] = geo_info
        else:
            print(f"{Colors.FAIL}No GeoIP information found.{Colors.ENDC}\n")

    if args.reverse_ip:
        print(f"{Colors.UNDERLINE}Reverse IP Lookup:{Colors.ENDC}")
        domains = reverse_ip_lookup(args.target)
        if domains:
            for domain in domains:
                print(f"{Colors.OKGREEN}{domain}{Colors.ENDC}")
            results['reverse_ip'] = domains
        else:
            print(f"{Colors.FAIL}No domains found.{Colors.ENDC}\n")

    if args.subdomains:
        print(f"{Colors.UNDERLINE}Subdomain Enumeration:{Colors.ENDC}")
        subdomains = subdomain_enumeration(args.target, args.subdomains_wordlist)
        if subdomains:
            for subdomain, ip in subdomains:
                print(f"{Colors.OKGREEN}{subdomain}: {ip}{Colors.ENDC}")
            results['subdomains'] = subdomains
        else:
            print(f"{Colors.FAIL}No subdomains found.{Colors.ENDC}\n")

    if args.dir_brute and args.url:
        print(f"{Colors.UNDERLINE}Directory Brute-Forcing:{Colors.ENDC}")
        directories = directory_brute_force(args.url, args.dir_wordlist)
        if directories:
            for directory in directories:
                print(f"{Colors.OKGREEN}{directory}{Colors.ENDC}")
            results['directories'] = directories
        else:
            print(f"{Colors.FAIL}No directories found.{Colors.ENDC}\n")

    if args.find_admin:
        print(f"{Colors.UNDERLINE}Finding Admin Panels:{Colors.ENDC}")
        admin_urls = find_admin_panel(args.target)
        if admin_urls:
            for url in admin_urls:
                print(f"{Colors.OKGREEN}Found admin panel: {url}{Colors.ENDC}")
            results['admin_urls'] = admin_urls
        else:
            print(f"{Colors.FAIL}No admin panels found.{Colors.ENDC}\n")

    if args.url:
        print(f"{Colors.UNDERLINE}HTTP URL Analysis: {args.url}{Colors.ENDC}")
        resp = fetch_url(args.url)
        if not resp:
            print(f"{Colors.FAIL}Failed to fetch URL or Requests not installed.{Colors.ENDC}\n")
        else:
            if args.status:
                print(f"{Colors.OKGREEN}Status code: {resp.status_code}{Colors.ENDC}")
                results['status'] = resp.status_code
            if args.headers:
                headers = extract_headers(resp)
                print(f"{Colors.OKBLUE}Headers:{Colors.ENDC}")
                for k, v in headers.items():
                    print(f"  {Colors.OKCYAN}{k}: {Colors.ENDC}{v}")
                results['headers'] = headers
            if args.cookies:
                cookies = extract_cookies(resp)
                print(f"{Colors.OKBLUE}Cookies: {Colors.ENDC}{cookies}")
                results['cookies'] = cookies
            if args.links:
                links = extract_links(resp)
                print(f"{Colors.OKBLUE}Links found ({len(links)}):{Colors.ENDC}")
                for link in links[:20]:
                    print(f"  {link}")
                if len(links) > 20:
                    print("  ...")
                results['links'] = links
            if args.forms:
                forms = extract_forms(resp)
                print(f"{Colors.OKBLUE}Forms found ({len(forms)}):{Colors.ENDC}")
                for f in forms:
                    print(f"  {Colors.OKCYAN}Action: {f['action']}, Method: {f['method']}, Inputs: {len(f['inputs'])}{Colors.ENDC}")
                results['forms'] = forms
            if args.scripts:
                scripts = extract_scripts(resp)
                print(f"{Colors.OKBLUE}Scripts found ({len(scripts)}):{Colors.ENDC}")
                for s in scripts[:20]:
                    print(f"  {s}")
                results['scripts'] = scripts
            if args.robots:
                domain = args.url.split('/')[2]
                robots_txt = extract_robots(domain)
                print(f"{Colors.OKBLUE}robots.txt:{Colors.ENDC}\n{robots_txt}\n")
                results['robots'] = robots_txt
            if args.sitemap:
                domain = args.url.split('/')[2]
                sitemap = extract_sitemap(domain)
                print(f"{Colors.OKBLUE}sitemap.xml:{Colors.ENDC}\n{sitemap}\n")
                results['sitemap'] = sitemap
            if args.fingerprint:
                fp = fingerprint(resp)
                print(f"{Colors.OKBLUE}Fingerprint headers:{Colors.ENDC}")
                for k, v in fp.items():
                    print(f"  {Colors.OKCYAN}{k}: {Colors.ENDC}{v}")
                results['fingerprint'] = fp
            if args.redirects:
                redirects = extract_redirects(resp)
                print(f"{Colors.OKBLUE}Redirect chain:{Colors.ENDC}")
                for r in redirects:
                    print(f"  {r}")
                results['redirects'] = redirects
            if args.http_methods:
                methods = http_methods_check(args.url)
                print(f"{Colors.OKBLUE}Allowed HTTP methods: {Colors.ENDC}{', '.join(methods)}")
                results['http_methods'] = methods
            if args.cms_detection:
                cms = cms_detection(args.url)
                print(f"{Colors.OKBLUE}CMS: {Colors.ENDC}{cms}")
                results['cms'] = cms

    if args.sniff:
        print(f"{Colors.UNDERLINE}Network Sniffing:{Colors.ENDC}")
        packets = network_sniffing(args.interface)
        if packets:
            for packet in packets:
                print(f"{Colors.OKGREEN}Source IP: {packet['src_ip']}, Destination IP: {packet['dst_ip']}, Protocol: {packet['proto']}{Colors.ENDC}")
            results['packets'] = packets
        else:
            print(f"{Colors.FAIL}No packets captured.{Colors.ENDC}\n")

    if args.save:
        save_results(results, args.save, args.format)
        print(f"{Colors.OKGREEN}Results saved to {args.save}{Colors.ENDC}")

if __name__ == "__main__":
    main()
