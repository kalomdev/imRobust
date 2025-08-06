<img width="1920" height="1440" alt="image" src="https://github.com/user-attachments/assets/7850c567-e2cf-4b6a-a86f-869934b5e391" />



---

# imRobust 🔎🛡️

**Network & Web Reconnaissance Tool** — Developed by **KALOM**

imRobust is a powerful, modular, and user-friendly tool designed for developers, penetration testers, and security researchers. It automates a wide range of reconnaissance techniques to gather detailed and actionable information about networks and web applications. Whether you need to map open ports, analyze SSL certificates, or enumerate web directories, imRobust provides a one-stop solution.

---

## Table of Contents

* [Features](#-features)
* [Installation](#-installation)
* [Usage Exemple](#-exemple)
* [Contributing](#-contributing)
* [License](#-license)
* [Ethic & Legal Usage](#%EF%B8%8F-ethic)

---

## 🚀 Features

### 🌐 Network Reconnaissance

* `--ping`            Ping the target host
* `--dns`             DNS lookup
* `--whois`           WHOIS information
* `--trace`           Traceroute to the target
* `--geoip`           Get geographical info about IP
* `--reverse-ip`      Find domains on the same server
* `--sniff`            Basic packet sniffing (with `--interface`)

### 🔐 SSL & Certificate Analysis

* `--ssl`             Retrieve SSL certificate info
* `--ssl-scan`       Scan for SSL/TLS vulnerabilities

### 🕵️ Web Reconnaissance

* `--url` `<target>`     Target URL for analysis
* `--headers`        Extract HTTP headers
* `--cookies`        Extract cookies
* `--links`          Extract all hyperlinks
* `--forms`         Extract HTML forms
* `--scripts`        Extract JavaScript files
* `--status`         Get HTTP status code
* `--robots`         Fetch `robots.txt`
* `--sitemap`        Fetch `sitemap.xml`
* `--fingerprint`     Fingerprint HTTP headers
* `--redirects`      Trace redirect chains
* `--find-admin`     Find admin panel URLs
* `--http-methods`   Check allowed HTTP verbs
* `--cms-detection`  Detect Content Management System

### 🪓 Brute-Forcing & Enumeration

* `--wordlist` `<file>`     Password bruteforce
* `--userlist` `<file>`     Username bruteforce
* `--subdomains`       Subdomain enumeration
* `--subdomains-wordlist` `<file>`
* `--dir-brute`        Directory bruteforce
* `--dir-wordlist` `<file>`   Wordlist for directories

### 🧠 Service Detection

* `--port` `<list>`       Port scan
* `--service-detection`   Detect services on open ports

### 💾 Output Options

* `--save` `<file>`     Save results to file
* `--format` `json|csv`   Output format

---

## 📦 Installation

```bash
git clone https://github.com/kalomdev/imRobust
cd imRobust
pip install -r requirements.txt
```

---

## 💡 Usage Exemple

```bash
# Ping target and perform DNS lookup
python imRobust.py --ping --dns example.com

# Scan specific ports on an IP with 10 threads and timeout 5s
python imRobust.py --port 80 443 8080 -T 10 -t 5 192.168.1.1

# Perform web reconnaissance on a URL and extract headers, cookies, links
python imRobust.py --url https://example.com --headers --cookies --links

# Enumerate subdomains with a wordlist and save output as JSON
python imRobust.py --subdomains --subdomains-wordlist subdomains.txt --save results.json --format json example.com

# Check SSL certificate and scan for vulnerabilities
python imRobust.py --ssl --ssl-scan example.com

# Check if port 22 is open on a remote IP
python imRobust.py --checkport 192.168.1.100:22
```

---

## 🤝 Contributing

Contributions are welcome! If you want to suggest new features, report bugs, or improve documentation, please open an issue or submit a pull request.

Please follow the [Code of Conduct](CODE_OF_CONDUCT.md) and ensure your contributions align with the project’s goals.

---

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## ⚠️Ethics & Legal Notice

imRobust is intended for **ethical security research and authorized penetration testing only**.
Unauthorized scanning, reconnaissance, or attacks on systems without permission may be illegal and unethical.

Use responsibly and always obtain explicit authorization before targeting any network or website.

---


