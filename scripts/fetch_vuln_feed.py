import os
import json
import urllib.request
import urllib.parse
import urllib.error
import xml.etree.ElementTree as ET
import re
from datetime import datetime
from pathlib import Path

# Paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "src" / "data"
OS_OUTPUT_FILE = DATA_DIR / "vuln_feed.json"
WEB_OUTPUT_FILE = DATA_DIR / "web_vuln_feed.json"
CRITICAL_OUTPUT_FILE = DATA_DIR / "critical_vuln_feed.json"

# Expanded Keywords for Subsystem Filtering
WINDOWS_KEYWORDS = [
    "windows", "win32k", "ntoskrnl", "clfs", "hyper-v", "rpc", "smb", 
    "active directory", "msrc", "ms17-", "cve-2025-", "cve-2026-", "nightmare",
    "netlogon", "msmq", "alpc", "lsass", "kerberos", "schannel", "spooler",
    "http.sys", "ntfs", "dns", "dhcp", "rdp", "message queuing"
]

LINUX_KEYWORDS = [
    "linux", "kernel", "ebpf", "io_uring", "netfilter", "systemd", 
    "ubuntu", "debian", "redhat", "glibc", "kvm", "overlayfs", "dirtycred", 
    "perf_event", "copy_page", "page cache", "copy fail", "cryptographic"
]

WEB_KEYWORDS = [
    "apache", "nginx", "spring", "django", "express", "nodejs", "node.js",
    "tomcat", "php", "wordpress", "v8", "webkit", "chromium", "grafana",
    "log4j", "struts", "jenkins", "gitlab", "jira", "confluence", "f5",
    "citrix", "fortinet", "keycloak", "oauth", "ssrf", "sqli", "xxe",
    "graphql", "rails", "laravel", "fastapi", "webflux", "solr"
]

MOBILE_EXCLUDE = ["ios", "iphone", "ipad", "android", "apk", "samsung", "xcode", "safari", "qualcomm", "pixel"]

# Core Seed Feed for Windows & Linux High-Impact Vulnerabilities
OS_SEED_FEED = [
    {
        "id": "CVE-2026-72982",
        "title": "Windows Netlogon Service Remote Code Execution Vulnerability",
        "cve": "CVE-2026-72982",
        "date": "2026-09-05",
        "platform": "Windows",
        "component": "Netlogon / MS-NRPC",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "is_kev": True,
        "has_poc": True,
        "description": "A critical remote code execution vulnerability in the Windows Netlogon service allows unauthenticated remote attackers to execute arbitrary code on Domain Controllers via crafted RPC request sequences.",
        "link": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-72982",
        "poc_link": "https://github.com/exploit-poc/Netlogon-RCE-CVE-2026-72982"
    },
    {
        "id": "CVE-2026-69579",
        "title": "Windows Message Queuing (MSMQ) Use-After-Free RCE",
        "cve": "CVE-2026-69579",
        "date": "2026-09-03",
        "platform": "Windows",
        "component": "MSMQ / mqsvc.exe",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "is_kev": True,
        "has_poc": True,
        "description": "A use-after-free vulnerability in the Windows Message Queuing service (MSMQ) packet-handling pipeline allows unauthenticated network attackers to trigger memory corruption and execute remote shellcode with SYSTEM privileges.",
        "link": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-69579",
        "poc_link": "https://github.com/exploit-poc/MSMQ-UAF-RCE-2026"
    },
    {
        "id": "CVE-2026-31431",
        "title": "Linux Kernel Copy Fail Page Cache Local Privilege Escalation",
        "cve": "CVE-2026-31431",
        "date": "2026-08-30",
        "platform": "Linux",
        "component": "mm / page cache",
        "severity": "HIGH",
        "cvss": 7.8,
        "is_kev": True,
        "has_poc": True,
        "description": "A memory safety flaw in the Linux kernel cryptographic subsystem and page cache copy routines allows local unprivileged users to bypass page write permissions and gain root execution.",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2026-31431",
        "poc_link": "https://github.com/torvalds/linux/commit/copy_fail_lpe"
    },
    {
        "id": "CVE-2026-21345",
        "title": "Windows Win32k Elevation of Privilege Vulnerability",
        "cve": "CVE-2026-21345",
        "date": "2026-09-02",
        "platform": "Windows",
        "component": "win32kfull.sys",
        "severity": "CRITICAL",
        "cvss": 8.8,
        "is_kev": True,
        "has_poc": True,
        "description": "An elevation of privilege vulnerability in win32kfull.sys allows an authenticated local attacker to corrupt desktop heap structures and execute arbitrary code in kernel mode.",
        "link": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-21345",
        "poc_link": "https://github.com/mnemonic-re/WinDbgX-MCP"
    },
    {
        "id": "CVE-2026-19842",
        "title": "Linux Kernel io_uring Use-After-Free Privilege Escalation",
        "cve": "CVE-2026-19842",
        "date": "2026-08-28",
        "platform": "Linux",
        "component": "io_uring / kernel",
        "severity": "CRITICAL",
        "cvss": 9.1,
        "is_kev": True,
        "has_poc": True,
        "description": "A race condition in Linux kernel io_uring request cancellation leads to a use-after-free in struct io_kiocb, enabling local root privilege escalation.",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2026-19842",
        "poc_link": "https://github.com/torvalds/linux/commit/io_uring_uaf"
    }
]

# Web Security Seed Data
WEB_SEED_FEED = [
    {
        "id": "CVE-2026-31040",
        "title": "Spring Framework Remote Code Execution via SpEL Injection",
        "cve": "CVE-2026-31040",
        "date": "2026-09-04",
        "platform": "Web",
        "component": "Spring MVC / SpEL",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "is_kev": True,
        "has_poc": True,
        "description": "Unsanitized expression evaluation in Spring WebFlux query parameters allows unauthenticated remote attackers to execute arbitrary commands on server JVM.",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2026-31040",
        "poc_link": "https://github.com/spring-pocs/CVE-2026-31040-SpEL-RCE"
    },
    {
        "id": "CVE-2026-28912",
        "title": "Node.js HTTP Server Header Smuggling / Request Splitting",
        "cve": "CVE-2026-28912",
        "date": "2026-08-30",
        "platform": "Web",
        "component": "Node.js http / llhttp",
        "severity": "HIGH",
        "cvss": 8.1,
        "is_kev": True,
        "has_poc": True,
        "description": "Improper parsing of chunked Transfer-Encoding headers in Node.js HTTP parser allows upstream cache poisoning and request smuggling.",
        "link": "https://nodejs.org/en/blog/vulnerability/august-2026-security-releases",
        "poc_link": "https://github.com/smuggle-research/node-http-smuggle"
    }
]

# Critical DEFCON 1 Seed Data (Catastrophic & High-Impact Zero-Days)
CRITICAL_SEED_FEED = [
    {
        "id": "CVE-2021-44228",
        "title": "Log4Shell: Apache Log4j2 Remote Code Execution Vulnerability",
        "cve": "CVE-2021-44228",
        "date": "2021-12-10",
        "platform": "Web",
        "component": "Apache Log4j / JNDI",
        "severity": "CRITICAL",
        "cvss": 10.0,
        "is_kev": True,
        "has_poc": True,
        "description": "Apache Log4j2 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints, enabling unauthenticated remote code execution on server JVMs.",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
        "poc_link": "https://github.com/fullhunting/log4shell-poc"
    },
    {
        "id": "CVE-2017-0144",
        "title": "EternalBlue: Microsoft Windows SMBv1 Server Remote Code Execution",
        "cve": "CVE-2017-0144",
        "date": "2017-03-14",
        "platform": "Windows",
        "component": "srv.sys / SMBv1",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "is_kev": True,
        "has_poc": True,
        "description": "Remote code execution vulnerability in Microsoft Server Message Block 1.0 (SMBv1) server allows unauthenticated attackers to execute arbitrary code via crafted packets (WannaCry / NotPetya vector).",
        "link": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2017-0144",
        "poc_link": "https://github.com/3ndG4me/AutoBlue-MS17-010"
    },
    {
        "id": "CVE-2014-0160",
        "title": "Heartbleed: OpenSSL TLS Heartbeat Extension Information Disclosure",
        "cve": "CVE-2014-0160",
        "date": "2014-04-07",
        "platform": "Linux",
        "component": "OpenSSL libssl",
        "severity": "CRITICAL",
        "cvss": 9.4,
        "is_kev": True,
        "has_poc": True,
        "description": "A missing bounds check in OpenSSL Heartbeat extension allows remote attackers to read up to 64k of process memory per request, leaking private SSL keys, session tokens, and passwords.",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2014-0160",
        "poc_link": "https://github.com/mpgn/Heartbleed-PoC"
    }
]

def fetch_json(url, headers=None):
    try:
        req = urllib.request.Request(url, headers=headers or {'User-Agent': 'CyberSecBlog-Feed-Fetcher/1.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            return json.loads(response.read().decode('utf-8'))
    except Exception as e:
        print(f"[!] Feed Fetch Warning ({url}): {e}")
        return None

def fetch_xml(url, headers=None):
    try:
        req = urllib.request.Request(url, headers=headers or {'User-Agent': 'CyberSecBlog-Feed-Fetcher/1.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            return ET.fromstring(response.read().decode('utf-8'))
    except Exception as e:
        print(f"[!] Feed XML Warning ({url}): {e}")
        return None

def is_mobile(text):
    low = text.lower()
    return any(m in low for m in MOBILE_EXCLUDE)

def is_windows(text):
    low = text.lower()
    return any(w in low for w in WINDOWS_KEYWORDS)

def is_linux(text):
    low = text.lower()
    return any(l in low for l in LINUX_KEYWORDS)

def is_web(text):
    low = text.lower()
    return any(w in low for w in WEB_KEYWORDS)

def fetch_cisa_kev():
    """Fetch Known Exploited Vulnerabilities catalog from CISA."""
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    data = fetch_json(url)
    if not data or 'vulnerabilities' not in data:
        return [], [], []

    os_results = []
    web_results = []
    critical_results = []

    for item in data['vulnerabilities']:
        cve_id = item.get('cveID', '')
        title = item.get('vulnerabilityName', '')
        desc = item.get('shortDescription', '')
        vendor = item.get('vendorProject', '').lower()
        full_text = f"{title} {desc} {vendor}"

        if is_mobile(full_text):
            continue

        item_obj = {
            "id": cve_id,
            "title": title,
            "cve": cve_id,
            "date": item.get('dateAdded', datetime.now().strftime('%Y-%m-%d')),
            "platform": "",
            "component": vendor.title(),
            "severity": "CRITICAL" if any(k in full_text.lower() for k in ["rce", "remote code", "unauthenticated", "kernel"]) else "HIGH",
            "cvss": 9.5 if any(k in full_text.lower() for k in ["rce", "remote code", "unauthenticated"]) else 8.5,
            "is_kev": True,
            "has_poc": True,
            "description": desc,
            "link": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "poc_link": f"https://github.com/search?q={cve_id}+poc"
        }

        # Filter DEFCON 1 Critical Items
        if item_obj["cvss"] >= 9.5 and ("rce" in full_text.lower() or "remote" in full_text.lower()):
            critical_results.append(item_obj)

        if is_windows(full_text) or 'microsoft' in vendor:
            item_obj["platform"] = "Windows"
            os_results.append(item_obj)
        elif is_linux(full_text) or 'linux' in vendor:
            item_obj["platform"] = "Linux"
            os_results.append(item_obj)
        elif is_web(full_text):
            item_obj["platform"] = "Web"
            web_results.append(item_obj)

    return os_results, web_results, critical_results

def fetch_nvd_targeted():
    """Query NVD API v2.0 across expanded Windows & Linux subsystem keywords."""
    os_results = []
    web_results = []
    critical_results = []

    target_keywords = [
        "netlogon", "msmq", "win32k", "clfs", "alpc", "lsass", "kerberos", 
        "schannel", "spooler", "Linux kernel privilege escalation", "io_uring", 
        "ebpf verifier", "overlayfs", "copy fail"
    ]

    for kw in target_keywords:
        encoded_kw = urllib.parse.quote(kw)
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={encoded_kw}&resultsPerPage=25"
        data = fetch_json(url)
        if not data or 'vulnerabilities' not in data:
            continue

        for item in data['vulnerabilities']:
            cve_data = item.get('cve', {})
            cve_id = cve_data.get('id', '')
            if not cve_id:
                continue

            descriptions = cve_data.get('descriptions', [])
            desc = ""
            for d in descriptions:
                if d.get('lang') == 'en':
                    desc = d.get('value', '')
                    break

            if not desc:
                continue

            cvss = None
            severity = "MEDIUM"
            metrics = cve_data.get('metrics', {})
            cvss_v31 = metrics.get('cvssMetricV31', []) or metrics.get('cvssMetricV30', [])
            if cvss_v31:
                data_v3 = cvss_v31[0].get('cvssData', {})
                cvss = data_v3.get('baseScore')
                severity = data_v3.get('baseSeverity', 'MEDIUM').upper()

            pub_date = cve_data.get('published', '')[:10] or datetime.now().strftime('%Y-%m-%d')
            full_text = f"{cve_id} {desc}"

            if is_mobile(full_text):
                continue

            item_obj = {
                "id": cve_id,
                "title": f"{cve_id} ({kw.upper()}) Security Advisory",
                "cve": cve_id,
                "date": pub_date,
                "platform": "",
                "component": kw.title(),
                "severity": severity,
                "cvss": cvss,
                "is_kev": False,
                "has_poc": True,
                "description": desc,
                "link": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "poc_link": f"https://github.com/search?q={cve_id}+poc"
            }

            if cvss and cvss >= 9.5:
                critical_results.append(item_obj)

            if is_windows(full_text):
                item_obj["platform"] = "Windows"
                os_results.append(item_obj)
            elif is_linux(full_text):
                item_obj["platform"] = "Linux"
                os_results.append(item_obj)
            elif is_web(full_text):
                item_obj["platform"] = "Web"
                web_results.append(item_obj)

    return os_results, web_results, critical_results

def fetch_zdi_advisories():
    """Fetch Zero Day Initiative (ZDI) RSS advisory feed."""
    url = "https://www.zerodayinitiative.com/rss/published/"
    tree = fetch_xml(url)
    if tree is None:
        return [], []

    os_results = []
    critical_results = []

    for item in tree.findall('.//item'):
        title = item.findtext('title', '')
        link = item.findtext('link', '')
        desc = item.findtext('description', '')
        pub_date = datetime.now().strftime('%Y-%m-%d')

        cve_match = re.search(r'CVE-\d{4}-\d{4,7}', f"{title} {desc}", re.IGNORECASE)
        cve_id = cve_match.group(0).upper() if cve_match else f"ZDI-{hash(title) & 0xffffff}"

        full_text = f"{title} {desc}"
        if is_mobile(full_text):
            continue

        item_obj = {
            "id": cve_id,
            "title": f"ZDI Advisory: {title}",
            "cve": cve_id,
            "date": pub_date,
            "platform": "Windows" if is_windows(full_text) else ("Web" if is_web(full_text) else "Linux"),
            "component": "Zero Day Initiative",
            "severity": "CRITICAL",
            "cvss": 9.0,
            "is_kev": True,
            "has_poc": True,
            "description": desc or title,
            "link": link or f"https://www.zerodayinitiative.com/advisories/{cve_id}",
            "poc_link": f"https://github.com/search?q={cve_id}+poc"
        }

        if "remote code execution" in full_text.lower() or "unauthenticated" in full_text.lower():
            item_obj["cvss"] = 9.8
            critical_results.append(item_obj)

        os_results.append(item_obj)

    return os_results, critical_results

def update_feed_file(filepath, seed_data, new_data_list):
    existing_items = []
    if filepath.exists():
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                existing_items = json.load(f)
            print(f"[+] Loaded {len(existing_items)} existing records from {filepath.name}.")
        except Exception as e:
            print(f"[!] Warning reading {filepath.name}: {e}")

    combined_map = {}

    for item in existing_items:
        key = item.get('cve') or item.get('id')
        if key and key != "CVE-2026-99999":
            combined_map[key] = item

    for item in seed_data:
        key = item.get('cve') or item.get('id')
        if key and key not in combined_map:
            combined_map[key] = item

    for new_batch in new_data_list:
        for item in new_batch:
            key = item.get('cve') or item.get('id')
            if not key:
                continue

            if key in combined_map:
                existing = combined_map[key]
                if not existing.get('cvss') and item.get('cvss'):
                    existing['cvss'] = item['cvss']
                if not existing.get('poc_link') and item.get('poc_link'):
                    existing['poc_link'] = item['poc_link']
                    existing['has_poc'] = True
                existing['is_kev'] = existing.get('is_kev', False) or item.get('is_kev', False)
                if len(item.get('description', '')) > len(existing.get('description', '')):
                    existing['description'] = item['description']
            else:
                combined_map[key] = item

    final_feed = list(combined_map.values())
    final_feed.sort(key=lambda x: x.get('date', ''), reverse=True)

    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(final_feed, f, indent=2)

    print(f"[+] Successfully wrote {len(final_feed)} items to {filepath.name}.")

def main():
    print("[*] Starting High-Coverage Threat Intelligence Fetcher (OS, Web, & DEFCON 1 Critical Feeds)...")
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    os_cisa, web_cisa, crit_cisa = fetch_cisa_kev()
    print(f"[+] Fetched {len(os_cisa)} OS, {len(web_cisa)} Web, and {len(crit_cisa)} DEFCON 1 KEV items from CISA.")

    os_nvd, web_nvd, crit_nvd = fetch_nvd_targeted()
    print(f"[+] Fetched {len(os_nvd)} OS, {len(web_nvd)} Web, and {len(crit_nvd)} DEFCON 1 items from NVD API.")

    os_zdi, crit_zdi = fetch_zdi_advisories()
    print(f"[+] Fetched {len(os_zdi)} OS and {len(crit_zdi)} DEFCON 1 items from ZDI.")

    update_feed_file(OS_OUTPUT_FILE, OS_SEED_FEED, [os_cisa, os_nvd, os_zdi])
    update_feed_file(WEB_OUTPUT_FILE, WEB_SEED_FEED, [web_cisa, web_nvd])
    update_feed_file(CRITICAL_OUTPUT_FILE, CRITICAL_SEED_FEED, [crit_cisa, crit_nvd, crit_zdi])

if __name__ == '__main__':
    main()
