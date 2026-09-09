# Future Vulnerability & Threat Intelligence Sources

This document outlines planned external API integrations and feed connectors for `scripts/fetch_vuln_feed.py`.

---

## 1. GitHub Security Advisory API (GHSA)
* **Endpoint**: `https://api.github.com/advisories` (REST) or GitHub GraphQL API `securityAdvisories`
* **Purpose**: Pulls open-source security advisories, CVE mappings, affected package ecosystems (npm, PyPI, Go, Cargo, NuGet), and direct links to PoC repositories / security fixes.
* **Headers Required**: `User-Agent: CyberSecBlog-Feed-Fetcher`, `Authorization: Bearer <GITHUB_TOKEN>` (optional, increases rate limit).
* **Key Fields**:
  - `ghsa_id`, `cve_id`
  - `summary`, `description`
  - `severity` (`CRITICAL`, `HIGH`, `MODERATE`, `LOW`)
  - `references` (extract GitHub PoC commit & repository URLs)

---

## 2. MSRC & Vendor Security Advisories (RSS / REST)
* **Microsoft Security Response Center (MSRC)**:
  - **Endpoint**: `https://api.msrc.microsoft.com/cvrf/v3.0/updates`
  - **Purpose**: Direct Windows kernel, Win32k, CLFS, Hyper-V Patch Tuesday advisories with official KB links.
* **Ubuntu Security Notices (USN)**:
  - **Endpoint**: `https://ubuntu.com/security/notices.json`
  - **Purpose**: Linux kernel, eBPF, netfilter, systemd, and glibc security advisories.
* **Debian Security Advisories (DSA)**:
  - **Endpoint**: `https://www.debian.org/security/dsa.xml` (RSS)

---

## 3. Exploit Databases & Live PoC Drop Feeds
* **Exploit-DB Feed**:
  - **Endpoint**: `https://www.exploit-db.com/rss.xml`
  - **Purpose**: Verified public exploit code drops for 0-days and 1-days.
* **Packet Storm Security**:
  - **Endpoint**: `https://packetstormsecurity.com/feeder/news/` (RSS)
  - **Purpose**: Real-time exploit drops, advisories, and paper publications.
* **VulnCheck KEV / NVD++ API**:
  - **Endpoint**: `https://api.vulncheck.com/v3/index/vulncheck-kev`
  - **Purpose**: High-speed real-time replacement feed for NVD latency.

---

## Implementation Status
- [x] **CISA Known Exploited Vulnerabilities (KEV) Catalog** — Active
- [x] **NVD API v2.0** — Active
- [ ] **GitHub Security Advisory API** — Planned
- [ ] **MSRC & Vendor RSS Feeds** — Planned
- [ ] **Exploit-DB / PacketStorm Feeds** — Planned
