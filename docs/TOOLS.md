# Open-source tool catalogue (27)

> **Execution status (verified 2026-11-10):** 8 source-analysis tools (Semgrep, Gitleaks, Trivy, Checkov, Syft, Grype, YARA, ClamAV) completed successfully in GitHub Actions and produced report artifacts. Seven APK/binary analyzers (MobSF, JADX, Apktool, Androguard, APKLeaks, Ghidra, radare2) are wired into the workflow but have not yet run because no APK has been placed in `authorized-samples/`. Eleven network tools (Nmap, ZAP baseline, Nuclei, httpx, Subfinder, Amass, dnsx, Katana, Naabu, testssl.sh, Nikto) are available in a separate manual workflow that requires explicit authorization confirmation and one exact public target. mitmproxy remains a local/device proxy integration and is not yet wired into the APK workflow. The API currently validates scope and plans jobs; it does not dispatch scans itself.

**Run source/APK analysis:** GitHub → Actions → Authorized Static Security Analysis → Run workflow. For APK analysis, first add your authorized APK under `authorized-samples/` and push it.

**Run a network assessment:** GitHub → Actions → Approved Low-Impact Network Assessment → Run workflow. Confirm written authorization, enter one exact hostname/IP/URL and a scope reference. Wildcards, CIDR, private IPs and localhost are rejected. The workflow uses rate-limited, non-exploit checks only.

Adapters are optional and must pin reviewed releases/digests. The worker enforces authorization, allowlists, rate limits, timeouts, output caps, and audit logging.

| # | Tool | Function | Execution guard |
|---:|---|---|---|
| 1 | [Nmap](https://github.com/nmap/nmap) | Port/service inventory | Approved IP/CIDR only; conservative timing |
| 2 | [OWASP ZAP](https://github.com/zaproxy/zaproxy) | Web DAST | Passive baseline by default; active tests need approval |
| 3 | [Nuclei](https://github.com/projectdiscovery/nuclei) | Template checks | Curated non-destructive templates only |
| 4 | [httpx](https://github.com/projectdiscovery/httpx) | HTTP metadata | Allowlisted hosts; low rate |
| 5 | [Subfinder](https://github.com/projectdiscovery/subfinder) | Passive subdomain discovery | Passive sources only |
| 6 | [Amass](https://github.com/owasp-amass/amass) | Attack-surface mapping | Passive mode; approved root domains |
| 7 | [dnsx](https://github.com/projectdiscovery/dnsx) | DNS validation | Approved domains; bounded queries |
| 8 | [Katana](https://github.com/projectdiscovery/katana) | Web crawling | Same-origin; bounded depth |
| 9 | [Naabu](https://github.com/projectdiscovery/naabu) | Port discovery | Approved IPs; conservative rate |
| 10 | [testssl.sh](https://github.com/testssl/testssl.sh) | TLS audit | Non-destructive checks |
| 11 | [Nikto](https://github.com/sullo/nikto) | Web server hygiene | Approved hosts; safe plugins |
| 12 | [Semgrep](https://github.com/semgrep/semgrep) | SAST | User-supplied source only |
| 13 | [Gitleaks](https://github.com/gitleaks/gitleaks) | Secret detection | User-owned repos/files; redact results |
| 14 | [Trivy](https://github.com/aquasecurity/trivy) | Image/dependency/IaC scan | User-supplied artifacts |
| 15 | [Checkov](https://github.com/bridgecrewio/checkov) | IaC security | User-supplied infrastructure code |
| 16 | [Grype](https://github.com/anchore/grype) | Vulnerability matching | SBOMs and user-owned images |
| 17 | [Syft](https://github.com/anchore/syft) | SBOM generation | User-supplied artifacts |
| 18 | [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) | Mobile app assessment | Uploaded APKs with authorization |
| 19 | [JADX](https://github.com/skylot/jadx) | APK/DEX decompilation | Uploaded APKs only |
| 20 | [Apktool](https://github.com/iBotPeaches/Apktool) | APK resource inspection | Uploaded APKs only |
| 21 | [Androguard](https://github.com/androguard/androguard) | Android static analysis | Uploaded APKs only |
| 22 | [APKLeaks](https://github.com/dwisiswant0/apkleaks) | APK endpoint indicators | Uploaded APKs; redact secrets |
| 23 | [Ghidra](https://github.com/NationalSecurityAgency/ghidra) | Native reverse engineering | Authorized binaries only |
| 24 | [radare2](https://github.com/radareorg/radare2) | Binary inspection | Authorized binaries only |
| 25 | [YARA](https://github.com/VirusTotal/yara) | Malware pattern matching | Static classification; never execute samples |
| 26 | [ClamAV](https://github.com/Cisco-Talos/clamav) | Malware scanning | Quarantine and scan; no execution |
| 27 | [mitmproxy](https://github.com/mitmproxy/mitmproxy) | Traffic inspection | Explicit test-device consent only |

## Adapter interface
Each adapter implements validate_scope, plan, execute, normalize_findings, health, and version. The API accepts typed task schemas, never arbitrary shell commands. The runner is non-root, read-only, egress-restricted, and resource-limited.

## AI assistants
- Qwen2.5-Coder-7B-Instruct: code review and remediation.
- DeepSeek-R1-Distill-Qwen-7B: finding triage and report review.

Both are advisory and cannot call tools or override policy. A human approves scans and active tests. Model hosting and GPU inference may incur cost; local inference on a low-memory phone is not assumed.
