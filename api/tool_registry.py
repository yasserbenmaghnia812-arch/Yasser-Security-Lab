"""Central registry for the 27 open-source security tools.

Only tools wired into .github/workflows/security-static.yml are marked
workflow_enabled. Network and proxy tools remain disabled until a scoped,
approval-gated isolated runner is deployed.
"""

TOOL_REGISTRY = {
    "nmap": {"name": "Nmap", "mode": "active", "category": "network", "workflow_enabled": False, "reason": "Requires explicit target scope and active-scan approval."},
    "zap": {"name": "OWASP ZAP", "mode": "active", "category": "web", "workflow_enabled": False, "reason": "Requires isolated web-test runner and explicit approval."},
    "nuclei": {"name": "Nuclei", "mode": "active", "category": "web", "workflow_enabled": False, "reason": "Template allowlist and explicit approval required."},
    "httpx": {"name": "httpx", "mode": "passive", "category": "recon", "workflow_enabled": False, "reason": "Domain discovery runner not connected."},
    "subfinder": {"name": "Subfinder", "mode": "passive", "category": "recon", "workflow_enabled": False, "reason": "Domain discovery runner not connected."},
    "amass": {"name": "Amass", "mode": "passive", "category": "recon", "workflow_enabled": False, "reason": "Domain discovery runner not connected."},
    "dnsx": {"name": "dnsx", "mode": "passive", "category": "recon", "workflow_enabled": False, "reason": "DNS enumeration runner not connected."},
    "katana": {"name": "Katana", "mode": "active", "category": "web", "workflow_enabled": False, "reason": "Crawling requires an approved host allowlist."},
    "naabu": {"name": "Naabu", "mode": "active", "category": "network", "workflow_enabled": False, "reason": "Port scanning requires explicit target scope and approval."},
    "testssl": {"name": "testssl.sh", "mode": "active", "category": "tls", "workflow_enabled": False, "reason": "TLS checks require an approved host allowlist."},
    "nikto": {"name": "Nikto", "mode": "active", "category": "web", "workflow_enabled": False, "reason": "Web probing requires explicit approval."},
    "semgrep": {"name": "Semgrep", "mode": "static", "category": "source", "workflow_enabled": True, "reason": "Runs in the static GitHub Actions workflow."},
    "gitleaks": {"name": "Gitleaks", "mode": "static", "category": "source", "workflow_enabled": True, "reason": "Runs in the static GitHub Actions workflow."},
    "trivy": {"name": "Trivy", "mode": "static", "category": "dependencies", "workflow_enabled": True, "reason": "Runs filesystem vulnerability scanning in GitHub Actions."},
    "checkov": {"name": "Checkov", "mode": "static", "category": "infrastructure", "workflow_enabled": True, "reason": "Runs IaC and configuration checks in GitHub Actions."},
    "grype": {"name": "Grype", "mode": "static", "category": "dependencies", "workflow_enabled": True, "reason": "Scans generated SBOM in GitHub Actions."},
    "syft": {"name": "Syft", "mode": "static", "category": "dependencies", "workflow_enabled": True, "reason": "Generates CycloneDX SBOM in GitHub Actions."},
    "mobsf": {"name": "MobSF", "mode": "reverse_engineering", "category": "mobile", "workflow_enabled": False, "reason": "Runs in the MobSF API-only Docker step when an authorized APK is supplied."},
    "jadx": {"name": "JADX", "mode": "reverse_engineering", "category": "mobile", "workflow_enabled": False, "reason": "Runs on APKs placed in authorized-samples/."},
    "apktool": {"name": "Apktool", "mode": "reverse_engineering", "category": "mobile", "workflow_enabled": False, "reason": "Runs on APKs placed in authorized-samples/."},
    "androguard": {"name": "Androguard", "mode": "reverse_engineering", "category": "mobile", "workflow_enabled": False, "reason": "Runs on APKs placed in authorized-samples/."},
    "apkleaks": {"name": "APKLeaks", "mode": "reverse_engineering", "category": "mobile", "workflow_enabled": False, "reason": "Runs on APKs placed in authorized-samples/."},
    "ghidra": {"name": "Ghidra", "mode": "reverse_engineering", "category": "binary", "workflow_enabled": False, "reason": "Headless Ghidra analysis is run on native libraries extracted from authorized APKs."},
    "radare2": {"name": "radare2", "mode": "reverse_engineering", "category": "binary", "workflow_enabled": False, "reason": "radare2 metadata analysis is run on native libraries extracted from authorized APKs."},
    "yara": {"name": "YARA", "mode": "static", "category": "malware_defense", "workflow_enabled": True, "reason": "Runs repository file-pattern scan in GitHub Actions."},
    "clamav": {"name": "ClamAV", "mode": "static", "category": "malware_defense", "workflow_enabled": True, "reason": "Runs repository file scan in GitHub Actions."},
    "mitmproxy": {"name": "mitmproxy", "mode": "active", "category": "proxy", "workflow_enabled": False, "reason": "Requires user-controlled device, certificate consent, and isolated proxy."},
}


def public_tool_catalog():
    return {
        key: {
            **value,
            "execution_available": value["workflow_enabled"],
            "execution_route": "github_actions" if value["workflow_enabled"] else None,
        }
        for key, value in TOOL_REGISTRY.items()
    }
