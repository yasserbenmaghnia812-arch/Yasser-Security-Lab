# Security scanning rules

The curated YARA rules in this directory detect common exposed credential formats. They are intended for defensive source review and may require local tuning to reduce false positives.

The GitHub Actions workflow scans repository files, records actual YARA match output separately from scanner errors, and uploads the resulting report. A match is a signal for manual validation, not proof that a credential is valid.

Never add real credentials or private keys to test fixtures. Use synthetic strings that cannot authenticate to any service.
