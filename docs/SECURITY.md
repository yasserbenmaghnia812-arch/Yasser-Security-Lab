# Security model

## Authorization
Each asset requires ownership/permission confirmation, owner, allowed domains/IP ranges/package hashes, permitted test categories, and expiry. Every job must resolve to an active scope record. No scope means no job.

## Prohibited
No stealth/evasion, persistence, credential harvesting, phishing kits, destructive payloads, mass exploitation, botnets, unauthorized access, or autonomous exploitation. Chat instructions cannot override policy.

## Execution controls
- Typed task schemas; no arbitrary shell, Python, or OS command endpoint.
- Passive checks by default. Active DAST/port checks require explicit approval per job.
- Allowlists, DNS/IP revalidation, private/link-local/metadata blocking, redirect scope checks, request budgets, concurrency limits, and timeouts.
- Non-root ephemeral containers, read-only base, restricted egress, no Docker socket/host mounts, and artifact caps.
- Redact credentials, cookies, tokens, personal data, and sensitive response bodies before persistence or AI processing.
- Audit approvals, tool versions, parameters, start/end, and report exports.
- Treat AI output as untrusted; validate every suggested action against policy.

## Data protection
Supabase Auth, RLS, private Storage, short-lived signed URLs, least privilege. Never ship service-role keys or model secrets in APK/browser bundles. Retain uploaded APKs briefly and support deletion.

## Reports
Every finding records evidence, timestamp, affected asset, severity, confidence, validation status, impact, remediation, and limitations. Separate confirmed findings from suspected indicators.
