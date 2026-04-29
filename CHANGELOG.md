# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-04-29

### Added

- Initial release of `Invoke-ADDnsHealthCheck.ps1`.
- Forest discovery via `Get-ADForest` / `Get-ADDomainController`, with optional
  `-IncludeDomain` scoping.
- DNS Server service-state check on every DC.
- DC NIC client-side audit via CIM-over-DCOM (no WinRM required):
  - Primary / Secondary / additional DNS servers
  - DNS suffix and DNS suffix search list
  - "Register This Connection in DNS" flag
  - Self-only / `127.0.0.1` anti-pattern detection (DNS island risk)
- Zone enumeration with replication scope per zone (Primary, Secondary, Stub,
  AD-Integrated).
- Forward / reverse record audit:
  - Every A record has a matching PTR
  - Reverse zone exists for every subnet that owns A records
  - Reverse maps back to forward (PTR -> A consistency)
  - Duplicate IP -> multiple PTR targets
  - Same hostname -> multiple A records (informational)
- Forwarder validation:
  - TCP/53 reachability test
  - Live `Resolve-DnsName` test against `microsoft.com`
  - Optional `-ApprovedForwarders` allow-list comparison
- Best-practice findings:
  - AD-integrated zones must use Secure dynamic updates
  - Aging/scavenging configuration (server-wide and per-zone)
  - Recursion / EDNS0 advisory
- Matrix-style HTML report (Arial 7pt, navy `#0B2161` headers,
  severity-coded rows).
- Findings CSV plus four detail CSVs (zones, forwarders, PTR issues,
  duplicate PTRs).
- Optional SMTP email delivery (HTML body + every CSV attached) with
  `Send-MailMessage` and `System.Net.Mail.SmtpClient` fallback.
- ASCII-only source with UTF-8 BOM so PowerShell 5.1 parses consistently.

### Author

- Roy R. Taylor &lt;IAM@ITC.Technology&gt; &mdash; <https://itc.technology/>
