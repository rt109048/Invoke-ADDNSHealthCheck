# Invoke-ADDnsHealthCheck

A read-only DNS health check for an Active Directory forest. Discovers every
domain controller, verifies the DNS Server role, audits NIC client settings,
walks every forward and reverse zone, validates forwarders, and flags
Microsoft DNS best-practice deviations &mdash; producing a styled HTML report,
a findings CSV, and four detail CSVs (zones, forwarders, PTR coverage, and
duplicate PTRs).

> **Read-only.** No DNS records, zones, forwarders or NIC settings are modified.
> WinRM is **not** required &mdash; everything works over CIM-over-DCOM.

---

## What it checks

| Category | Specifically |
|---|---|
| **DC = DNS server** | DNS service running on every DC |
| **DC NIC config** | Primary + Secondary DNS, additional servers, DNS suffix, DNS suffix search list, "Register This Connection in DNS" |
| **DC NIC anti-patterns** | DC pointing only at itself for DNS (the classic "DNS island"), `127.0.0.1` as a DNS server, missing secondary DNS, primary DNS not pointing at any DC in the forest |
| **Zones** | Per-zone replication scope &mdash; **Primary**, **Secondary**, **Stub** or **AD-Integrated** |
| **PTR coverage** | Every A record has a matching PTR record |
| **Reverse zones exist** | A reverse lookup zone (`/24` or covering parent `/16` `/8`) exists for every subnet that owns A records |
| **Reverse maps to forward** | Every PTR points back to a real A record at the same IP |
| **Duplicate PTRs** | Same IP -> multiple host names |
| **Duplicate A records** | Same hostname -> multiple IPs (informational; flags stale or unintended round-robin) |
| **Forwarders** | Each forwarder is reachable on TCP/53, resolves a public test query, and (optionally) is on the `-ApprovedForwarders` allow list |
| **Aging / scavenging** | Server-wide scavenging state and interval, plus per-zone aging |
| **Best practices** | AD-integrated zones must use **Secure** dynamic updates, recursion advisory, EDNS0, primary-DNS-points-to-a-partner-DC |
| **Output** | HTML report, findings CSV, plus zones / forwarders / PTR-issues / duplicate-PTRs detail CSVs &mdash; all attached to the email |

## Prerequisites

- **PowerShell 5.1** or later (works on PS 7+).
- **RSAT** with `ActiveDirectory`, `DnsServer`, `DnsClient` modules.
- Read rights on every DC's DNS server role.
- **RPC connectivity** to every DC (TCP/135 + dynamic RPC range).
- `Resolve-DnsName` available (built-in on Windows 8+ / Server 2012+).

> **WinRM-free.** All remote queries use CIM-over-DCOM (`Win32_NetworkAdapterConfiguration`
> for NIC settings; `Get-DnsServer*` cmdlets for server / zone / forwarder data).
> Runs cleanly in environments where WinRM is disabled by policy.

## Installation

```powershell
git clone https://github.com/<your-username>/Invoke-ADDnsHealthCheck.git
cd Invoke-ADDnsHealthCheck
Unblock-File .\Invoke-ADDnsHealthCheck.ps1
```

## Usage

### Local report only

```powershell
.\Invoke-ADDnsHealthCheck.ps1 -NoEmail
```

Reports are written to `.\AD-DNS-HealthCheck-Reports\` (subdirectory of the
script's folder). Output files:

- `AD_DNS_Health_<timestamp>.html` &mdash; matrix-style report
- `AD_DNS_Health_<timestamp>.csv` &mdash; flat findings list
- `AD_DNS_Zones_<timestamp>.csv` &mdash; full zone inventory
- `AD_DNS_Forwarders_<timestamp>.csv` &mdash; per-DC forwarder reachability/resolution
- `AD_DNS_PTR_Issues_<timestamp>.csv` &mdash; missing/orphan PTR records
- `AD_DNS_Duplicate_PTR_<timestamp>.csv` &mdash; IPs with multiple PTR targets

### Email the report (with all CSV attachments)

```powershell
.\Invoke-ADDnsHealthCheck.ps1 `
    -SmtpServer mail.example.com -SmtpPort 587 -UseSsl `
    -From dns-monitor@example.com -To ops@example.com,secops@example.com `
    -ApprovedForwarders 1.1.1.1,1.0.0.1,8.8.8.8 `
    -Credential (Get-Credential)
```

### Limit scope

```powershell
.\Invoke-ADDnsHealthCheck.ps1 `
    -IncludeDomain corp.example.com,prod.example.com `
    -MaxRecordsPerZone 10000 -NoEmail
```

## Parameters

| Name | Type | Default | Notes |
|---|---|---|---|
| `SmtpServer` | `string` | (none) | If omitted, no email is sent |
| `SmtpPort` | `int` | 25 (or 587 if `-UseSsl`) | |
| `From` | `string` | (none) | Required when `-SmtpServer` is supplied |
| `To` | `string[]` | (none) | One or more recipients |
| `Cc` | `string[]` | (none) | Optional |
| `UseSsl` | `switch` | off | TLS for SMTP |
| `Credential` | `PSCredential` | (none) | For authenticated SMTP |
| `Subject` | `string` | `DNS Health Check - <Mon-DD> - <Forest>` | Override default subject |
| `IncludeDomain` | `string[]` | (all forest domains) | Limit scope |
| `ApprovedForwarders` | `string[]` | (none) | Flag forwarders not in this list |
| `MaxRecordsPerZone` | `int` | 5000 | Cap per-zone record pull |
| `ReportFolder` | `string` | `<script-dir>\AD-DNS-HealthCheck-Reports` | HTML/CSV destination |
| `NoEmail` | `switch` | off | Generate files only |

## Report layout

```
Active Directory DNS Health Check
Forest: example.com   DCs checked: N   Zones audited: M   Generated: YYYY-MM-DD HH:MM:SS
[Critical: N · High: N · Medium: N · Low: N · Info: N]

Domain Controller NIC / DNS Configuration
   DC | Domain | DC IP | DNS Svc | Primary | Secondary | Additional | Suffix | Search List | Register | Self-Only | 127.0.0.1

DNS Zones (Primary / Secondary / AD-Integrated / Stub)
   DC | Zone | Type | Reverse | Dynamic Update | Aging | NoRefresh | Refresh | Replication Scope

Forwarders
   DC | Forwarder | Reachable (TCP/53) | Resolves Test Query | On Approved List

Duplicate IP -> Multiple PTR Targets
   IP | Count | Targets

PTR Coverage / Mismatch Issues
   IP | Type | Detail

Health Findings and Recommendations
   Severity-ranked Critical -> Info, color-coded

Run Context
   script path, host, user, PS version, started/completed/duration
```

## Author

- **Roy R. Taylor**
- Email: <IAM@ITC.Technology>
- Website: <https://itc.technology/>

See [AUTHOR.md](AUTHOR.md) for the canonical paste-in template used by every
script in this repository.

## License

Released under the [MIT License](LICENSE). Provided as-is, no warranty. Test
in a lab before running against production.

## Companion script

For a complete AD health workflow, pair this with
**[Invoke-ADHealthCheck](https://github.com/&lt;your-username&gt;/Invoke-ADHealthCheck)** &mdash;
forest / FSMO / DCDIAG / replication / services / privileged groups /
hygiene / GPO / event log + matrix HTML + email.
