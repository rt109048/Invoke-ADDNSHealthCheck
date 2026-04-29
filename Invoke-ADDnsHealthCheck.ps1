<#
.SYNOPSIS
    Comprehensive read-only DNS health check for an Active Directory forest.

.DESCRIPTION
    Discovers every domain controller in the forest, verifies DNS-server role,
    inspects DC NIC client settings, audits forward and reverse zones, and
    validates the most important Microsoft DNS best-practice settings:

      - DCs are running the DNS Server role.
      - DC NIC configuration: primary / secondary DNS, DNS suffix, search list,
        register-this-connection setting, and the classic "self-as-only-DNS"
        island anti-pattern.
      - Every A record has a matching PTR.
      - Reverse lookup zones exist for every subnet seen in A records.
      - No duplicate IP -> multiple hostnames in PTR records.
      - Every PTR record points back to an A record in the forward zone.
      - Zone replication scope per zone (Primary, Secondary, AD-Integrated).
      - Conditional + global forwarders resolve and are reachable.
      - Aging / scavenging configuration (server-wide and per-zone).
      - Best-practice settings: secure-only dynamic updates on AD-integrated
        zones, recursion, EDNS0, root hints, response rate limiting, etc.

    Output:
      - Styled HTML report (matrix-style: DC x check) written to disk.
      - Findings CSV (Severity, Domain, DC/Zone, Category, Issue,
        Recommendation) for ingestion / Excel.
      - Optional SMTP email delivery with both files attached.

    READ-ONLY. No DNS records, zones, forwarders or NIC settings are modified.

.PARAMETER SmtpServer
    SMTP relay used to send the report. If omitted, no email is sent.

.PARAMETER SmtpPort
    SMTP port. Default 25 (or 587 if -UseSsl is supplied).

.PARAMETER From
    Sender address. Required when -SmtpServer is supplied.

.PARAMETER To
    One or more recipients.

.PARAMETER Cc
    Optional CC recipients.

.PARAMETER UseSsl
    Use TLS for SMTP.

.PARAMETER Credential
    PSCredential for authenticated SMTP.

.PARAMETER Subject
    Optional subject override. Default: "DNS Health Check - <date> - <Forest>".

.PARAMETER IncludeDomain
    Optional array of domain FQDNs to limit scope.

.PARAMETER ApprovedForwarders
    Optional array of IPv4 strings that are allowed as forwarders. If supplied
    the script flags any forwarder NOT in this list as a finding.

.PARAMETER MaxRecordsPerZone
    Cap on records pulled per zone (avoids huge zones blowing the report).
    Default 5000.

.PARAMETER ReportFolder
    Folder where the HTML/CSV reports are written. Defaults to a
    subdirectory named "AD-DNS-HealthCheck-Reports" under the directory
    containing this script.

.PARAMETER NoEmail
    Generate the report files only; do not send mail.

.EXAMPLE
    .\Invoke-ADDnsHealthCheck.ps1 -NoEmail

.EXAMPLE
    .\Invoke-ADDnsHealthCheck.ps1 `
        -SmtpServer mail.example.com -SmtpPort 587 -UseSsl `
        -From dns-monitor@example.com -To ops@example.com,secops@example.com `
        -ApprovedForwarders 1.1.1.1,1.0.0.1,8.8.8.8 `
        -Credential (Get-Credential)

.NOTES
    Author  : Roy R. Taylor
    Email   : IAM@ITC.Technology
    Website : https://itc.technology/

    Requires : ActiveDirectory, DnsServer, DnsClient modules (RSAT-AD,
               RSAT-DNS-Server). PowerShell 5.1 or later.
               Read rights on every DC's DNS server role.

    *** WinRM is NOT required. ***
    All remote queries use CIM-over-DCOM (TCP/135 + dynamic RPC):
        - Win32_NetworkAdapterConfiguration  -> NIC client settings
        - Get-DnsServer*                     -> server / zone / forwarder data
                                                 (CIM session over DCOM)

    READ-ONLY: This script makes no changes to DNS or AD.
    Provided as-is, no warranty. Test in a lab before production use.
#>

[CmdletBinding()]
param(
    [string]   $SmtpServer,
    [int]      $SmtpPort,
    [string]   $From,
    [string[]] $To,
    [string[]] $Cc,
    [switch]   $UseSsl,
    [pscredential] $Credential,
    [string]   $Subject,

    [string[]] $IncludeDomain,
    [string[]] $ApprovedForwarders = @(),
    [int]      $MaxRecordsPerZone  = 5000,

    [string]   $ReportFolder,
    [switch]   $NoEmail
)

#region ---------- Setup ------------------------------------------------------

$ErrorActionPreference = 'Stop'
$script:Findings   = New-Object System.Collections.Generic.List[object]
$script:DCResults  = New-Object System.Collections.Generic.List[object]
$script:ZoneData   = New-Object System.Collections.Generic.List[object]
$script:DupRecs    = New-Object System.Collections.Generic.List[object]
$script:Orphans    = New-Object System.Collections.Generic.List[object]
$script:Forwarders = New-Object System.Collections.Generic.List[object]
$timestamp         = Get-Date -Format 'yyyyMMdd-HHmmss'

# Resolve report folder default
if (-not $ReportFolder) {
    $scriptDir = if     ($PSScriptRoot)               { $PSScriptRoot }
                 elseif ($MyInvocation.MyCommand.Path) { Split-Path -Path $MyInvocation.MyCommand.Path -Parent }
                 else                                  { (Get-Location).Path }
    $ReportFolder = Join-Path -Path $scriptDir -ChildPath 'AD-DNS-HealthCheck-Reports'
}

# Run context (for email footer)
if     ($PSCommandPath)               { $rcPath = $PSCommandPath; $rcName = Split-Path $PSCommandPath -Leaf }
elseif ($MyInvocation.MyCommand.Path) { $rcPath = $MyInvocation.MyCommand.Path; $rcName = $MyInvocation.MyCommand.Name }
else                                  { $rcPath = '<interactive / unsaved>'; $rcName = '<interactive>' }
try   { $rcHost = [System.Net.Dns]::GetHostEntry([System.Environment]::MachineName).HostName }
catch { $rcHost = $env:COMPUTERNAME }
try   { $rcUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name }
catch { $rcUser = "$env:USERDOMAIN\$env:USERNAME" }

$script:RunContext = [pscustomobject]@{
    ScriptPath = $rcPath
    ScriptName = $rcName
    RunHost    = $rcHost
    RunUser    = $rcUser
    StartTime  = Get-Date
    PSVersion  = $PSVersionTable.PSVersion.ToString()
}

function Add-Finding {
    param(
        [Parameter(Mandatory)] [ValidateSet('Critical','High','Medium','Low','Info')] [string]$Severity,
        [Parameter(Mandatory)] [string]$Target,
        [Parameter(Mandatory)] [string]$Domain,
        [Parameter(Mandatory)] [string]$Category,
        [Parameter(Mandatory)] [string]$Issue,
        [string]$Recommendation
    )
    $script:Findings.Add([pscustomobject]@{
        Severity       = $Severity
        Domain         = $Domain
        Target         = $Target
        Category       = $Category
        Issue          = $Issue
        Recommendation = $Recommendation
    })
}

function Write-Section($Text) {
    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor DarkCyan
    Write-Host (" $Text") -ForegroundColor Cyan
    Write-Host ('=' * 78) -ForegroundColor DarkCyan
}

function HtmlEnc([string]$s) {
    if ($null -eq $s) { return '' }
    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue
    [System.Web.HttpUtility]::HtmlEncode($s)
}

function Test-IPv4 {
    param([string]$ip)
    if ([string]::IsNullOrWhiteSpace($ip)) { return $false }
    [System.Net.IPAddress]::TryParse($ip, [ref]([System.Net.IPAddress]::Loopback))
}

function ConvertTo-ReverseZone {
    # IPv4 -> /24 reverse zone name (matches default Windows DNS reverse-zone layout).
    param([string]$ip)
    if (-not (Test-IPv4 $ip)) { return $null }
    $octets = $ip.Split('.')
    if ($octets.Count -ne 4) { return $null }
    "$($octets[2]).$($octets[1]).$($octets[0]).in-addr.arpa"
}

function ConvertFrom-PTRName {
    # Convert a PTR owner name + zone name back to an IPv4 string.
    param([string]$ownerName, [string]$zoneName)
    $name = $ownerName.Trim('.')
    if ($name -match '^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\.in-addr\.arpa$') {
        $rev = $Matches[1].Split('.')
        return ($rev[3..0] -join '.')
    }
    $zRev = $zoneName.Trim('.') -replace '\.in-addr\.arpa$',''
    $zParts = $zRev.Split('.')
    if ($zParts.Count -eq 3) {
        return "$($zParts[2]).$($zParts[1]).$($zParts[0]).$name"
    } elseif ($zParts.Count -eq 2) {
        $oct = $name.Split('.')
        if ($oct.Count -eq 2) {
            return "$($zParts[1]).$($zParts[0]).$($oct[1]).$($oct[0])"
        }
    } elseif ($zParts.Count -eq 1) {
        $oct = $name.Split('.')
        if ($oct.Count -eq 3) {
            return "$($zParts[0]).$($oct[2]).$($oct[1]).$($oct[0])"
        }
    }
    return $null
}

# Module load (warn-only; checks tolerate missing modules)
foreach ($m in 'ActiveDirectory','DnsServer','DnsClient') {
    try { Import-Module $m -ErrorAction Stop } catch {
        Write-Warning "Module '$m' could not be loaded: $($_.Exception.Message). Some checks may be skipped."
    }
}

#endregion

#region ---------- Discover DCs ---------------------------------------------

Write-Section 'Discovering domain controllers'
try {
    $forest  = Get-ADForest
    $domains = $forest.Domains
    if ($IncludeDomain) { $domains = $domains | Where-Object { $IncludeDomain -contains $_ } }
} catch {
    throw "Unable to query forest. $_"
}

$allDCs = foreach ($d in $domains) {
    try {
        Get-ADDomainController -Filter * -Server $d |
            Select-Object Name, HostName, Domain, Site, OperatingSystem, IPv4Address, IsGlobalCatalog
    } catch {
        Add-Finding -Severity High -Target '(discovery)' -Domain $d -Category 'Discovery' `
            -Issue "Failed to enumerate DCs in domain '$d': $($_.Exception.Message)" `
            -Recommendation "Verify trust, DNS resolution and reachability to '$d'."
    }
}

Write-Host ("Forest          : {0}" -f $forest.Name)          -ForegroundColor Green
Write-Host ("Domains in scope: {0}" -f ($domains -join ', ')) -ForegroundColor Green
Write-Host ("DCs discovered  : {0}" -f $allDCs.Count)         -ForegroundColor Green

$dcDnsIps = @{}
foreach ($dc in $allDCs) { $dcDnsIps[$dc.HostName] = $dc.IPv4Address }

#endregion

#region ---------- Per-DC DNS server collection -----------------------------

Write-Section 'Collecting DNS server data from each DC'

foreach ($dc in $allDCs) {

    $hn = $dc.HostName
    Write-Host ''
    Write-Host (" >>> {0}  ({1})" -f $hn, $dc.Domain) -ForegroundColor White

    $row = [ordered]@{
        DC                     = $hn
        Domain                 = $dc.Domain
        Site                   = $dc.Site
        IP                     = $dc.IPv4Address
        DNSServiceState        = 'Unknown'
        PrimaryDNS             = ''
        SecondaryDNS           = ''
        AdditionalDNS          = ''
        DnsSuffix              = ''
        DnsSuffixSearchList    = ''
        RegisterThisConnection = ''
        UsesSelfOnlyAsDns      = ''
        UsesLoopbackAsDns      = ''
        Recursion              = ''
        ScavengingEnabled      = ''
        ScavengingInterval     = ''
        EDNSEnabled            = ''
        ForwardersList         = ''
        ZonesPrimary           = 0
        ZonesSecondary         = 0
        ZonesADIntegrated      = 0
        ZonesStub              = 0
    }

    # ---- DNS service running ----
    try {
        $svc = Get-Service -ComputerName $hn -Name DNS -ErrorAction Stop
        $row.DNSServiceState = $svc.Status.ToString()
        if ($svc.Status -ne 'Running') {
            Add-Finding -Severity Critical -Target $hn -Domain $dc.Domain -Category 'DNS Service' `
                -Issue "DNS Server service is $($svc.Status) on $hn." `
                -Recommendation "Start the DNS service: Start-Service DNS -ComputerName $hn. Investigate why it stopped (Application/System logs)."
        }
    } catch {
        $row.DNSServiceState = 'Error'
        Add-Finding -Severity High -Target $hn -Domain $dc.Domain -Category 'DNS Service' `
            -Issue "Could not query DNS service: $($_.Exception.Message)" `
            -Recommendation 'Verify reachability, Remote Service Management firewall rule, and account rights.'
    }

    # ---- DCOM CIM session ----
    $cim = $null
    try {
        $dcomOpt = New-CimSessionOption -Protocol Dcom
        $cim     = New-CimSession -ComputerName $hn -SessionOption $dcomOpt -ErrorAction Stop
    } catch {
        Add-Finding -Severity High -Target $hn -Domain $dc.Domain -Category 'Connectivity' `
            -Issue "Could not open CIM/DCOM session: $($_.Exception.Message)" `
            -Recommendation 'Verify TCP/135 + dynamic RPC range and the WMI firewall rules are enabled. WinRM is not required by this script.'
        $script:DCResults.Add([pscustomobject]$row)
        continue
    }

    # ---- NIC configuration via CIM (no WinRM) -------------------------
    try {
        $nics = Get-CimInstance -CimSession $cim `
            -ClassName Win32_NetworkAdapterConfiguration `
            -Filter "IPEnabled = TRUE" -ErrorAction Stop

        $primary    = $null
        $secondary  = $null
        $extra      = @()
        $suffix     = ''
        $searchList = ''
        $register   = $null
        $usesSelf   = $false
        $usesLoop   = $false

        foreach ($nic in $nics) {
            if ($nic.DNSServerSearchOrder -and $nic.DNSServerSearchOrder.Count -gt 0) {
                if (-not $primary) {
                    $primary = $nic.DNSServerSearchOrder[0]
                    if ($nic.DNSServerSearchOrder.Count -gt 1) { $secondary = $nic.DNSServerSearchOrder[1] }
                    if ($nic.DNSServerSearchOrder.Count -gt 2) {
                        $extra = $nic.DNSServerSearchOrder[2..($nic.DNSServerSearchOrder.Count-1)]
                    }
                } else {
                    $extra += $nic.DNSServerSearchOrder
                }
                if ($nic.DNSServerSearchOrder -contains '127.0.0.1') { $usesLoop = $true }
                if ($nic.DNSServerSearchOrder.Count -eq 1 -and $nic.DNSServerSearchOrder[0] -eq $dc.IPv4Address) {
                    $usesSelf = $true
                }
            }
            if ($nic.DNSDomain) { $suffix = $nic.DNSDomain }
            if ($nic.DNSDomainSuffixSearchOrder -and -not $searchList) {
                $searchList = ($nic.DNSDomainSuffixSearchOrder -join ', ')
            }
            if ($null -ne $nic.FullDNSRegistrationEnabled) {
                $register = $nic.FullDNSRegistrationEnabled
            }
        }

        $row.PrimaryDNS             = $primary
        $row.SecondaryDNS           = $secondary
        $row.AdditionalDNS          = ($extra -join ', ')
        $row.DnsSuffix              = $suffix
        $row.DnsSuffixSearchList    = $searchList
        $row.RegisterThisConnection = $register
        $row.UsesSelfOnlyAsDns      = $usesSelf
        $row.UsesLoopbackAsDns      = $usesLoop

        if (-not $primary) {
            Add-Finding -Severity Critical -Target $hn -Domain $dc.Domain -Category 'NIC' `
                -Issue 'No DNS server addresses configured on any IP-enabled NIC.' `
                -Recommendation 'Configure at least one Primary and one Secondary DNS server (other DCs in the domain).'
        }
        if ($usesLoop) {
            Add-Finding -Severity High -Target $hn -Domain $dc.Domain -Category 'NIC' `
                -Issue 'NIC has 127.0.0.1 as a DNS server.' `
                -Recommendation 'Microsoft recommends NOT using 127.0.0.1 as a primary DNS server on a DC. Use the DC own external IP or another DC.'
        }
        if ($usesSelf -and $allDCs.Count -gt 1) {
            Add-Finding -Severity High -Target $hn -Domain $dc.Domain -Category 'NIC' `
                -Issue 'DC points only to itself for DNS (DNS island risk).' `
                -Recommendation 'Best practice: primary DNS = a partner DC, secondary = this DC. Avoids the "DNS island" issue.'
        }
        $allDcIps = $allDCs | ForEach-Object { $_.IPv4Address }
        if ($primary -and ($primary -ne '127.0.0.1') -and ($allDcIps -notcontains $primary)) {
            Add-Finding -Severity Medium -Target $hn -Domain $dc.Domain -Category 'NIC' `
                -Issue "Primary DNS ($primary) does not match any DC IP in the forest." `
                -Recommendation 'On a DC, the primary DNS server should normally be another DC in the same forest.'
        }
        if (-not $secondary -and $allDCs.Count -gt 1) {
            Add-Finding -Severity Medium -Target $hn -Domain $dc.Domain -Category 'NIC' `
                -Issue 'Only one DNS server configured.' `
                -Recommendation 'Configure a Secondary DNS server (another DC) for resilience.'
        }
        if ($register -eq $false) {
            Add-Finding -Severity Low -Target $hn -Domain $dc.Domain -Category 'NIC' `
                -Issue 'Register This Connection in DNS is disabled.' `
                -Recommendation 'Enable dynamic registration unless this NIC is intentionally manually registered.'
        }
    } catch {
        Add-Finding -Severity Medium -Target $hn -Domain $dc.Domain -Category 'NIC' `
            -Issue "Could not collect NIC configuration: $($_.Exception.Message)" `
            -Recommendation 'Verify CIM/WMI connectivity (DCOM-In + WMI-In firewall rules).'
    }

    # ---- DNS server settings ------------------------------------------
    try {
        $srv = Get-DnsServerSetting -ComputerName $hn -All -ErrorAction Stop
        $row.Recursion   = ($srv.NoRecursion -eq $false)
        $row.EDNSEnabled = $srv.EnableEDnsProbes
        if ($srv.NoRecursion -eq $false) {
            Add-Finding -Severity Info -Target $hn -Domain $dc.Domain -Category 'DNS Settings' `
                -Issue 'Recursion is enabled.' `
                -Recommendation 'Acceptable for internal AD DNS. If this DC is reachable from the internet, disable recursion to mitigate amplification attacks.'
        }
    } catch {
        Add-Finding -Severity Low -Target $hn -Domain $dc.Domain -Category 'DNS Settings' `
            -Issue "Could not query DNS server settings: $($_.Exception.Message)" `
            -Recommendation 'Verify DnsServer module (RSAT-DNS-Server) and reachability.'
    }

    # ---- Forwarders ---------------------------------------------------
    try {
        $fw = Get-DnsServerForwarder -ComputerName $hn -ErrorAction Stop
        if ($fw -and $fw.IPAddress) {
            $row.ForwardersList = ($fw.IPAddress -join ', ')
            foreach ($ipObj in $fw.IPAddress) {
                $ipStr = $ipObj.ToString()
                $reachable = $false
                try {
                    $reachable = (Test-Connection -ComputerName $ipStr -Count 1 -Quiet -ErrorAction SilentlyContinue) `
                                  -or ((Test-NetConnection -ComputerName $ipStr -Port 53 -WarningAction SilentlyContinue).TcpTestSucceeded)
                } catch { $reachable = $false }

                $resolves = $false
                try {
                    $r = Resolve-DnsName -Server $ipStr -Name 'microsoft.com' -Type A -DnsOnly -ErrorAction Stop
                    $resolves = ($null -ne $r)
                } catch { $resolves = $false }

                $approvedFlag = if ($ApprovedForwarders -and $ApprovedForwarders.Count -gt 0) {
                    if ($ApprovedForwarders -contains $ipStr) { 'Yes' } else { 'NO' }
                } else { 'n/a' }

                $script:Forwarders.Add([pscustomobject]@{
                    DC             = $hn
                    Forwarder      = $ipStr
                    Reachable      = $reachable
                    Resolves       = $resolves
                    OnApprovedList = $approvedFlag
                })
                if (-not $reachable) {
                    Add-Finding -Severity High -Target $hn -Domain $dc.Domain -Category 'Forwarders' `
                        -Issue "Forwarder $ipStr is not reachable on TCP/53." `
                        -Recommendation 'Verify the upstream resolver is online and that firewall rules permit DNS to it.'
                }
                if (-not $resolves) {
                    Add-Finding -Severity High -Target $hn -Domain $dc.Domain -Category 'Forwarders' `
                        -Issue "Forwarder $ipStr did not resolve a public test query." `
                        -Recommendation 'Confirm the forwarder is a recursive resolver and is functioning.'
                }
                if ($approvedFlag -eq 'NO') {
                    Add-Finding -Severity Medium -Target $hn -Domain $dc.Domain -Category 'Forwarders' `
                        -Issue "Forwarder $ipStr is not on the approved list." `
                        -Recommendation 'Update -ApprovedForwarders, change the forwarder, or document the exception.'
                }
            }
        } else {
            Add-Finding -Severity Low -Target $hn -Domain $dc.Domain -Category 'Forwarders' `
                -Issue 'No forwarders configured.' `
                -Recommendation 'For internet name resolution, configure at least one trusted upstream forwarder (or rely on root hints if intentional).'
        }
    } catch {
        Add-Finding -Severity Low -Target $hn -Domain $dc.Domain -Category 'Forwarders' `
            -Issue "Could not query forwarders: $($_.Exception.Message)" `
            -Recommendation 'Confirm the DnsServer module is available and the account has rights.'
    }

    # ---- Scavenging ---------------------------------------------------
    try {
        $sc = Get-DnsServerScavenging -ComputerName $hn -ErrorAction Stop
        $row.ScavengingEnabled  = $sc.ScavengingState
        $row.ScavengingInterval = $sc.ScavengingInterval
        if (-not $sc.ScavengingState) {
            Add-Finding -Severity Medium -Target $hn -Domain $dc.Domain -Category 'Scavenging' `
                -Issue 'Server-level scavenging is DISABLED.' `
                -Recommendation 'Enable scavenging on at least one DC (typically the PDC Emulator). Example: Set-DnsServerScavenging -ScavengingState $true -ScavengingInterval 7.00:00:00 -ApplyOnAllZones'
        }
    } catch {
        Add-Finding -Severity Low -Target $hn -Domain $dc.Domain -Category 'Scavenging' `
            -Issue "Could not query scavenging settings: $($_.Exception.Message)" `
            -Recommendation 'Verify DnsServer module availability.'
    }

    # ---- Zones --------------------------------------------------------
    try {
        $zones = Get-DnsServerZone -ComputerName $hn -ErrorAction Stop
        foreach ($z in $zones) {
            $type = if     ($z.IsDsIntegrated)             { 'AD-Integrated' }
                    elseif ($z.ZoneType -eq 'Primary')     { 'Primary' }
                    elseif ($z.ZoneType -eq 'Secondary')   { 'Secondary' }
                    elseif ($z.ZoneType -eq 'Stub')        { 'Stub' }
                    else                                    { $z.ZoneType.ToString() }
            switch ($type) {
                'Primary'       { $row.ZonesPrimary++ }
                'Secondary'     { $row.ZonesSecondary++ }
                'AD-Integrated' { $row.ZonesADIntegrated++ }
                'Stub'          { $row.ZonesStub++ }
            }

            $script:ZoneData.Add([pscustomobject]@{
                DC                = $hn
                Zone              = $z.ZoneName
                Type              = $type
                ZoneType          = $z.ZoneType.ToString()
                Reverse           = $z.IsReverseLookupZone
                Aging             = $z.IsAgingEnabled
                DynamicUpdate     = $z.DynamicUpdate.ToString()
                NoRefreshInterval = $z.NoRefreshInterval
                RefreshInterval   = $z.RefreshInterval
                ReplicationScope  = $z.ReplicationScope
                IsDsIntegrated    = $z.IsDsIntegrated
            })

            if ($z.IsDsIntegrated -and $z.DynamicUpdate -ne 'Secure') {
                Add-Finding -Severity High -Target "$hn :: $($z.ZoneName)" -Domain $dc.Domain -Category 'Zone Security' `
                    -Issue "AD-integrated zone $($z.ZoneName) accepts $($z.DynamicUpdate) dynamic updates." `
                    -Recommendation 'AD-integrated zones should accept Secure dynamic updates only: Set-DnsServerPrimaryZone -Name <zone> -DynamicUpdate Secure'
            }
            if ($z.ZoneType -eq 'Primary' -and -not $z.IsAgingEnabled) {
                Add-Finding -Severity Low -Target "$hn :: $($z.ZoneName)" -Domain $dc.Domain -Category 'Scavenging' `
                    -Issue "Aging is NOT enabled on zone $($z.ZoneName)." `
                    -Recommendation "Enable aging: Set-DnsServerZoneAging -Name $($z.ZoneName) -Aging `$true -ComputerName $hn"
            }
        }
    } catch {
        Add-Finding -Severity Medium -Target $hn -Domain $dc.Domain -Category 'Zones' `
            -Issue "Could not enumerate DNS zones: $($_.Exception.Message)" `
            -Recommendation 'Verify the DC is reachable and the running account has DNS Admin (read) rights.'
    }

    if ($cim) { Remove-CimSession -CimSession $cim -ErrorAction SilentlyContinue }
    $script:DCResults.Add([pscustomobject]$row)
}

#endregion

#region ---------- Forward / reverse record analysis ------------------------

Write-Section 'Auditing forward and reverse zone records'

$aRecords   = @{}
$ptrRecords = @{}

# Pick one DC per zone to query records
$forwardZonesSeen = @{}
$reverseZonesSeen = @{}
foreach ($z in $script:ZoneData) {
    if ($z.Type -eq 'Stub' -or $z.Type -eq 'Secondary') { continue }
    if (-not $z.Reverse -and -not $forwardZonesSeen.ContainsKey($z.Zone)) {
        $forwardZonesSeen[$z.Zone] = $z.DC
    } elseif ($z.Reverse -and -not $reverseZonesSeen.ContainsKey($z.Zone)) {
        $reverseZonesSeen[$z.Zone] = $z.DC
    }
}

# Pull A records from forward zones
foreach ($zone in $forwardZonesSeen.Keys) {
    $dc = $forwardZonesSeen[$zone]
    try {
        $rrs = Get-DnsServerResourceRecord -ComputerName $dc -ZoneName $zone -RRType A -ErrorAction Stop |
               Select-Object -First $MaxRecordsPerZone
        foreach ($r in $rrs) {
            if ($null -eq $r.RecordData -or $null -eq $r.RecordData.IPv4Address) { continue }
            $ip   = $r.RecordData.IPv4Address.IPAddressToString
            $name = if ($r.HostName -eq '@') { $zone } else { "$($r.HostName).$zone" }
            if (-not $aRecords.ContainsKey($ip)) { $aRecords[$ip] = New-Object System.Collections.Generic.List[object] }
            $aRecords[$ip].Add([pscustomobject]@{ Host=$name; Zone=$zone; DC=$dc })
        }
    } catch {
        Add-Finding -Severity Low -Target $zone -Domain $dc -Category 'Records' `
            -Issue "Could not pull A records: $($_.Exception.Message)" `
            -Recommendation 'Verify zone availability and DnsServer rights.'
    }
}

# Pull PTR records from reverse zones
foreach ($zone in $reverseZonesSeen.Keys) {
    $dc = $reverseZonesSeen[$zone]
    try {
        $rrs = Get-DnsServerResourceRecord -ComputerName $dc -ZoneName $zone -RRType Ptr -ErrorAction Stop |
               Select-Object -First $MaxRecordsPerZone
        foreach ($r in $rrs) {
            $ip = ConvertFrom-PTRName -ownerName $r.HostName -zoneName $zone
            if (-not $ip) { continue }
            $tgt = $r.RecordData.PtrDomainName.TrimEnd('.')
            if (-not $ptrRecords.ContainsKey($ip)) { $ptrRecords[$ip] = New-Object System.Collections.Generic.List[object] }
            $ptrRecords[$ip].Add([pscustomobject]@{ TargetHost=$tgt; Zone=$zone; DC=$dc })
        }
    } catch {
        Add-Finding -Severity Low -Target $zone -Domain $dc -Category 'Records' `
            -Issue "Could not pull PTR records: $($_.Exception.Message)" `
            -Recommendation 'Verify zone availability and DnsServer rights.'
    }
}

# Reverse zones exist for every subnet referenced by an A record
$existingReverseZones = $reverseZonesSeen.Keys
$subnetsSeen = @{}
foreach ($ip in $aRecords.Keys) {
    $rev = ConvertTo-ReverseZone $ip
    if ($rev -and -not $subnetsSeen.ContainsKey($rev)) {
        $subnetsSeen[$rev] = $true
        $covered = $false
        foreach ($exist in $existingReverseZones) {
            if ($rev -eq $exist) { $covered = $true; break }
            if ($rev.EndsWith('.' + $exist)) { $covered = $true; break }   # /16, /8 parent
        }
        if (-not $covered) {
            $sampleHosts = ($aRecords[$ip] | Select-Object -First 3 -ExpandProperty Host) -join ', '
            $netParts = $ip.Split('.')
            Add-Finding -Severity Medium -Target $rev -Domain $forest.Name -Category 'Reverse Zones' `
                -Issue "No reverse zone found for $rev (sample IP $ip used by: $sampleHosts)." `
                -Recommendation "Create the reverse zone: Add-DnsServerPrimaryZone -NetworkID $($netParts[0]).$($netParts[1]).$($netParts[2]).0/24 -ReplicationScope Domain"
        }
    }
}

# Every A record has a matching PTR
foreach ($ip in $aRecords.Keys) {
    if (-not $ptrRecords.ContainsKey($ip)) {
        $sampleHosts = ($aRecords[$ip] | Select-Object -First 3 -ExpandProperty Host) -join ', '
        $script:Orphans.Add([pscustomobject]@{
            IP     = $ip
            Type   = 'Missing PTR'
            Detail = "A record(s) exist ($sampleHosts) but no PTR record."
        })
        Add-Finding -Severity Low -Target $ip -Domain $forest.Name -Category 'PTR Coverage' `
            -Issue "No PTR record for $ip (forward host: $sampleHosts)." `
            -Recommendation 'Create the PTR record or enable dynamic updates so clients self-register.'
    }
}

# Every PTR record points back to an A record (PTR maps back to forward)
foreach ($ip in $ptrRecords.Keys) {
    foreach ($p in $ptrRecords[$ip]) {
        $matches = $false
        if ($aRecords.ContainsKey($ip)) {
            $matches = ($aRecords[$ip] | Where-Object { $_.Host.TrimEnd('.').ToLower() -eq $p.TargetHost.ToLower() }).Count -gt 0
        }
        if (-not $matches) {
            $script:Orphans.Add([pscustomobject]@{
                IP     = $ip
                Type   = 'PTR no match'
                Detail = "PTR -> $($p.TargetHost) but no matching A in any forward zone."
            })
            Add-Finding -Severity Low -Target $ip -Domain $forest.Name -Category 'PTR Mismatch' `
                -Issue "PTR for $ip points to $($p.TargetHost) but there is no matching A record." `
                -Recommendation 'Either remove the stale PTR or create the A record.'
        }
    }
}

# Duplicate IPs in PTR (same IP -> multiple host names)
foreach ($ip in $ptrRecords.Keys) {
    $unique = $ptrRecords[$ip] | Select-Object -ExpandProperty TargetHost -Unique
    if ($unique.Count -gt 1) {
        $allHosts = ($ptrRecords[$ip] | Select-Object -ExpandProperty TargetHost) -join ', '
        $script:DupRecs.Add([pscustomobject]@{
            IP    = $ip
            Hosts = $allHosts
            Count = $unique.Count
        })
        Add-Finding -Severity High -Target $ip -Domain $forest.Name -Category 'Duplicate PTR' `
            -Issue "IP $ip has multiple PTR targets: $allHosts" `
            -Recommendation 'Multiple PTRs for the same IP cause unpredictable reverse-resolution. Remove all but the authoritative record.'
    }
}

# Same hostname -> multiple IPs (informational)
$hostToIp = @{}
foreach ($ip in $aRecords.Keys) {
    foreach ($a in $aRecords[$ip]) {
        $h = $a.Host.ToLower()
        if (-not $hostToIp.ContainsKey($h)) { $hostToIp[$h] = New-Object System.Collections.Generic.List[string] }
        [void]$hostToIp[$h].Add($ip)
    }
}
foreach ($h in $hostToIp.Keys) {
    if ($hostToIp[$h].Count -gt 1) {
        Add-Finding -Severity Info -Target $h -Domain $forest.Name -Category 'Duplicate A' `
            -Issue "$h has multiple A records: $($hostToIp[$h] -join ', ')" `
            -Recommendation 'Round-robin or stale records? Confirm intentional. Remove stale entries to keep forward lookup deterministic.'
    }
}

#endregion

#region ---------- Build HTML email body ------------------------------------

Write-Section 'Building email body'

$css = @'
<style>
  body { font-family: "Arial"; font-size: 7pt; }
  th, td, tr { border: 1px solid #A4A4A4; border-collapse: collapse; padding: 8px; text-align: center; }
  th { font-size: 8pt; text-align: center; background-color: #0B2161; color: #EFF2FB; }
  td { color: #000000; }
  h2 { color: #0B2161; }
  h4 { color: #0B2161; margin-bottom: 4px; }
  h5 { color: #555555; }
  .sev-Critical { background-color: #FF6B6B; color: #FFFFFF; font-weight: bold; }
  .sev-High     { background-color: #FFB347; }
  .sev-Medium   { background-color: #FFE066; }
  .sev-Low      { background-color: #B5EAD7; }
  .sev-Info     { background-color: #E6E6E6; color: #555555; }
  .ok           { background-color: #B5EAD7; }
  .fail         { background-color: #FF6B6B; color: #FFFFFF; font-weight:bold; }
</style>
'@

# DC NIC + DNS table
$dcRows = foreach ($r in ($script:DCResults | Sort-Object Domain, DC)) {
    $svcCell  = if ($r.DNSServiceState -eq 'Running') { "<td class=`"ok`">Running</td>" }
                else { "<td class=`"fail`">$($r.DNSServiceState)</td>" }
    $selfCell = if ($r.UsesSelfOnlyAsDns) { "<td class=`"fail`">YES</td>" } else { "<td class=`"ok`">No</td>" }
    $loopCell = if ($r.UsesLoopbackAsDns) { "<td class=`"fail`">YES</td>" } else { "<td class=`"ok`">No</td>" }

    "<tr><td>$(HtmlEnc $r.DC)</td><td>$(HtmlEnc $r.Domain)</td><td>$(HtmlEnc $r.IP)</td>" +
    "$svcCell" +
    "<td>$(HtmlEnc $r.PrimaryDNS)</td><td>$(HtmlEnc $r.SecondaryDNS)</td>" +
    "<td style=`"text-align:left`">$(HtmlEnc $r.AdditionalDNS)</td>" +
    "<td>$(HtmlEnc $r.DnsSuffix)</td>" +
    "<td style=`"text-align:left`">$(HtmlEnc $r.DnsSuffixSearchList)</td>" +
    "<td>$(HtmlEnc $r.RegisterThisConnection)</td>" +
    "$selfCell$loopCell</tr>"
}
$dcHdr = '<th>DC</th><th>Domain</th><th>DC IP</th><th>DNS Svc</th><th>Primary DNS</th><th>Secondary DNS</th><th>Additional DNS</th><th>Suffix</th><th>Search List</th><th>Register</th><th>Self-Only</th><th>127.0.0.1</th>'
$dcTable = "<h4>Domain Controller NIC / DNS Configuration</h4><table><tr>$dcHdr</tr>$($dcRows -join "`n")</table><p>"

# Zones table
$zoneRows = foreach ($z in ($script:ZoneData | Sort-Object DC, Zone)) {
    $aging = if ($z.Aging) { 'Yes' } else { 'No' }
    "<tr><td>$(HtmlEnc $z.DC)</td><td style=`"text-align:left`">$(HtmlEnc $z.Zone)</td>" +
    "<td>$(HtmlEnc $z.Type)</td><td>$(if ($z.Reverse){'Yes'}else{'No'})</td>" +
    "<td>$(HtmlEnc $z.DynamicUpdate)</td><td>$aging</td>" +
    "<td>$(HtmlEnc $z.NoRefreshInterval)</td><td>$(HtmlEnc $z.RefreshInterval)</td>" +
    "<td>$(HtmlEnc $z.ReplicationScope)</td></tr>"
}
$zHdr = '<th>DC</th><th>Zone</th><th>Type</th><th>Reverse</th><th>Dynamic Update</th><th>Aging</th><th>NoRefresh</th><th>Refresh</th><th>Replication Scope</th>'
$zoneTable = "<h4>DNS Zones (Primary / Secondary / AD-Integrated / Stub)</h4><table><tr>$zHdr</tr>$($zoneRows -join "`n")</table><p>"

# Forwarders table
$fwRows = foreach ($f in ($script:Forwarders | Sort-Object DC, Forwarder)) {
    $rCell = if ($f.Reachable) { "<td class=`"ok`">Yes</td>" } else { "<td class=`"fail`">No</td>" }
    $sCell = if ($f.Resolves)  { "<td class=`"ok`">Yes</td>" } else { "<td class=`"fail`">No</td>" }
    "<tr><td>$(HtmlEnc $f.DC)</td><td>$(HtmlEnc $f.Forwarder)</td>$rCell$sCell<td>$(HtmlEnc $f.OnApprovedList)</td></tr>"
}
$fwHdr = '<th>DC</th><th>Forwarder</th><th>Reachable (TCP/53)</th><th>Resolves Test Query</th><th>On Approved List</th>'
$fwTable = if ($fwRows) {
    "<h4>Forwarders</h4><table><tr>$fwHdr</tr>$($fwRows -join "`n")</table><p>"
} else {
    "<h4>Forwarders</h4><p>No forwarders configured on any DC.</p>"
}

# Duplicate IPs table
$dupTable = if ($script:DupRecs.Count -gt 0) {
    $rows = foreach ($d in ($script:DupRecs | Sort-Object IP)) {
        "<tr class=`"sev-High`"><td>$(HtmlEnc $d.IP)</td><td>$($d.Count)</td><td style=`"text-align:left`">$(HtmlEnc $d.Hosts)</td></tr>"
    }
    "<h4>Duplicate IP -> Multiple PTR Targets</h4><table><tr><th>IP</th><th>Count</th><th>Targets</th></tr>$($rows -join "`n")</table><p>"
} else { '' }

# Orphan / mismatch table (top 200)
$orphanTable = if ($script:Orphans.Count -gt 0) {
    $rows = foreach ($o in ($script:Orphans | Sort-Object Type, IP | Select-Object -First 200)) {
        "<tr><td>$(HtmlEnc $o.IP)</td><td>$(HtmlEnc $o.Type)</td><td style=`"text-align:left`">$(HtmlEnc $o.Detail)</td></tr>"
    }
    $more = if ($script:Orphans.Count -gt 200) {
        "<p style=`"font-size:7pt;`"><i>Showing first 200 of $($script:Orphans.Count) - full list in CSV.</i></p>"
    } else { '' }
    "<h4>PTR Coverage / Mismatch Issues</h4>$more<table><tr><th>IP</th><th>Type</th><th>Detail</th></tr>$($rows -join "`n")</table><p>"
} else { '' }

# Findings table
$severityOrder = @{ 'Critical'=0; 'High'=1; 'Medium'=2; 'Low'=3; 'Info'=4 }
$findingsSorted = $script:Findings | Sort-Object @{e={$severityOrder[$_.Severity]}}, Domain, Target
$findRows = foreach ($f in $findingsSorted) {
    "<tr class=`"sev-$($f.Severity)`"><td>$($f.Severity)</td>" +
    "<td>$(HtmlEnc $f.Domain)</td><td>$(HtmlEnc $f.Target)</td>" +
    "<td>$(HtmlEnc $f.Category)</td><td style=`"text-align:left`">$(HtmlEnc $f.Issue)</td>" +
    "<td style=`"text-align:left`">$(HtmlEnc $f.Recommendation)</td></tr>"
}
$findingsTable = if ($findRows) {
    "<h4>Health Findings and Recommendations</h4><table><tr><th>Severity</th><th>Domain</th><th>Target</th><th>Category</th><th>Issue</th><th>Recommendation</th></tr>$($findRows -join "`n")</table><p>"
} else {
    "<h4>Health Findings and Recommendations</h4><p>No issues detected.</p>"
}

# Severity ribbon
$counts = $findingsSorted | Group-Object Severity
$summaryLine = ($counts | ForEach-Object { "<b>$($_.Name):</b> $($_.Count)" }) -join ' &nbsp; '
if (-not $summaryLine) { $summaryLine = 'No findings.' }

# Run footer
$now = Get-Date
$duration = $now - $script:RunContext.StartTime
$runFooter = @"
<table style="border:1px solid #A4A4A4; font-size:7pt; width:100%; margin-top:8px;">
  <tr><th colspan="2" style="text-align:left; padding:6px;">Run Context</th></tr>
  <tr><td style="text-align:left; width:160px;"><b>Script name</b></td><td style="text-align:left;">$(HtmlEnc $script:RunContext.ScriptName)</td></tr>
  <tr><td style="text-align:left;"><b>Script location</b></td><td style="text-align:left;">$(HtmlEnc $script:RunContext.ScriptPath)</td></tr>
  <tr><td style="text-align:left;"><b>Executed on host</b></td><td style="text-align:left;">$(HtmlEnc $script:RunContext.RunHost)</td></tr>
  <tr><td style="text-align:left;"><b>Executed by</b></td><td style="text-align:left;">$(HtmlEnc $script:RunContext.RunUser)</td></tr>
  <tr><td style="text-align:left;"><b>PowerShell version</b></td><td style="text-align:left;">$(HtmlEnc $script:RunContext.PSVersion)</td></tr>
  <tr><td style="text-align:left;"><b>Started</b></td><td style="text-align:left;">$($script:RunContext.StartTime.ToString('yyyy-MM-dd HH:mm:ss'))</td></tr>
  <tr><td style="text-align:left;"><b>Completed</b></td><td style="text-align:left;">$($now.ToString('yyyy-MM-dd HH:mm:ss'))</td></tr>
  <tr><td style="text-align:left;"><b>Duration</b></td><td style="text-align:left;">$("{0:N0}m {1:N0}s" -f $duration.TotalMinutes, $duration.Seconds)</td></tr>
</table>
"@

$body = @"
<html><head><meta http-equiv="Content-Type" content="text/html; charset=us-ascii">$css</head><body>
<h2>Active Directory DNS Health Check</h2>
<p><b>Forest:</b> $(HtmlEnc $forest.Name) &nbsp; <b>DCs checked:</b> $($script:DCResults.Count)
&nbsp; <b>Zones audited:</b> $($script:ZoneData.Count) &nbsp; <b>Generated:</b> $($now.ToString('yyyy-MM-dd HH:mm:ss'))</p>
<p>$summaryLine</p>
<p>
$dcTable
$zoneTable
$fwTable
$dupTable
$orphanTable
$findingsTable
$runFooter
<h5>Date and time: $($now.ToString('MM/dd/yyyy HH:mm:ss'))</h5>
</body></html>
"@

#endregion

#region ---------- Write reports + email -----------------------------------

if (-not (Test-Path $ReportFolder)) { New-Item -Path $ReportFolder -ItemType Directory -Force | Out-Null }
$htmlPath = Join-Path $ReportFolder "AD_DNS_Health_$timestamp.html"
$csvPath  = Join-Path $ReportFolder "AD_DNS_Health_$timestamp.csv"
$body          | Out-File -FilePath $htmlPath -Encoding UTF8
$findingsSorted | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

$detailAttachments = @()
if ($script:Orphans.Count -gt 0) {
    $orphanCsv = Join-Path $ReportFolder "AD_DNS_PTR_Issues_$timestamp.csv"
    $script:Orphans | Export-Csv -Path $orphanCsv -NoTypeInformation -Encoding UTF8
    $detailAttachments += $orphanCsv
}
if ($script:DupRecs.Count -gt 0) {
    $dupCsv = Join-Path $ReportFolder "AD_DNS_Duplicate_PTR_$timestamp.csv"
    $script:DupRecs | Export-Csv -Path $dupCsv -NoTypeInformation -Encoding UTF8
    $detailAttachments += $dupCsv
}
if ($script:ZoneData.Count -gt 0) {
    $zonesCsv = Join-Path $ReportFolder "AD_DNS_Zones_$timestamp.csv"
    $script:ZoneData | Export-Csv -Path $zonesCsv -NoTypeInformation -Encoding UTF8
    $detailAttachments += $zonesCsv
}
if ($script:Forwarders.Count -gt 0) {
    $fwCsv = Join-Path $ReportFolder "AD_DNS_Forwarders_$timestamp.csv"
    $script:Forwarders | Export-Csv -Path $fwCsv -NoTypeInformation -Encoding UTF8
    $detailAttachments += $fwCsv
}

Write-Host ''
Write-Host "HTML report : $htmlPath"  -ForegroundColor Green
Write-Host "Findings CSV: $csvPath"   -ForegroundColor Green
foreach ($a in $detailAttachments) { Write-Host "Detail CSV  : $a" -ForegroundColor Green }

if (-not $Subject) {
    $Subject = "DNS Health Check - {0} - {1}" -f $now.ToString('MMM-dd'), $forest.Name
}

if ($NoEmail -or -not $SmtpServer -or -not $To) {
    Write-Host ''
    if ($NoEmail) { Write-Host '-NoEmail specified: skipping mail send.' -ForegroundColor Yellow }
    else          { Write-Host 'Email skipped (no -SmtpServer or -To provided).' -ForegroundColor DarkGray }
} else {
    if (-not $From) {
        Write-Warning 'Email skipped: -From parameter is required when -SmtpServer is supplied.'
    } else {
        if (-not $SmtpPort) { $SmtpPort = if ($UseSsl) { 587 } else { 25 } }
        $allAttachments = @($csvPath, $htmlPath) + $detailAttachments
        try {
            $params = @{
                SmtpServer  = $SmtpServer
                Port        = $SmtpPort
                From        = $From
                To          = $To
                Subject     = $Subject
                Body        = $body
                BodyAsHtml  = $true
                Attachments = $allAttachments
                Encoding    = ([System.Text.Encoding]::UTF8)
            }
            if ($Cc)         { $params.Cc = $Cc }
            if ($UseSsl)     { $params.UseSsl = $true }
            if ($Credential) { $params.Credential = $Credential }
            Send-MailMessage @params -WarningAction SilentlyContinue
            Write-Host ''
            Write-Host ("Email sent via {0} to: {1}" -f $SmtpServer, ($To -join ', ')) -ForegroundColor Green
            Write-Host ("Attachments  : {0} file(s)" -f $allAttachments.Count) -ForegroundColor Green
        } catch {
            Write-Warning "Send-MailMessage failed: $($_.Exception.Message). Trying SmtpClient fallback..."
            try {
                $smtp = New-Object System.Net.Mail.SmtpClient($SmtpServer, $SmtpPort)
                $smtp.EnableSsl = [bool]$UseSsl
                if ($Credential) {
                    $smtp.Credentials = New-Object System.Net.NetworkCredential(
                        $Credential.UserName, $Credential.GetNetworkCredential().Password)
                }
                $msg = New-Object System.Net.Mail.MailMessage
                $msg.From = $From
                foreach ($r in $To) { $msg.To.Add($r) }
                if ($Cc) { foreach ($r in $Cc) { $msg.Cc.Add($r) } }
                $msg.Subject = $Subject
                $msg.Body = $body
                $msg.IsBodyHtml = $true
                foreach ($att in $allAttachments) { $msg.Attachments.Add((New-Object System.Net.Mail.Attachment($att))) }
                $smtp.Send($msg)
                $msg.Dispose(); $smtp.Dispose()
                Write-Host ("Email sent (fallback) via {0} to: {1}" -f $SmtpServer, ($To -join ', ')) -ForegroundColor Green
            } catch {
                Write-Host "FAILED to send email: $($_.Exception.Message)" -ForegroundColor Red
                Write-Host "HTML report is still available at: $htmlPath"  -ForegroundColor Yellow
            }
        }
    }
}

# Console summary
Write-Section 'Findings summary'
foreach ($c in ($counts | Sort-Object @{e={$severityOrder[$_.Name]}})) {
    $color = switch ($c.Name) {
        'Critical' { 'Red' } 'High' { 'Magenta' } 'Medium' { 'Yellow' }
        'Low'      { 'Cyan' } default { 'Gray' }
    }
    Write-Host ("  {0,-9} : {1}" -f $c.Name, $c.Count) -ForegroundColor $color
}

$findingsSorted

#endregion
