<#
.SYNOPSIS
    IP Analysis System v1.0 - Security Intelligence Tool
.DESCRIPTION
    Simple and effective IP analysis system with automatic classification
.NOTES
    Version: 1.0
    Author: Abdulaziz Aljoissam
    Date: 2026-01-10
#>

#Requires -Version 5.1

param(
    [string]$InputFile = "",
    [string]$ProjectName = ""
)

# ============================================================================
# GLOBAL VARIABLES
# ============================================================================

$ErrorActionPreference = 'Continue'
$BasePath = $PSScriptRoot
$BlacklistPath = Join-Path $BasePath "IP_Blacklist"
$WhitelistPath = Join-Path $BasePath "IP_Whitelist"
$ProjectsPath = Join-Path $BasePath "Projects"

# Create directories if needed
@($ProjectsPath) | ForEach-Object {
    if (-not (Test-Path $_)) {
        New-Item -ItemType Directory -Path $_ -Force | Out-Null
    }
}

# ============================================================================
# UI FUNCTIONS
# ============================================================================

function Show-Header {
    Clear-Host
    Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                                                              ║" -ForegroundColor Cyan
    Write-Host "║          🛡️  IP ANALYSIS SYSTEM v1.0 🛡️                     ║" -ForegroundColor Cyan
    Write-Host "║                                                              ║" -ForegroundColor Cyan
    Write-Host "║          Abdulaziz Aljoissam - Security Tool                ║" -ForegroundColor Gray
    Write-Host "║                                                              ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

function Show-MainMenu {
    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
    Write-Host "║                        MAIN MENU                               ║" -ForegroundColor Yellow
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  [1] 🚀 Start New Project" -ForegroundColor Green
    Write-Host "  [2] 🗑️  Clean Old Data" -ForegroundColor Yellow
    Write-Host "  [3] 📊 View Statistics" -ForegroundColor Cyan
    Write-Host "  [0] ❌ Exit" -ForegroundColor Red
    Write-Host ""
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Yellow
    Write-Host ""
}

# ============================================================================
# IP EXTRACTION FUNCTIONS
# ============================================================================

function Extract-IPsFromFile {
    param([string]$FilePath)
    
    $ips = @()
    $content = Get-Content $FilePath -ErrorAction SilentlyContinue
    
    foreach ($line in $content) {
        $matches = [regex]::Matches($line, '\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
        foreach ($match in $matches) {
            $ip = $match.Value
            if (Test-ValidIP -IP $ip) {
                $ips += $ip
            }
        }
    }
    
    return ($ips | Select-Object -Unique)
}

function Test-ValidIP {
    param([string]$IP)
    
    if ($IP -notmatch '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
        return $false
    }
    
    $octets = $IP -split '\.'
    foreach ($octet in $octets) {
        $num = [int]$octet
        if ($num -lt 0 -or $num -gt 255) {
            return $false
        }
    }
    
    return $true
}


# ============================================================================
# HIGH-PERFORMANCE IPV4 PARSING / CIDR CACHE
# ============================================================================

function ConvertTo-UInt32IPv4 {
    param([string]$IP)

    if ([string]::IsNullOrWhiteSpace($IP)) { return $null }
    if ($IP.IndexOf(':') -ge 0) { return $null }  # IPv6 (skip safely)

    $parts = $IP.Split('.')
    if ($parts.Count -ne 4) { return $null }

    $a = 0; $b = 0; $c = 0; $d = 0
    if (-not [int]::TryParse($parts[0], [ref]$a)) { return $null }
    if (-not [int]::TryParse($parts[1], [ref]$b)) { return $null }
    if (-not [int]::TryParse($parts[2], [ref]$c)) { return $null }
    if (-not [int]::TryParse($parts[3], [ref]$d)) { return $null }

    if (($a -lt 0 -or $a -gt 255) -or ($b -lt 0 -or $b -gt 255) -or ($c -lt 0 -or $c -gt 255) -or ($d -lt 0 -or $d -gt 255)) {
        return $null
    }

    # IMPORTANT: shift using UInt64 first to avoid Int32 overflow (e.g., 128.x.x.x -> -2147483648)
    $u = (([uint64]$a -shl 24) -bor ([uint64]$b -shl 16) -bor ([uint64]$c -shl 8) -bor [uint64]$d)
    return [uint32]$u
}


function New-CIDRInfo {
    param([string]$CIDR)

    if ([string]::IsNullOrWhiteSpace($CIDR)) { return $null }
    if ($CIDR.IndexOf(':') -ge 0) { return $null } # IPv6 CIDR not supported here

    $slash = $CIDR.IndexOf('/')
    if ($slash -lt 0) { return $null }

    $networkIP = $CIDR.Substring(0, $slash)
    $prefixStr = $CIDR.Substring($slash + 1)

    $prefixLength = 0
    if (-not [int]::TryParse($prefixStr, [ref]$prefixLength)) { return $null }
    if ($prefixLength -lt 0 -or $prefixLength -gt 32) { return $null }

    $networkInt = ConvertTo-UInt32IPv4 -IP $networkIP
    if ($null -eq $networkInt) { return $null }

    $mask = [uint32]0
    if ($prefixLength -eq 0) {
        $mask = [uint32]0
    }
    else {
        $mask = [uint32]((([uint64]0xFFFFFFFF) -shl (32 - $prefixLength)) -band 0xFFFFFFFF)
    }

    $networkMasked = ([uint32]$networkInt -band $mask)

    return [PSCustomObject]@{
        CIDR = $CIDR
        PrefixLength = [int]$prefixLength
        Mask = $mask
        NetworkMasked = $networkMasked
    }
}
# ============================================================================
# RULES LOADING FUNCTIONS (TWO-STAGE VERIFICATION OPTIMIZED)
# ============================================================================


function Load-Rules {
    param(
        [string]$Path,
        [string]$Type
    )

    # Two-Stage Verification Data Structure (memory-safe / high-performance)
    # NOTE: PrefixIndex is now a SET of prefixes (keys only) to avoid duplicating all IP strings in memory.
    $rules = @{
        IPs       = @{}   # Exact IP lookup (O(1)) - keys are IPv4 strings
        CIDRs     = @()   # Array of CIDR strings (for reporting/compat)
        PrefixIndex = @{} # Stage 1: Prefix set (1/2/3 octets) -> $true
        SubnetMap = @{}   # Stage 2: Prefix -> List[CIDR string]
        CIDRInfo  = @{}   # CIDR string -> cached mask/network (bitwise)
    }

    if (-not (Test-Path $Path)) {
        return $rules
    }

    $files = Get-ChildItem -Path $Path -File -ErrorAction SilentlyContinue
    $fileCount = $files.Count

    if ($fileCount -eq 0) {
        return $rules
    }

    Write-Host "   Loading $fileCount files with Two-Stage indexing..." -ForegroundColor Gray

    $current = 0
    $ipCount = 0
    $cidrCount = 0

    # De-dupe CIDRs without O(n) array scans
    $cidrSeen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $cidrList = New-Object 'System.Collections.Generic.List[string]'

    foreach ($file in $files) {
        $current++

        # Skip very large files (>50MB) for speed
        if ($file.Length -gt 50MB) {
            Write-Host "   ⚠️  Skipping large file: $($file.Name) ($([math]::Round($file.Length/1MB, 1))MB)" -ForegroundColor Yellow
            continue
        }

        # Show progress every 10 files
        if ($current % 10 -eq 0 -or $current -eq $fileCount) {
            Write-Host "   Processing: $current/$fileCount files ($ipCount IPs, $cidrCount CIDRs)" -ForegroundColor Gray
        }

        try {
            # Read file in one go (fast)
            $content = [System.IO.File]::ReadAllText($file.FullName)

            # Extract IPv4 IPs (plain)
            $ipMatches = [regex]::Matches($content, '\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
            foreach ($match in $ipMatches) {
                $ip = $match.Value
                if (-not (Test-ValidIP -IP $ip)) { continue }

                if (-not $rules.IPs.ContainsKey($ip)) {
                    $rules.IPs[$ip] = $true
                    $ipCount++

                    # PrefixIndex SET (1/2/3 octets) - Stage 1 trigger
                    $d1 = $ip.IndexOf('.'); if ($d1 -lt 0) { continue }
                    $d2 = $ip.IndexOf('.', $d1 + 1); if ($d2 -lt 0) { continue }
                    $d3 = $ip.IndexOf('.', $d2 + 1); if ($d3 -lt 0) { continue }

                    $rules.PrefixIndex[$ip.Substring(0, $d1)] = $true
                    $rules.PrefixIndex[$ip.Substring(0, $d2)] = $true
                    $rules.PrefixIndex[$ip.Substring(0, $d3)] = $true
                }
            }

            # Extract CIDRs
            $cidrMatches = [regex]::Matches($content, '\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,2})\b')
            foreach ($match in $cidrMatches) {
                $cidr = $match.Value

                if (-not $cidrSeen.Add($cidr)) { continue }  # already processed

                $cidrInfo = New-CIDRInfo -CIDR $cidr
                if ($null -eq $cidrInfo) { continue }

                $rules.CIDRInfo[$cidr] = $cidrInfo
                $cidrList.Add($cidr) | Out-Null
                $cidrCount++

                # Build SubnetMap (Stage 2 candidate source) + PrefixIndex (Stage 1 trigger)
                $networkIP = $cidr.Split('/')[0]

                $d1 = $networkIP.IndexOf('.'); if ($d1 -lt 0) { continue }
                $d2 = $networkIP.IndexOf('.', $d1 + 1); if ($d2 -lt 0) { continue }
                $d3 = $networkIP.IndexOf('.', $d2 + 1); if ($d3 -lt 0) { continue }

                $prefix8  = $networkIP.Substring(0, $d1)
                $prefix16 = $networkIP.Substring(0, $d2)
                $prefix24 = $networkIP.Substring(0, $d3)

                foreach ($prefix in @($prefix24, $prefix16, $prefix8)) {
                    # Stage 1 trigger set
                    $rules.PrefixIndex[$prefix] = $true

                    # Stage 2 candidate map
                    if (-not $rules.SubnetMap.ContainsKey($prefix)) {
                        $rules.SubnetMap[$prefix] = New-Object 'System.Collections.Generic.List[string]'
                    }
                    $rules.SubnetMap[$prefix].Add($cidr) | Out-Null
                }
            }
        }
        catch {
            Write-Host "   ⚠️  Error reading: $($file.Name)" -ForegroundColor Yellow
            continue
        }
    }

    $rules.CIDRs = $cidrList.ToArray()

    Write-Host "   ✓ Loaded: $ipCount IPs, $cidrCount CIDRs" -ForegroundColor Green
    Write-Host "   ✓ Indexed: $($rules.PrefixIndex.Count) prefixes (set), $($rules.SubnetMap.Count) subnet prefixes" -ForegroundColor Cyan

    return $rules
}


# ============================================================================
# TWO-STAGE VERIFICATION FUNCTIONS
# ============================================================================

<#
.SYNOPSIS
    Gets IP prefix for indexing (e.g., "192.168.1" from "192.168.1.100")
#>
function Get-IPPrefix {
    param(
        [string]$IP,
        [int]$OctetCount = 3
    )
    
    $octets = $IP -split '\.'
    return ($octets[0..($OctetCount-1)] -join '.')
}

<#
.SYNOPSIS
    Two-Stage IP Verification - Ultra-fast matching for 600k+ records
    Stage 1: Partial Match (Prefix-based filter)
    Stage 2: Full Validation (Exact verification)
#>

function Test-IPInList-TwoStage {
    param(
        [string]$IP,
        [hashtable]$IPList,
        [object]$CIDRList,
        [hashtable]$PrefixIndex,
        [hashtable]$SubnetMap,
        [hashtable]$CIDRInfo = $null,
        [object]$IPInt = $null
    )

    # IPv6 safety (skip without throwing)
    if ([string]::IsNullOrWhiteSpace($IP)) {
        return @{ Found = $false; MatchType = "NONE"; Details = "Empty IP" }
    }
    if ($IP.IndexOf(':') -ge 0) {
        return @{ Found = $false; MatchType = "SKIP_IPV6"; Details = "IPv6 skipped" }
    }

    # Fastest path: exact IP lookup
    if ($IPList -and $IPList.ContainsKey($IP)) {
        return @{ Found = $true; MatchType = "EXACT_IP"; Details = "Direct match in IP list" }
    }

    # Quick sanity (prevents split/substring exceptions on malformed values)
    if (-not (Test-ValidIP -IP $IP)) {
        return @{ Found = $false; MatchType = "INVALID"; Details = "Invalid IPv4" }
    }

    # Build prefixes (1/2/3 octets) using dot positions (less allocation than -split)
    $d1 = $IP.IndexOf('.')
    $d2 = $IP.IndexOf('.', $d1 + 1)
    $d3 = $IP.IndexOf('.', $d2 + 1)
    if ($d1 -lt 0 -or $d2 -lt 0 -or $d3 -lt 0) {
        return @{ Found = $false; MatchType = "INVALID"; Details = "Invalid IPv4 format" }
    }

    $prefix8  = $IP.Substring(0, $d1)
    $prefix16 = $IP.Substring(0, $d2)
    $prefix24 = $IP.Substring(0, $d3)

    # ========================================================================
    # STAGE 1: PARTIAL MATCH (THE TRIGGER) - MUST CHECK PrefixIndex FIRST
    # ========================================================================
    $hasSimilarity = $false
    if ($PrefixIndex) {
        if ($PrefixIndex.ContainsKey($prefix24) -or $PrefixIndex.ContainsKey($prefix16) -or $PrefixIndex.ContainsKey($prefix8)) {
            $hasSimilarity = $true
        }
    }

    if (-not $hasSimilarity) {
        return @{ Found = $false; MatchType = "NONE"; Details = "No prefix similarity found" }
    }

    # ========================================================================
    # STAGE 2: FULL CIDR VALIDATION (THE CONFIRMATION) - SubnetMap + bitwise
    # ========================================================================
    if (-not $SubnetMap) {
        return @{ Found = $false; MatchType = "NONE"; Details = "Prefix similarity found but no SubnetMap available" }
    }

        # Fast pre-check: if SubnetMap has no candidate buckets for these prefixes, skip conversion
    $hasCandidates = $false
    foreach ($p in @($prefix24, $prefix16, $prefix8)) {
        if ($SubnetMap.ContainsKey($p) -and $SubnetMap[$p].Count -gt 0) { $hasCandidates = $true; break }
    }
    if (-not $hasCandidates) {
        return @{ Found = $false; MatchType = "NONE"; Details = "Prefix similarity found but no CIDR candidates" }
    }

# Convert IP once (UInt32) for all CIDR checks
    $ipUInt32 = $null
    if ($null -ne $IPInt) {
        try { $ipUInt32 = [uint32]$IPInt } catch { $ipUInt32 = $null }
    }
    if ($null -eq $ipUInt32) {
        $ipUInt32 = ConvertTo-UInt32IPv4 -IP $IP
    }
    if ($null -eq $ipUInt32) {
        return @{ Found = $false; MatchType = "INVALID"; Details = "IPv4 conversion failed" }
    }

    # Deduplicate candidate CIDRs without pipelines (fast)
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)

    foreach ($p in @($prefix24, $prefix16, $prefix8)) {
        if (-not $SubnetMap.ContainsKey($p)) { continue }

        foreach ($cidr in $SubnetMap[$p]) {
            if (-not $seen.Add($cidr)) { continue }

            $info = $null
            if ($CIDRInfo -and $CIDRInfo.ContainsKey($cidr)) {
                $info = $CIDRInfo[$cidr]
            }
            else {
                if (-not $script:__CIDRInfoCache) { $script:__CIDRInfoCache = @{} }
                if ($script:__CIDRInfoCache.ContainsKey($cidr)) {
                    $info = $script:__CIDRInfoCache[$cidr]
                }
                else {
                    $info = New-CIDRInfo -CIDR $cidr
                    if ($null -ne $info) { $script:__CIDRInfoCache[$cidr] = $info }
                }
            }

            if ($null -eq $info) { continue }

            if (([uint32]$ipUInt32 -band [uint32]$info.Mask) -eq [uint32]$info.NetworkMasked) {
                return @{
                    Found = $true
                    MatchType = "CIDR_MATCH"
                    Details = "Matched CIDR: $($info.CIDR)"
                    CIDR = $info.CIDR
                }
            }
        }
    }

    return @{ Found = $false; MatchType = "NONE"; Details = "Prefix similarity found but CIDR validation failed" }
}


# ============================================================================
# VERIFICATION FUNCTIONS
# ============================================================================


function Test-IPInList {
    param(
        [string]$IP,
        [hashtable]$IPList,
        [array]$CIDRList,
        [hashtable]$PrefixIndex = $null,
        [hashtable]$SubnetMap = $null,
        [hashtable]$CIDRInfo = $null,
        [object]$IPInt = $null
    )
    
    # Use Two-Stage Verification if indexes are available
    if ($PrefixIndex -and $SubnetMap) {
        $result = Test-IPInList-TwoStage -IP $IP -IPList $IPList -CIDRList $CIDRList -PrefixIndex $PrefixIndex -SubnetMap $SubnetMap -CIDRInfo $CIDRInfo -IPInt $IPInt
        return $result.Found
    }
    
    # Fallback to legacy method if indexes not available
    if ($IPList -and $IPList.ContainsKey($IP)) {
        return $true
    }
    
    foreach ($cidr in $CIDRList) {
        if (Test-IPInCIDR -IP $IP -CIDR $cidr -CIDRInfo $CIDRInfo -IPInt $IPInt) {
            return $true
        }
    }
    
    return $false
}


function Test-IPInCIDR {
    param(
        [string]$IP,
        [string]$CIDR,
        [hashtable]$CIDRInfo = $null,
        [object]$IPInt = $null
    )

    if ([string]::IsNullOrWhiteSpace($IP) -or [string]::IsNullOrWhiteSpace($CIDR)) { return $false }
    if ($IP.IndexOf(':') -ge 0 -or $CIDR.IndexOf(':') -ge 0) { return $false }  # IPv6 skip safely

    # CIDR cache lookup (prefer passed-in cache, fallback to script cache)
    $info = $null
    if ($CIDRInfo -and $CIDRInfo.ContainsKey($CIDR)) {
        $info = $CIDRInfo[$CIDR]
    }
    else {
        if (-not $script:__CIDRInfoCache) { $script:__CIDRInfoCache = @{} }
        if ($script:__CIDRInfoCache.ContainsKey($CIDR)) {
            $info = $script:__CIDRInfoCache[$CIDR]
        }
        else {
            $info = New-CIDRInfo -CIDR $CIDR
            if ($null -ne $info) { $script:__CIDRInfoCache[$CIDR] = $info }
        }
    }

    if ($null -eq $info) { return $false }

    # Convert IP once (UInt32)
    $ipUInt32 = $null
    if ($null -ne $IPInt) {
        try { $ipUInt32 = [uint32]$IPInt } catch { $ipUInt32 = $null }
    }
    if ($null -eq $ipUInt32) {
        $ipUInt32 = ConvertTo-UInt32IPv4 -IP $IP
    }
    if ($null -eq $ipUInt32) { return $false }

    return (([uint32]$ipUInt32 -band [uint32]$info.Mask) -eq [uint32]$info.NetworkMasked)
}

# Legacy helper kept for compatibility (not used by optimized CIDR checks)
function ConvertTo-BinaryIP {
    param([string]$IP)

    $u = ConvertTo-UInt32IPv4 -IP $IP
    if ($null -eq $u) { return '' }
    return ([Convert]::ToString([uint32]$u, 2).PadLeft(32, '0'))
}


# ============================================================================
# WHOIS FUNCTIONS
# ============================================================================

function Get-IPInfo {
    param([string]$IP)
    
    try {
        $response = Invoke-RestMethod -Uri "http://ip-api.com/json/$IP" -TimeoutSec 5 -ErrorAction Stop
        
        Start-Sleep -Milliseconds 1500
        
        return @{
            Country = $response.country
            CountryCode = $response.countryCode
            Region = $response.regionName
            City = $response.city
            ISP = $response.isp
            Organization = $response.org
            AS = $response.as
            Success = $true
        }
    }
    catch {
        return @{
            Country = "Unknown"
            CountryCode = "XX"
            Region = "Unknown"
            City = "Unknown"
            ISP = "Unknown"
            Organization = "Unknown"
            AS = "Unknown"
            Success = $false
        }
    }
}

# ============================================================================
# AUTO-CLASSIFICATION FUNCTIONS
# ============================================================================

function Get-AutoClassification {
    param(
        [string]$IP,
        [hashtable]$IPInfo
    )
    
    $highRiskCountries = @('RU', 'CN', 'KP', 'AF', 'PK', 'MM', 'NG', 'SD', 'SO', 'LY', 'IR', 'SY', 'BY')
    $trustedOrgs = @('Microsoft', 'Google', 'Amazon', 'Apple', 'Cloudflare', 'Akamai', 'Fastly')
    
    $classification = @{
        Status = "Unknown"
        Reason = ""
        AutoAdded = $false
        TargetList = ""
    }
    
    foreach ($org in $trustedOrgs) {
        if ($IPInfo.Organization -like "*$org*" -or $IPInfo.ISP -like "*$org*") {
            $classification.Status = "Whitelist"
            $classification.Reason = "Trusted Organization: $org"
            $classification.AutoAdded = $true
            $classification.TargetList = "Whitelist"
            return $classification
        }
    }
    
    if ($highRiskCountries -contains $IPInfo.CountryCode) {
        $classification.Status = "Blacklist"
        $classification.Reason = "High-Risk Country: $($IPInfo.Country)"
        $classification.AutoAdded = $true
        $classification.TargetList = "Blacklist"
        return $classification
    }
    
    return $classification
}

function Add-ToAutoList {
    param(
        [string]$IP,
        [string]$ListType,
        [string]$Reason
    )
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $fileName = "Auto_Classified_$timestamp.txt"
    
    $targetPath = if ($ListType -eq "Blacklist") { $BlacklistPath } else { $WhitelistPath }
    $filePath = Join-Path $targetPath $fileName
    
    if (-not (Test-Path $filePath)) {
        "# Auto-Classified IPs - $timestamp" | Out-File $filePath -Encoding UTF8
        "# Reason: $Reason" | Add-Content $filePath -Encoding UTF8
        "" | Add-Content $filePath -Encoding UTF8
    }
    
    $IP | Add-Content $filePath -Encoding UTF8
}

# ============================================================================
# OPTION 1: START NEW PROJECT
# ============================================================================

function Start-NewProject {
    Show-Header
    
    Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║                    NEW PROJECT                                 ║" -ForegroundColor Green
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""
    
    if (-not $ProjectName) {
        Write-Host "📝 Project Name (press Enter for auto-generated):" -ForegroundColor Cyan
        Write-Host "   " -NoNewline
        $ProjectName = Read-Host
        
        if ([string]::IsNullOrWhiteSpace($ProjectName)) {
            $ProjectName = "Analysis_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        }
    }
    
    if (-not $InputFile) {
        Write-Host ""
        Write-Host "📁 IP List File:" -ForegroundColor Cyan
        Write-Host "   " -NoNewline
        $InputFile = Read-Host
        
        $InputFile = $InputFile.Trim('"').Trim("'")
    }
    
    if (-not (Test-Path $InputFile)) {
        Write-Host ""
        Write-Host "❌ File not found: $InputFile" -ForegroundColor Red
        Write-Host ""
        Write-Host "Press any key to return..." -ForegroundColor Gray
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        return
    }
    
    Write-Host ""
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host ""
    Write-Host "🚀 Starting Analysis..." -ForegroundColor Green
    Write-Host ""
    
    $projectPath = Join-Path $ProjectsPath $ProjectName
    $resultsPath = Join-Path $projectPath "Results"
    $logsPath = Join-Path $projectPath "Logs"
    
    @($projectPath, $resultsPath, $logsPath) | ForEach-Object {
        if (-not (Test-Path $_)) {
            New-Item -ItemType Directory -Path $_ -Force | Out-Null
        }
    }
    
    Write-Host "📥 Extracting IPs from file..." -ForegroundColor Cyan
    $ips = Extract-IPsFromFile -FilePath $InputFile
    Write-Host "   ✓ Found $($ips.Count) IP addresses" -ForegroundColor Green
    Write-Host ""
    
    if ($ips.Count -eq 0) {
        Write-Host "❌ No valid IPs found" -ForegroundColor Red
        Write-Host ""
        Write-Host "Press any key to return..." -ForegroundColor Gray
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        return
    }
    
    Write-Host "📚 Loading threat intelligence (optimized)..." -ForegroundColor Cyan
    Write-Host ""
    Write-Host "   🔴 Blacklist:" -ForegroundColor Red
    $blacklist = Load-Rules -Path $BlacklistPath -Type "Blacklist"
    Write-Host ""
    Write-Host "   🟢 Whitelist:" -ForegroundColor Green
    $whitelist = Load-Rules -Path $WhitelistPath -Type "Whitelist"
    Write-Host ""
    
    Write-Host "🔍 Analyzing IP addresses..." -ForegroundColor Cyan
    Write-Host ""
    
    $results = @()
    $current = 0
    $blacklistedCount = 0
    $whitelistedCount = 0
    $unknownCount = 0
    $autoClassifiedCount = 0
    
    
    
    # Precomputed lists (avoid reallocating per IP)
    $trustedOrgs = @('Microsoft', 'Google', 'Amazon', 'Apple', 'Cloudflare', 'Akamai', 'Fastly', 'Facebook', 'Meta')
    $maliciousKeywords = @('torrent', 'tracker', 'p2p', 'vpn', 'proxy', 'tor', 'anydesk', 'teamviewer', 'rdp', 'remote')
    $highRiskCountries = @('RU', 'CN', 'KP', 'AF', 'PK', 'MM', 'NG', 'SD', 'SO', 'LY', 'IR', 'SY', 'BY')
foreach ($ip in $ips) {
        $current++
        $percent = [math]::Round(($current / $ips.Count) * 100, 1)
        
        Write-Progress -Activity "Analyzing IPs" -Status "IP $current of $($ips.Count) - $ip" -PercentComplete $percent
        
        $result = @{
            IP = $ip
            Status = "Unknown"
            Reason = ""
            Country = ""
            Organization = ""
            AutoClassified = $false
        }
        
        
        # PRIMARY: Two-Stage verification (local lists) - use this BEFORE any WHOIS/heuristics
        $ipUInt32 = ConvertTo-UInt32IPv4 -IP $ip
        if ($null -eq $ipUInt32) {
            $result.Status = "Unknown"
            $result.Reason = "IPv6/Invalid IP - Skipped"
            $unknownCount++
            $results += [PSCustomObject]$result
            continue
        }

        $whitelistMatch = Test-IPInList-TwoStage -IP $ip -IPList $whitelist.IPs -CIDRList $whitelist.CIDRs -PrefixIndex $whitelist.PrefixIndex -SubnetMap $whitelist.SubnetMap -CIDRInfo $whitelist.CIDRInfo -IPInt $ipUInt32
        if ($whitelistMatch.Found) {
            $result.Status = "Whitelist"
            $result.Reason = "Found in Whitelist ($($whitelistMatch.MatchType))"
            $whitelistedCount++
            $results += [PSCustomObject]$result
            continue
        }

        $blacklistMatch = Test-IPInList-TwoStage -IP $ip -IPList $blacklist.IPs -CIDRList $blacklist.CIDRs -PrefixIndex $blacklist.PrefixIndex -SubnetMap $blacklist.SubnetMap -CIDRInfo $blacklist.CIDRInfo -IPInt $ipUInt32
        if ($blacklistMatch.Found) {
            $result.Status = "Blacklist"
            $result.Reason = "Found in Blacklist ($($blacklistMatch.MatchType))"
            $blacklistedCount++
            $results += [PSCustomObject]$result
            continue
        }

        # STEP 1: Get WHOIS info ONLY for IPs not found in local lists
        $ipInfo = Get-IPInfo -IP $ip
        $result.Country = $ipInfo.Country
        $result.Organization = $ipInfo.Organization

        # STEP 2: Check if it's a trusted organization (PRIORITY)
        $isTrusted = $false
        foreach ($org in $trustedOrgs) {
            if ($ipInfo.Organization -like "*$org*" -or $ipInfo.ISP -like "*$org*") {
                $result.Status = "Whitelist"
                $result.Reason = "Trusted Organization: $org"
                $result.AutoClassified = $true
                $whitelistedCount++
                $autoClassifiedCount++
                $isTrusted = $true

                Add-ToAutoList -IP $ip -ListType "Whitelist" -Reason "Trusted Organization: $org"
                break
            }
        }

        if (-not $isTrusted) {
            # STEP 3: Check for malicious indicators
            $isMalicious = $false
            foreach ($keyword in $maliciousKeywords) {
                if ($ipInfo.Organization -like "*$keyword*" -or $ipInfo.ISP -like "*$keyword*") {
                    $result.Status = "Blacklist"
                    $result.Reason = "Malicious Service: $keyword"
                    $result.AutoClassified = $true
                    $blacklistedCount++
                    $autoClassifiedCount++
                    $isMalicious = $true

                    Add-ToAutoList -IP $ip -ListType "Blacklist" -Reason "Malicious Service: $keyword"
                    break
                }
            }

            if (-not $isMalicious) {
                # STEP 4: Check high-risk countries
                if ($highRiskCountries -contains $ipInfo.CountryCode) {
                    $result.Status = "Blacklist"
                    $result.Reason = "High-Risk Country: $($ipInfo.Country)"
                    $result.AutoClassified = $true
                    $blacklistedCount++
                    $autoClassifiedCount++

                    Add-ToAutoList -IP $ip -ListType "Blacklist" -Reason "High-Risk Country: $($ipInfo.Country)"
                }
                # STEP 5: Cloud providers (potential C2) - keep as Unknown when not in local lists
                elseif ($ipInfo.Organization -like "*hosting*" -or $ipInfo.Organization -like "*cloud*" -or $ipInfo.Organization -like "*server*") {
                    $result.Status = "Unknown"
                    $result.Reason = "Cloud/Hosting Provider - Needs Review"
                    $unknownCount++
                }
                else {
                    $result.Status = "Unknown"
                    $result.Reason = "Not in any list"
                    $unknownCount++
                }
            }
        }


$results += [PSCustomObject]$result
    }
    
    Write-Progress -Activity "Analyzing IPs" -Completed
    
    Write-Host ""
    Write-Host "💾 Saving results..." -ForegroundColor Cyan
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    
    $completeFile = Join-Path $resultsPath "Complete_Analysis_$timestamp.csv"
    $results | Export-Csv -Path $completeFile -NoTypeInformation -Encoding UTF8
    
    $blacklistedFile = Join-Path $resultsPath "Blacklisted_$timestamp.csv"
    $results | Where-Object { $_.Status -eq "Blacklist" } | Export-Csv -Path $blacklistedFile -NoTypeInformation -Encoding UTF8
    
    $whitelistedFile = Join-Path $resultsPath "Whitelisted_$timestamp.csv"
    $results | Where-Object { $_.Status -eq "Whitelist" } | Export-Csv -Path $whitelistedFile -NoTypeInformation -Encoding UTF8
    
    $unknownFile = Join-Path $resultsPath "Unknown_$timestamp.csv"
    $results | Where-Object { $_.Status -eq "Unknown" } | Export-Csv -Path $unknownFile -NoTypeInformation -Encoding UTF8
    
    if ($autoClassifiedCount -gt 0) {
        $autoFile = Join-Path $resultsPath "Auto_Classified_$timestamp.csv"
        $results | Where-Object { $_.AutoClassified -eq $true } | Export-Csv -Path $autoFile -NoTypeInformation -Encoding UTF8
    }
    
    $summaryFile = Join-Path $resultsPath "Summary_$timestamp.txt"
    @"
═══════════════════════════════════════════════════════════════
                    ANALYSIS SUMMARY
═══════════════════════════════════════════════════════════════

📁 Project: $ProjectName
📅 Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

📊 Statistics:
   • Total IPs: $($ips.Count)
   • Blacklisted: $blacklistedCount
   • Whitelisted: $whitelistedCount
   • Unknown: $unknownCount
   • Auto-Classified: $autoClassifiedCount

📁 Files:
   • Complete Results: $completeFile
   • Blacklisted: $blacklistedFile
   • Whitelisted: $whitelistedFile
   • Unknown: $unknownFile
$(if ($autoClassifiedCount -gt 0) { "   • Auto-Classified: $autoFile" })

═══════════════════════════════════════════════════════════════
"@ | Out-File $summaryFile -Encoding UTF8
    
    Write-Host "   ✓ Results saved to: $resultsPath" -ForegroundColor Green
    Write-Host ""
    
    Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║                      RESULTS SUMMARY                           ║" -ForegroundColor Green
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""
    Write-Host "  📊 Total IPs         : $($ips.Count)" -ForegroundColor White
    Write-Host "  🔴 Blacklisted      : $blacklistedCount" -ForegroundColor Red
    Write-Host "  🟢 Whitelisted      : $whitelistedCount" -ForegroundColor Green
    Write-Host "  ⚪ Unknown          : $unknownCount" -ForegroundColor Gray
    Write-Host "  🤖 Auto-Classified  : $autoClassifiedCount" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host ""
    Write-Host "✅ Analysis completed successfully!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Press any key to return..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# ============================================================================
# OPTION 2: CLEAN OLD DATA
# ============================================================================

function Clear-OldData {
    Show-Header
    
    Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
    Write-Host "║                    CLEAN OLD DATA                              ║" -ForegroundColor Yellow
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Yellow
    Write-Host ""
    
    Write-Host "⚠️  Warning: This will delete projects older than 30 days!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Do you want to continue? [Y/N]: " -NoNewline -ForegroundColor Yellow
    $confirm = Read-Host
    
    if ($confirm -ne "Y" -and $confirm -ne "y") {
        Write-Host ""
        Write-Host "❌ Operation cancelled" -ForegroundColor Red
        Write-Host ""
        Write-Host "Press any key to return..." -ForegroundColor Gray
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        return
    }
    
    Write-Host ""
    Write-Host "🗑️  Cleaning..." -ForegroundColor Cyan
    Write-Host ""
    
    $deletedCount = 0
    $projects = Get-ChildItem -Path $ProjectsPath -Directory -ErrorAction SilentlyContinue
    
    foreach ($project in $projects) {
        $age = (Get-Date) - $project.LastWriteTime
        
        if ($age.TotalDays -gt 30) {
            try {
                Remove-Item -Path $project.FullName -Recurse -Force -ErrorAction Stop
                Write-Host "   ✓ Deleted: $($project.Name)" -ForegroundColor Green
                $deletedCount++
            }
            catch {
                Write-Host "   ✗ Failed to delete: $($project.Name)" -ForegroundColor Red
            }
        }
    }
    
    Write-Host ""
    Write-Host "✅ Deleted $deletedCount old projects" -ForegroundColor Green
    Write-Host ""
    Write-Host "Press any key to return..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# ============================================================================
# OPTION 3: VIEW STATISTICS
# ============================================================================

function Show-Statistics {
    Show-Header
    
    Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                        STATISTICS                              ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    
    $blacklistFiles = (Get-ChildItem -Path $BlacklistPath -File -ErrorAction SilentlyContinue).Count
    $whitelistFiles = (Get-ChildItem -Path $WhitelistPath -File -ErrorAction SilentlyContinue).Count
    $projects = (Get-ChildItem -Path $ProjectsPath -Directory -ErrorAction SilentlyContinue).Count
    
    Write-Host "📊 File Statistics:" -ForegroundColor Yellow
    Write-Host "   • Blacklist Files: $blacklistFiles" -ForegroundColor White
    Write-Host "   • Whitelist Files: $whitelistFiles" -ForegroundColor White
    Write-Host "   • Projects: $projects" -ForegroundColor White
    Write-Host ""
    
    $blacklistSize = (Get-ChildItem -Path $BlacklistPath -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1MB
    $whitelistSize = (Get-ChildItem -Path $WhitelistPath -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1MB
    
    Write-Host "💾 Directory Sizes:" -ForegroundColor Yellow
    Write-Host "   • Blacklist: $([math]::Round($blacklistSize, 2)) MB" -ForegroundColor White
    Write-Host "   • Whitelist: $([math]::Round($whitelistSize, 2)) MB" -ForegroundColor White
    Write-Host ""
    
    Write-Host "Press any key to return..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# ============================================================================
# MAIN LOOP
# ============================================================================

Show-Header

while ($true) {
    Show-MainMenu
    
    Write-Host "Select [0-3]: " -NoNewline -ForegroundColor White
    $choice = Read-Host
    
    switch ($choice) {
        "1" { Start-NewProject }
        "2" { Clear-OldData }
        "3" { Show-Statistics }
        "0" {
            Clear-Host
            Write-Host ""
            Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "  Thank you for using IP Analysis System v1.0!" -ForegroundColor Green
            Write-Host ""
            Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
            Write-Host ""
            exit 0
        }
        default {
            Write-Host ""
            Write-Host "❌ Invalid option. Please select 0-3" -ForegroundColor Red
            Start-Sleep -Seconds 2
        }
    }
    
    Show-Header
}
