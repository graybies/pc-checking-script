#Requires -RunAsAdministrator
#Requires -Version 7.0

<#
.SYNOPSIS
    System Analyzer - Comprehensive hardware and software inventory collection tool
.DESCRIPTION
    This script performs detailed system analysis including hardware enumeration,
    driver inventory, network configuration, running processes, and security settings.
    Collects forensic data for offline analysis and system auditing purposes.
.PARAMETER RedactSensitiveInfo
    When enabled, redacts computer name and username from reports for privacy
.NOTES
    Must be run with Administrator privileges and PowerShell 7+
    Use Run-System-Analyzer.ps1 to automatically launch in PowerShell 7
    Author: System Analysis Tool
    Date: October 22, 2025
    Version: 3.0 - Optimized & Secured Edition
#>

# Security: Option to redact sensitive information
param(
    [switch]$RedactSensitiveInfo = $false
)

# Track scan start time
$startTime = Get-Date

# Color coding for output
$script:findings = @()
$script:auditLog = @()
$script:silentMode = $true  # Silent scanning mode - no detailed output
$script:totalChecks = 29  # Updated: 18 original + 11 advanced detection checks
$script:currentCheck = 0
$script:redactInfo = $RedactSensitiveInfo

# Performance optimization: Cache expensive lookups
$script:processCache = @{}
$script:signatureCache = @{}
$script:pnpDeviceCache = $null
$script:pciDeviceCache = $null
$script:win32PnpCache = $null
$script:systemDriverCache = $null

function Write-Progress-Silent {
    param([string]$Activity, [string]$Status, [int]$PercentComplete)
    if ($script:silentMode) {
        Write-Progress -Activity $Activity -Status $Status -PercentComplete $PercentComplete
    }
}

function Update-ScanProgress {
    param([string]$CheckName)
    $script:currentCheck++
    $percent = [math]::Round(($script:currentCheck / $script:totalChecks) * 100)
    Write-Progress-Silent -Activity "Scanning" -Status "$CheckName - Check $script:currentCheck/$script:totalChecks" -PercentComplete $percent
}

function Write-Status {
    param([string]$Message, [string]$Type = "Info")
    # Only show critical findings during scan, suppress informational messages
    if (-not $script:silentMode) {
        $timestamp = Get-Date -Format "HH:mm:ss"
        switch ($Type) {
            "Success" { Write-Host "[$timestamp] [✓] $Message" -ForegroundColor Green }
            "Warning" { Write-Host "[$timestamp] [!] $Message" -ForegroundColor Yellow }
            "Error"   { Write-Host "[$timestamp] [✗] $Message" -ForegroundColor Red }
            "Info"    { Write-Host "[$timestamp] [i] $Message" -ForegroundColor Cyan }
            default   { Write-Host "[$timestamp] $Message" }
        }
    }
}

# Optimized: Get process command line with caching
function Get-ProcessCommandLine {
    param([int]$ProcessId)
    
    if ($script:processCache.ContainsKey($ProcessId)) {
        return $script:processCache[$ProcessId]
    }
    
    $cmdLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $ProcessId" -ErrorAction SilentlyContinue).CommandLine
    $script:processCache[$ProcessId] = $cmdLine
    return $cmdLine
}

# Enhanced operation logging system - extremely verbose for forensic verification
$script:operationLogEntries = [System.Collections.ArrayList]::new()
$script:operationLogPath = $null

function Write-OperationLog {
    <#
    .SYNOPSIS
    Logs every operation performed by the script for forensic verification
    .DESCRIPTION
    Creates an extremely verbose, timestamped log of all actions taken by the script.
    This log serves as proof that all findings are legitimate and verifiable.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS", "QUERY", "FINDING", "ACTION")]
        [string]$Level = "INFO",
        
        [Parameter(Mandatory=$false)]
        [hashtable]$Details = @{}
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $threadId = [System.Threading.Thread]::CurrentThread.ManagedThreadId
    
    # Build detailed log entry
    $logEntry = @{
        Timestamp = $timestamp
        ThreadID = $threadId
        Level = $Level
        Message = $Message
        Details = $Details
    }
    
    # Format for human readability
    $formattedEntry = "[$timestamp] [$Level] [TID:$threadId] $Message"
    
    # Add details if present
    if ($Details.Count -gt 0) {
        $detailsText = $Details.GetEnumerator() | ForEach-Object {
            "    ↳ $($_.Key): $($_.Value)"
        }
        $formattedEntry += "`n" + ($detailsText -join "`n")
    }
    
    # Add to in-memory collection
    $null = $script:operationLogEntries.Add($formattedEntry)
    
    # Immediately write to file if path is set (real-time logging)
    if ($script:operationLogPath) {
        try {
            Add-Content -Path $script:operationLogPath -Value $formattedEntry -ErrorAction SilentlyContinue
        } catch {
            # Silently fail if can't write - don't break the scan
        }
    }
}

function Initialize-OperationLog {
    <#
    .SYNOPSIS
    Initializes the operation log file with header information
    #>
    param([string]$LogPath)
    
    $script:operationLogPath = $LogPath
    
    $header = @"
╔══════════════════════════════════════════════════════════════════════════════╗
║                    SYSTEM ANALYZER OPERATION LOG                             ║
║                      FORENSIC VERIFICATION LOG                               ║
╚══════════════════════════════════════════════════════════════════════════════╝

PURPOSE:
This log contains a complete, timestamped record of every operation performed
by the System Analyzer script. It serves as forensic evidence that all findings
are legitimate and verifiable. Every query, check, and finding is logged here.

CREATED: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
COMPUTER: $(if ($script:redactInfo) { 'REDACTED' } else { $env:COMPUTERNAME })
USER: $(if ($script:redactInfo) { 'REDACTED' } else { $env:USERNAME })
SCRIPT VERSION: 3.0 (29 checks)
POWERSHELL VERSION: $($PSVersionTable.PSVersion)
OS VERSION: $((Get-CimInstance Win32_OperatingSystem).Caption)
EXECUTION POLICY: $(Get-ExecutionPolicy)

═══════════════════════════════════════════════════════════════════════════════
                              OPERATION LOG STARTS
═══════════════════════════════════════════════════════════════════════════════

"@
    
    try {
        Set-Content -Path $LogPath -Value $header -ErrorAction Stop
        Write-OperationLog "Operation log initialized at: $LogPath" "SUCCESS"
    } catch {
        Write-Host "[!] WARNING: Could not initialize operation log: $_" -ForegroundColor Yellow
    }
}

function Save-OperationLog {
    <#
    .SYNOPSIS
    Finalizes the operation log with summary statistics
    #>
    
    if (-not $script:operationLogPath) { return }
    
    $footer = @"

═══════════════════════════════════════════════════════════════════════════════
                              OPERATION LOG ENDS
═══════════════════════════════════════════════════════════════════════════════

SUMMARY:
Total Log Entries: $($script:operationLogEntries.Count)
End Time: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

Log Entry Breakdown:
$(($script:operationLogEntries | Where-Object {$_ -match '\[INFO\]'}).Count) INFO messages
$(($script:operationLogEntries | Where-Object {$_ -match '\[WARNING\]'}).Count) WARNING messages
$(($script:operationLogEntries | Where-Object {$_ -match '\[ERROR\]'}).Count) ERROR messages
$(($script:operationLogEntries | Where-Object {$_ -match '\[SUCCESS\]'}).Count) SUCCESS messages
$(($script:operationLogEntries | Where-Object {$_ -match '\[QUERY\]'}).Count) QUERY operations
$(($script:operationLogEntries | Where-Object {$_ -match '\[FINDING\]'}).Count) FINDING entries
$(($script:operationLogEntries | Where-Object {$_ -match '\[ACTION\]'}).Count) ACTION operations

This log can be independently verified by reviewing each timestamp and operation.
All WMI/CIM queries, registry accesses, and file operations are documented above.

═══════════════════════════════════════════════════════════════════════════════
"@
    
    try {
        Add-Content -Path $script:operationLogPath -Value $footer -ErrorAction Stop
    } catch {
        Write-Host "[!] WARNING: Could not finalize operation log: $_" -ForegroundColor Yellow
    }
}

# Optimized: Get signature with caching
function Get-CachedSignature {
    param([string]$FilePath)
    
    if (-not $FilePath -or -not (Test-Path $FilePath)) {
        return $null
    }
    
    if ($script:signatureCache.ContainsKey($FilePath)) {
        return $script:signatureCache[$FilePath]
    }
    
    $sig = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction SilentlyContinue
    $script:signatureCache[$FilePath] = $sig
    return $sig
}

# Optimized: Get all PnP devices once and cache
function Get-CachedPnpDevices {
    if ($null -eq $script:pnpDeviceCache) {
        $script:pnpDeviceCache = Get-PnpDevice
    }
    return $script:pnpDeviceCache
}

# Optimized: Get PCI devices once and cache
function Get-CachedPciDevices {
    if ($null -eq $script:pciDeviceCache) {
        $script:pciDeviceCache = Get-CachedPnpDevices | Where-Object { $_.InstanceId -like "PCI\*" }
    }
    return $script:pciDeviceCache
}

# Optimized: Cache Win32_PnPEntity for multiple uses
function Get-CachedWin32PnpEntity {
    if ($null -eq $script:win32PnpCache) {
        $script:win32PnpCache = Get-CimInstance Win32_PnPEntity
    }
    return $script:win32PnpCache
}

# Optimized: Cache system drivers for multiple uses
function Get-CachedSystemDrivers {
    if ($null -eq $script:systemDriverCache) {
        $script:systemDriverCache = Get-CimInstance Win32_SystemDriver
    }
    return $script:systemDriverCache
}

# Security: Validate paths to prevent path traversal
function Test-SafePath {
    param(
        [string]$Path,
        [string]$BaseDirectory
    )
    
    try {
        $resolvedPath = [System.IO.Path]::GetFullPath($Path)
        $resolvedBase = [System.IO.Path]::GetFullPath($BaseDirectory)
        
        # Ensure path is within base directory
        return $resolvedPath.StartsWith($resolvedBase, [StringComparison]::OrdinalIgnoreCase)
    } catch {
        return $false
    }
}

# Security: Sanitize filename to prevent injection
function Get-SafeFileName {
    param([string]$FileName)
    
    # Remove invalid characters and potential injection attempts
    $invalidChars = [System.IO.Path]::GetInvalidFileNameChars() -join ''
    $sanitized = $FileName -replace "[$([regex]::Escape($invalidChars))]", '_'
    
    # Remove path traversal attempts
    $sanitized = $sanitized -replace '\.\.', '_'
    $sanitized = $sanitized -replace '[\\/]', '_'
    
    return $sanitized
}

function Add-Finding {
    param(
        [string]$Category,
        [string]$Severity,
        [string]$Description,
        [object]$Details
    )
    $script:findings += [PSCustomObject]@{
        Timestamp = Get-Date
        Category = $Category
        Severity = $Severity
        Description = $Description
        Details = $Details
    }
}

function Add-AuditEntry {
    param([string]$CheckName, [string]$Status, [int]$ItemsScanned, [int]$SuspiciousFound, [object]$Details)
    $script:auditLog += [PSCustomObject]@{
        Timestamp = Get-Date; CheckName = $CheckName; Status = $Status; ItemsScanned = $ItemsScanned; SuspiciousFound = $SuspiciousFound; Details = $Details
    }
}

# Helper: Report scored finding with consolidated output
function Report-ScoredFinding {
    param([object]$Analysis, [string]$Name, [string]$Category, [hashtable]$ExtraDetails = @{}, [bool]$IsActive = $false)
    
    $risk = $Analysis.RiskLevel
    $score = $Analysis.Score
    $evidence = $Analysis.Evidence -join ", "
    
    if ($risk -eq "LIKELY-SAFE") {
        # Silently skip likely safe items
        return 0
    } elseif ($risk -eq "INFO") {
        # Silently skip informational items
        return 0
    } elseif ($risk -eq "LOW" -and -not $IsActive) {
        # Skip LOW risk drivers that aren't actively running
        return 0
    } else {
        # Store finding silently without console output
        # For active drivers, only report MEDIUM+ risk (score 15+)
        # For inactive drivers, only report HIGH risk (score 30+)
        if ($IsActive) {
            if ($score -lt 20) { return 0 }  # Skip low-score active drivers
            if ($risk -eq "HIGH") { $severity = "CRITICAL" } 
            elseif ($risk -eq "MEDIUM") { $severity = "HIGH" } 
            else { $severity = "MEDIUM" }
        } else {
            if ($score -lt 30) { return 0 }  # Only report high-score inactive drivers
            if ($risk -eq "HIGH") { $severity = "HIGH" } 
            elseif ($risk -eq "MEDIUM") { $severity = "MEDIUM" } 
            else { $severity = "LOW" }
        }
        
        $details = @{ SuspicionScore = $score; RiskLevel = $risk; Evidence = $Analysis.Evidence } + $ExtraDetails
        Add-Finding -Category $Category -Severity $severity -Description "Suspicious $Category with $risk risk" -Details $details
        return 1
    }
}

function Test-SuspiciousSerial {
    param([string]$serial)
    
    if (!$serial -or $serial -eq "") { return $true }
    
    # Check for common suspicious patterns
    if ($serial -match "^0+$") { return $true }                    # All zeros
    if ($serial -match "^[Ff]+$") { return $true }                 # All F's
    if ($serial -match "^1+$") { return $true }                    # All ones
    if ($serial -match "^([0-9A-Fa-f]{2})\1{3,}$") { return $true } # Repeating pairs
    if ($serial -match "1234|DEAD|BEEF|CAFE|BABE|FACE|FADE|C0DE") { return $true } # Common test values
    if ($serial -match "0123456789|ABCDEFGH") { return $true }     # Sequential
    if ($serial -match "^(TEST|DEFAULT|SAMPLE|DEBUG)") { return $true } # Test strings
    if ($serial.Length -lt 4) { return $true }                     # Too short
    
    return $false
}

function Test-DriverCertificate {
    param([string]$driverPath)
    
    $issues = @()
    
    try {
        if (Test-Path $driverPath) {
            # Use cached signature lookup
            $cert = Get-CachedSignature -FilePath $driverPath
            
            if (!$cert) {
                $issues += "No signature found"
                return $issues
            }
            
            if ($cert.Status -ne "Valid") {
                $issues += "Invalid signature: $($cert.Status)"
            }
            
            if ($cert.SignerCertificate) {
                $issuer = $cert.SignerCertificate.Issuer
                
                # Check for suspicious certificate issuers
                if ($issuer -match "CN=Test|CN=DEBUG|CN=Development|CN=Temp|CN=Example") {
                    $issues += "Test/Debug certificate detected"
                }
                
                # Check certificate expiration
                if ($cert.SignerCertificate.NotAfter -lt (Get-Date)) {
                    $issues += "Expired certificate"
                }
                
                # Check if self-signed
                if ($cert.SignerCertificate.Issuer -eq $cert.SignerCertificate.Subject) {
                    $issues += "Self-signed certificate"
                }
            }
        }
    } catch {
        $issues += "Error checking certificate: $($_.Exception.Message)"
    }
    
    return $issues
}

# Security Enhancement: Known driver file hashes (detects renamed drivers)
# Even if driver filename is changed, hash remains the same
$knownDriverHashes = @{
    # CH341 Serial Driver variants (commonly used for hardware modification)
    "8E7D4C3F2A1B9E5F6C8A9D7E4B3F2C1A5E6D7F8A9B0C1D2E3F4A5B6C7D8E9F0A" = @{ Name="CH341 Serial v3.4"; Risk="HIGH"; Component="USB-Serial bridge" }
    "9F8E7D6C5B4A3F2E1D0C9B8A7F6E5D4C3B2A1F0E9D8C7B6A5F4E3D2C1B0A9F8E" = @{ Name="CH341 Serial v3.5"; Risk="HIGH"; Component="USB-Serial bridge" }
    
    # FTDI Serial Driver variants
    "A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2" = @{ Name="FTDI Serial v2.12"; Risk="MEDIUM"; Component="USB-Serial communication" }
    
    # Xilinx Platform Cable USB drivers
    "B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3" = @{ Name="Xilinx Platform USB"; Risk="HIGH"; Component="FPGA programming interface" }
    
    # CP210x Serial drivers
    "C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3D4" = @{ Name="CP210x USB to UART"; Risk="MEDIUM"; Component="USB-Serial bridge" }
    
    # Interception driver (input redirection)
    "D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3D4E5" = @{ Name="Interception Driver"; Risk="HIGH"; Component="Input redirection/emulation" }
    
    # WinDivert packet filter
    "E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3D4E5F6" = @{ Name="WinDivert"; Risk="MEDIUM"; Component="Network packet filtering" }
}
# Note: Real hashes would be collected from known driver samples
# This is a template for the hash database structure

#region Baseline Comparison Functions
# These functions allow comparing current system state against a known-good baseline

function Export-SystemBaseline {
    <#
    .SYNOPSIS
    Creates a baseline snapshot of system when it's known to be clean
    .DESCRIPTION
    Exports driver list, PCI devices, services, and security settings to a JSON file
    #>
    param(
        [string]$BaselinePath = (Join-Path $PSScriptRoot "system-baseline.json")
    )
    
    try {
        Write-OperationLog "Creating system baseline at: $BaselinePath" "INFO"
        
        $baseline = @{
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ComputerName = $env:COMPUTERNAME
            Drivers = @(Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue | 
                       Select-Object Name, PathName, State, StartMode | 
                       ForEach-Object {
                           @{
                               Name = $_.Name
                               PathName = $_.PathName
                               State = $_.State
                               StartMode = $_.StartMode
                           }
                       })
            PCIDevices = @(Get-PnpDevice -Class "System","HDC","Net" -ErrorAction SilentlyContinue | 
                          Select-Object InstanceId, Status, FriendlyName | 
                          ForEach-Object {
                              @{
                                  InstanceId = $_.InstanceId
                                  Status = $_.Status
                                  FriendlyName = $_.FriendlyName
                              }
                          })
            Services = @(Get-Service -ErrorAction SilentlyContinue | 
                        Select-Object Name, Status, StartType | 
                        ForEach-Object {
                            @{
                                Name = $_.Name
                                Status = $_.Status.ToString()
                                StartType = $_.StartType.ToString()
                            }
                        })
            SecureBoot = (try { Confirm-SecureBootUEFI } catch { $false })
            DMAProtection = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\DmaSecurity" -ErrorAction SilentlyContinue).DmaProtectionEnabled -eq 1
        }
        
        $baseline | ConvertTo-Json -Depth 5 | Out-File $BaselinePath -Encoding UTF8
        Write-OperationLog "Baseline created successfully: $($baseline.Drivers.Count) drivers, $($baseline.PCIDevices.Count) devices" "INFO"
        
        return $true
    } catch {
        Write-OperationLog "Error creating baseline: $_" "ERROR"
        return $false
    }
}

function Compare-ToBaseline {
    <#
    .SYNOPSIS
    Compares current system state to previously created baseline
    .DESCRIPTION
    Returns findings for new/removed drivers, devices, or security changes
    #>
    param(
        [string]$BaselinePath = (Join-Path $PSScriptRoot "system-baseline.json")
    )
    
    $findings = @()
    
    try {
        if (-not (Test-Path $BaselinePath)) {
            return @{
                Category = "Baseline Not Found"
                Severity = "INFO"
                Evidence = "No baseline file exists at $BaselinePath"
                Impact = "Cannot perform baseline comparison - run Export-SystemBaseline first"
                SuspicionScore = 0
            }
        }
        
        $baseline = Get-Content $BaselinePath -ErrorAction Stop | ConvertFrom-Json
        Write-OperationLog "Comparing against baseline from $($baseline.Timestamp)" "INFO"
        
        # Get current state
        $currentDrivers = @(Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue | 
                           Select-Object Name, PathName, State)
        $currentDevices = @(Get-PnpDevice -Class "System","HDC","Net" -ErrorAction SilentlyContinue | 
                           Select-Object InstanceId, Status, FriendlyName)
        
        # Find new drivers not in baseline
        $newDrivers = @($currentDrivers | Where-Object {
            $driver = $_
            -not ($baseline.Drivers | Where-Object {$_.Name -eq $driver.Name})
        })
        
        if ($newDrivers.Count -gt 0) {
            $findings += @{
                Category = "New Drivers Since Baseline"
                Severity = "MEDIUM"
                Evidence = "Found $($newDrivers.Count) driver(s) not in baseline"
                NewDriverList = ($newDrivers.Name -join ", ")
                Impact = "New drivers may indicate installed hardware or malware"
                SuspicionScore = 40
            }
            Write-OperationLog "MEDIUM: $($newDrivers.Count) new drivers since baseline" "WARNING"
        }
        
        # Find removed drivers (in baseline but not current)
        $removedDrivers = @($baseline.Drivers | Where-Object {
            $baseDriver = $_
            -not ($currentDrivers | Where-Object {$_.Name -eq $baseDriver.Name})
        })
        
        if ($removedDrivers.Count -gt 0) {
            $findings += @{
                Category = "Removed Drivers Since Baseline"
                Severity = "LOW"
                Evidence = "Found $($removedDrivers.Count) driver(s) removed since baseline"
                RemovedDriverList = ($removedDrivers.Name -join ", ")
                SuspicionScore = 10
            }
        }
        
        # Find new PCI devices
        $newDevices = @($currentDevices | Where-Object {
            $device = $_
            -not ($baseline.PCIDevices | Where-Object {$_.InstanceId -eq $device.InstanceId})
        })
        
        if ($newDevices.Count -gt 0) {
            $findings += @{
                Category = "New Hardware Since Baseline"
                Severity = "HIGH"
                Evidence = "Found $($newDevices.Count) new hardware device(s)"
                NewDeviceList = ($newDevices.FriendlyName -join ", ")
                Impact = "New hardware may be DMA attack device or modified peripheral"
                SuspicionScore = 55
            }
            Write-OperationLog "HIGH: $($newDevices.Count) new hardware devices since baseline" "WARNING"
        }
        
        # Check security setting changes
        $currentSecureBoot = try { Confirm-SecureBootUEFI } catch { $false }
        if ($baseline.SecureBoot -and -not $currentSecureBoot) {
            $findings += @{
                Category = "Secure Boot Disabled Since Baseline"
                Severity = "CRITICAL"
                Evidence = "Secure Boot was enabled in baseline but is now disabled"
                Impact = "Critical security feature has been disabled"
                SuspicionScore = 80
            }
            Write-OperationLog "CRITICAL: Secure Boot disabled since baseline!" "WARNING"
        }
        
        $currentDMAProtection = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\DmaSecurity" -ErrorAction SilentlyContinue).DmaProtectionEnabled -eq 1
        if ($baseline.DMAProtection -and -not $currentDMAProtection) {
            $findings += @{
                Category = "DMA Protection Disabled Since Baseline"
                Severity = "CRITICAL"
                Evidence = "Kernel DMA Protection was enabled in baseline but is now disabled"
                Impact = "DMA attacks are now possible"
                SuspicionScore = 85
            }
            Write-OperationLog "CRITICAL: DMA Protection disabled since baseline!" "WARNING"
        }
        
        return $findings
        
    } catch {
        Write-OperationLog "Error comparing to baseline: $_" "ERROR"
        return @{
            Category = "Baseline Comparison Error"
            Severity = "LOW"
            Evidence = "Error reading or comparing baseline: $_"
            SuspicionScore = 5
        }
    }
}
#endregion Baseline Comparison Functions

# Hardware device signatures for analysis
$knownDMADevices = @{
    # FPGA development boards
    "VEN_10EE" = "Xilinx FPGA"
    "VEN_1172" = "Altera/Intel FPGA"
    "VEN_1D6A" = "Aquantia Network Adapter"
    
    # Specific FPGA product IDs
    "DEV_7038" = "Xilinx Kintex/Virtex"
    "DEV_8011" = "Xilinx Artix"
    "DEV_8012" = "Xilinx Artix"
    "DEV_8014" = "Xilinx Artix"
    "DEV_9038" = "Xilinx PCIe Bridge"
    
    # Device descriptions
    "PCILEECH" = "PCIe analysis tool"
    "ScreamerSquirrel" = "Hardware analysis device"
    "DMA" = "Direct Memory Access indicator"
    
    # Video capture hardware
    "VEN_1131" = "Philips SAA71xx Video Capture"
    "VEN_12AB" = "YUAN High-Tech Capture"
    "MacroSilicon" = "HDMI capture chips (MS2109/MS2130)"
    "USB Video" = "Generic USB video capture"
    "HDMI Capture" = "HDMI capture device"
    "Video Capture" = "Generic video capture"
}

# Device IDs associated with hardware modifications
$commonlySpoofedDevices = @{
    # Network adapters frequently modified
    "VEN_8086&DEV_10FB" = "Intel X540 10GbE"
    "VEN_8086&DEV_1563" = "Intel X550 10GbE"
    "VEN_8086&DEV_15B7" = "Intel I219-V"
    "VEN_8086&DEV_15B8" = "Intel I219-LM"
    "VEN_8086&DEV_1533" = "Intel I210 Gigabit"
    "VEN_8086&DEV_153A" = "Intel I217-LM"
    "VEN_8086&DEV_15A1" = "Intel I218-LM"
    "VEN_14E4" = "Broadcom Network Adapters"
    "VEN_14E4&DEV_1657" = "Broadcom NetXtreme BCM5719"
    "VEN_10EC&DEV_8168" = "Realtek RTL8168/8111"
    "VEN_10EC&DEV_8125" = "Realtek RTL8125 2.5GbE"
    
    # Capture/Video hardware
    "VEN_1131&DEV_7160" = "Philips SAA7160 Capture Card"
    "VEN_12AB" = "YUAN High-Tech Capture Cards"
    "VEN_1022&DEV_145F" = "AMD USB Controller"
    "VEN_1002" = "AMD/ATI devices"
    
    # Virtual/Emulation devices
    "VEN_1414" = "Microsoft Hyper-V"
    "VEN_1AEA" = "Google Goldfish (Android Emulator)"
    "VEN_15AD" = "VMware devices"
    "VEN_5853" = "XenSource/Citrix"
    
    # USB controllers
    "VEN_8086&DEV_A12F" = "Intel USB 3.0 eXtensible"
    "VEN_8086&DEV_9D2F" = "Intel USB 3.0"
}

# Driver names associated with system modifications
$suspiciousDrivers = @(
    # Hardware analysis drivers
    "pcileech",
    "screamer",
    "squirrel",
    "dmadrvr",
    "fpga",
    "xilinx",
    
    # Hardware access drivers (exploitable)
    "winring0",
    "physmem",
    "phymem",
    "directio",
    "inpoutx64",
    "ntiolib",
    "hw",
    
    # Exploit drivers
    "capcom",
    "gdrv",
    "atszio",
    "glckio2",
    "rtcore64",
    "amifldrv",
    "dbutil",
    "passport",
    "nvflash",
    "iqvw64e",
    "fiddrv",
    "nal",
    
    # Process/kernel manipulation
    "kprocesshacker",
    "kdmapper",
    "drvmap",
    "kernelmap",
    
    # Known exploit vectors
    "rzpnk",
    "speedfan",
    "aswarpot",
    "malcrpt",
    
    # Automation-specific
    "kmboxnet",
    "aimassist",
    "triggerbot",
    
    # Hardware input emulation devices
    "ch341ser",      # CH341 USB-Serial adapter
    "ch341",         # CH341 chip drivers
    "ftdi",          # FTDI USB-Serial
    "cp210x",        # Silicon Labs CP210x
    "pl2303",        # Prolific USB-Serial
    "arduino",       # Arduino-based devices
    "usbser",        # Generic USB serial
    "kmbox",         # KMBox devices
    "kmboxb",        # KMBox B series
    "kmboxa",        # KMBox A series
    "kmboxnet",      # KMBox Network model
    "kmboxnvideo",   # KMBox NVideo
    
    # Video capture hardware drivers
    "magewell",      # Magewell capture cards
    "avermedia",     # AVerMedia capture devices  
    "elgato",        # Elgato capture cards
    "mirabox",       # Mirabox HDMI capture
    "hdcap",         # Generic HDMI capture
    "uvcvideo",      # USB Video Class
    "usb2hdmi",      # USB to HDMI capture
    "hdmi2usb",      # HDMI to USB capture
    "macrosilicon",  # MacroSilicon capture chips
    "ms2109",        # MacroSilicon MS2109 chip
    "ms2130",        # MacroSilicon MS2130 chip
    "fuser"          # Fuser HDMI splitter/capture
)

# Function to calculate driver analysis score based on multiple evidence points
function Get-DriverSuspicionScore {
    param([string]$DriverName, [string]$DriverPath, [string]$ProviderName, [string]$ClassName, [AllowNull()][object]$DriverDate, [string]$Version)
    
    $score = 0
    $evidence = @()
    
    # Security: Check driver file hash against known database (catches renamed drivers)
    if ($DriverPath -and (Test-Path $DriverPath)) {
        try {
            $driverHash = (Get-FileHash -Path $DriverPath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            if ($driverHash -and $script:knownDriverHashes.ContainsKey($driverHash)) {
                $hashInfo = $script:knownDriverHashes[$driverHash]
                $score += 40  # Strong evidence - file hash matches known driver
                $evidence += "File hash matches known driver: $($hashInfo.Name) [$($hashInfo.Component)]"
                $evidence += "Driver may be renamed - hash detection bypasses filename spoofing"
            }
        } catch {
            # Hash calculation failed - not critical
        }
    }
    
    # Certificate validation (CRITICAL)
    if ($DriverPath -and (Test-Path $DriverPath)) {
        $cert = Get-CachedSignature -FilePath $DriverPath
        if (-not $cert -or $cert.Status -ne "Valid") {
            # Check if it's a known legitimate vendor without valid signature
            if ($ProviderName -match "libwdi|Marvell|CPUID|Corsair|GIGABYTE|Mullvad|Logitech|ASUS|MSI") {
                $score += 5; $evidence += "Unsigned third-party vendor driver"
            } else {
                $score += 30; $evidence += "No valid digital signature"
            }
        } elseif ($cert.SignerCertificate) {
            $issuer = $cert.SignerCertificate.Issuer
            $subject = $cert.SignerCertificate.Subject
            if ($issuer -match "CN=Test|CN=DEBUG|CN=Development") { $score += 25; $evidence += "Test/Debug certificate" }
            if ($issuer -eq $subject -and $subject -notmatch "Microsoft|Intel|AMD|NVIDIA") { $score += 20; $evidence += "Self-signed certificate" }
            # Expired certificates are common and not necessarily suspicious
            if ($cert.SignerCertificate.NotAfter -lt (Get-Date)) { 
                # Only penalize if also unsigned or self-signed
                if ($cert.Status -ne "Valid") { $score += 10; $evidence += "Expired certificate" }
            }
            if ($subject -match "Microsoft Corporation|Microsoft Windows") { $score -= 30; $evidence += "Valid Microsoft signature" }
        }
    }
    
    # Provider/Vendor verification - be much more lenient
    if ($ProviderName -match "Microsoft") { $score -= 20; $evidence += "Microsoft provider" }
    elseif ($ProviderName -match "Intel|AMD|NVIDIA|Realtek|Logitech|Corsair|ASUS|MSI|GIGABYTE") { $score -= 10; $evidence += "Known hardware vendor" }
    elseif ($ProviderName -match "Unknown|Generic|Test") { $score += 10; $evidence += "Generic/Unknown provider" }
    # Don't penalize missing provider info - many legitimate drivers don't have it
    
    # Class name + date + location analysis
    if ($ClassName -match "Generic|Unknown|Base") { $score += 5; $evidence += "Generic device class" }
    if ($DriverDate -is [datetime]) {
        if ($DriverDate -lt (Get-Date "2000-01-01")) { $score += 15; $evidence += "Suspiciously old driver date" }
        if ($DriverDate -gt (Get-Date).AddDays(1)) { $score += 20; $evidence += "Driver date in the future" }
    }
    
    # Path analysis - Windows paths are good
    if ($DriverPath -like "*\System32\drivers\Microsoft*" -or $DriverPath -like "*\DriverStore\*") { 
        $score -= 15; $evidence += "Microsoft driver directory" 
    }
    elseif ($DriverPath -like "*\System32\drivers\*" -or $DriverPath -like "*\Windows\System32\*") { 
        $score -= 10; $evidence += "Windows driver directory" 
    }
    elseif ($DriverPath -like "*\Program Files\*") {
        $score -= 5; $evidence += "Program Files location (legitimate software)"
    }
    
    # Common Windows driver names
    if (($DriverName -match "monitor|usbccgp|BthLEEnum|BthPan|Ndu") -and ($ProviderName -match "Microsoft")) {
        $score -= 10; $evidence += "Common Windows driver"
    }
    if ($Version -match "^10\.0\." -and $ProviderName -match "Microsoft") { $score -= 5; $evidence += "Windows 10/11 version" }
    
    return @{
        Score = $score
        Evidence = $evidence
        RiskLevel = if ($score -ge 30) { "HIGH" } elseif ($score -ge 15) { "MEDIUM" } elseif ($score -ge 5) { "LOW" } elseif ($score -lt 0) { "LIKELY-SAFE" } else { "INFO" }
    }
}

function Get-ProcessSuspicionScore {
    param([string]$ProcessName, [string]$ProcessPath, [string]$CommandLine)
    
    $score = 0
    $evidence = @()
    
    # Certificate validation
    if ($ProcessPath -and (Test-Path $ProcessPath)) {
        $cert = Get-CachedSignature -FilePath $ProcessPath
        if (-not $cert -or $cert.Status -ne "Valid") {
            $score += 25; $evidence += "No valid digital signature"
        } elseif ($cert.SignerCertificate) {
            if ($cert.SignerCertificate.Subject -match "Microsoft Corporation|Apple Inc\.|Google LLC") {
                $score -= 20; $evidence += "Valid trusted vendor signature"
            }
            if ($cert.SignerCertificate.Issuer -eq $cert.SignerCertificate.Subject) {
                $score += 15; $evidence += "Self-signed"
            }
        }
    } else {
        $score += 15; $evidence += "No executable path found"
    }
    
    # Location analysis
    if ($ProcessPath) {
        if ($ProcessPath -match "\\Windows\\(System32|SysWOW64)\\") { $score -= 10; $evidence += "Windows system directory" }
        elseif ($ProcessPath -like "*\Program Files*") { $score -= 5; $evidence += "Program Files directory" }
        elseif ($ProcessPath -like "*\AppData\Local\Temp\*") { $score += 20; $evidence += "Running from TEMP (suspicious)" }
        elseif ($ProcessPath -like "*\Downloads\*") { $score += 10; $evidence += "Running from Downloads (suspicious)" }
    }
    
    # Command line + process name analysis
    if ($CommandLine -match "inject|bypass|hack|cheat|dump|exploit") { $score += 20; $evidence += "Suspicious command line arguments" }
    if ($ProcessName -match "^(svchost|explorer|dwm|csrss|System|chrome|firefox|msedge)$") {
        $score -= 15; $evidence += "Common system/application process"
    }
    
    return @{
        Score = $score
        Evidence = $evidence
        RiskLevel = if ($score -ge 30) { "HIGH" } elseif ($score -ge 15) { "MEDIUM" } elseif ($score -ge 5) { "LOW" } elseif ($score -lt 0) { "LIKELY-SAFE" } else { "INFO" }
    }
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "        SYSTEM ANALYSIS" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan
Write-Host "Starting comprehensive security scan..." -ForegroundColor Gray
Write-Host ""

# Check 1: Current PCIe Devices
Update-ScanProgress "Hardware Devices"
try {
    $pciDevices = Get-CachedPnpDevices | Where-Object { 
        $_.InstanceId -like "PCI\*" -and ($_.Class -in @("System","Net","Display","Sound","Processor")) -and ($_.Status -in @("OK","Unknown","Error"))
    }
    
    $suspiciousCount = 0
    foreach ($device in $pciDevices) {
        $hardwareId = ($device.HardwareID | Select-Object -First 1)
        
        # Check known DMA signatures
        foreach ($signature in $knownDMADevices.Keys) {
            if ($hardwareId -like "*$signature*") {
                Write-Status "SUSPICIOUS: $($device.FriendlyName)" "Error"
                $suspiciousCount++
                Add-Finding -Category "PCIe Device" -Severity "HIGH" -Description "Known hardware device signature" `
                    -Details @{ DeviceName = $device.FriendlyName; HardwareID = $hardwareId; InstanceID = $device.InstanceId; Match = $knownDMADevices[$signature] }
                break
            }
        }
        
        # Check for FPGA/suspicious keywords
        if ($device.FriendlyName -match "FPGA|Xilinx|Altera|Unknown|Generic") {
            $suspiciousCount++
            Add-Finding -Category "PCIe Device" -Severity "MEDIUM" -Description "FPGA or unknown PCIe device" `
                -Details @{ DeviceName = $device.FriendlyName; HardwareID = $hardwareId; InstanceID = $device.InstanceId }
        }
    }
    
    Add-AuditEntry -CheckName "Current PCIe Devices" -Status "Completed" -ItemsScanned $pciDevices.Count -SuspiciousFound $suspiciousCount -Details @{}
} catch {
    Add-AuditEntry -CheckName "Current PCIe Devices" -Status "Error" -ItemsScanned 0 -SuspiciousFound 0 -Details @{ Error = $_.Exception.Message }
}

# Check 2: Historical PCIe Devices (Registry)
Update-ScanProgress "System Registry"
Update-ScanProgress "System Registry"
try {
    $totalEntries = 0
    $suspiciousCount = 0
    
    foreach ($regPath in @("HKLM:\SYSTEM\CurrentControlSet\Enum\PCI", "HKLM:\SYSTEM\ControlSet001\Enum\PCI")) {
        if (Test-Path $regPath) {
            $pciEntries = Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue
            $totalEntries += $pciEntries.Count
            
            foreach ($entry in $pciEntries) {
                foreach ($signature in $knownDMADevices.Keys) {
                    if ($entry.PSChildName -like "*$signature*") {
                        Get-ChildItem -Path $entry.PSPath -ErrorAction SilentlyContinue | ForEach-Object {
                            try {
                                $props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
                                # Suppressed finding
                                $suspiciousCount++
                                Add-Finding -Category "Registry (Historical)" -Severity "HIGH" -Description "Previously connected hardware device in registry" `
                                    -Details @{ DeviceID = $entry.PSChildName; RegistryPath = $_.PSPath; FriendlyName = $props.FriendlyName; Match = $knownDMADevices[$signature] }
                            } catch { }
                        }
                        break
                    }
                }
            }
        }
    }
    
    Add-AuditEntry -CheckName "Historical PCIe Devices" -Status "Completed" -ItemsScanned $totalEntries -SuspiciousFound $suspiciousCount -Details @{}
    # Silent
} catch {
    Add-AuditEntry -CheckName "Historical PCIe Devices" -Status "Error" -ItemsScanned 0 -SuspiciousFound 0 -Details @{ Error = $_.Exception.Message }
    # Silent error (logged)
}


# Check 3: Installed Drivers
Update-ScanProgress "System Drivers"
# Silent scanning...
try {
    $drivers = Get-WindowsDriver -Online -All
    $suspiciousCount = 0
    
    # Scan ALL drivers, not just those matching suspicious names
    foreach ($driver in $drivers) {
        $analysis = Get-DriverSuspicionScore -DriverName $driver.OriginalFileName -DriverPath $driver.OriginalFileName `
            -ProviderName $driver.ProviderName -ClassName $driver.ClassName -DriverDate $driver.Date -Version $driver.Version
        
        # Only report findings with meaningful suspicion scores
        if ($analysis.RiskLevel -notin @("LIKELY-SAFE", "INFO")) {
            $suspiciousCount += Report-ScoredFinding -Analysis $analysis -Name $driver.OriginalFileName -Category "Driver" `
                -ExtraDetails @{ ProviderName = $driver.ProviderName; ClassName = $driver.ClassName; Version = $driver.Version; Date = $driver.Date }
        }
    }
    
    Add-AuditEntry -CheckName "Installed Drivers" -Status "Completed" -ItemsScanned $drivers.Count -SuspiciousFound $suspiciousCount -Details @{}
    # Silent
} catch {
    Add-AuditEntry -CheckName "Installed Drivers" -Status "Error" -ItemsScanned 0 -SuspiciousFound 0 -Details @{ Error = $_.Exception.Message }
    # Silent error (logged)
}


# Check 4: Running Services and Drivers
Update-ScanProgress "Active Services"
# Silent scanning...
try {
    $runningDrivers = Get-CachedSystemDrivers | Where-Object { $_.State -eq "Running" }
    $suspiciousCount = 0
    
    # Scan ALL running drivers, not just those matching suspicious names
    foreach ($driver in $runningDrivers) {
        $analysis = Get-DriverSuspicionScore -DriverName $driver.Name -DriverPath $driver.PathName -ProviderName "" -ClassName "" -DriverDate $null -Version ""
        
        # Only report findings with meaningful suspicion scores (active drivers are higher risk)
        if ($analysis.RiskLevel -notin @("LIKELY-SAFE", "INFO")) {
            $suspiciousCount += Report-ScoredFinding -Analysis $analysis -Name $driver.Name -Category "Active Driver" -IsActive $true `
                -ExtraDetails @{ DisplayName = $driver.DisplayName; PathName = $driver.PathName; State = $driver.State; StartMode = $driver.StartMode }
        }
    }
    
    Add-AuditEntry -CheckName "Running Kernel Drivers" -Status "Completed" -ItemsScanned $runningDrivers.Count -SuspiciousFound $suspiciousCount -Details @{}
    # Silent
} catch {
    Add-AuditEntry -CheckName "Running Kernel Drivers" -Status "Error" -ItemsScanned 0 -SuspiciousFound 0 -Details @{ Error = $_.Exception.Message }
    # Silent error (logged)
}


# Check 5: Device Driver Store
Update-ScanProgress "Driver Repository"
# Silent scanning...
try {
    $driverStore = "C:\Windows\System32\DriverStore\FileRepository"
    $suspiciousCount = 0
    $totalPackages = 0
    
    if (Test-Path $driverStore) {
        $driverPackages = Get-ChildItem -Path $driverStore -Directory -ErrorAction SilentlyContinue
        $totalPackages = $driverPackages.Count
        
        # Scan ALL driver packages, not just those matching suspicious names
        foreach ($package in $driverPackages) {
            # Find actual driver file (.sys or .dll first, .inf only as fallback)
            # Optimize: Use -File to get files directly without pipeline
            $sysFiles = @(Get-ChildItem -Path $package.FullName -Filter "*.sys" -File -ErrorAction SilentlyContinue)
            $driverFile = if ($sysFiles.Count -gt 0) { $sysFiles[0] } else { $null }
            
            if (-not $driverFile) {
                $dllFiles = @(Get-ChildItem -Path $package.FullName -Filter "*.dll" -File -ErrorAction SilentlyContinue)
                $driverFile = if ($dllFiles.Count -gt 0) { $dllFiles[0] } else { $null }
            }
            # Don't use .inf for signature checking - it's a text file with no signature
            $driverFilePath = if ($driverFile) { $driverFile.FullName } else { $null }
            
            # Only check if we found an actual binary file
            if ($driverFilePath) {
                $analysis = Get-DriverSuspicionScore -DriverName $package.Name -DriverPath $driverFilePath -ProviderName "" -ClassName "" `
                    -DriverDate $package.CreationTime -Version ""
                
                # Only report MEDIUM or higher (reduce noise from legitimate drivers)
                if ($analysis.RiskLevel -in @("HIGH","MEDIUM")) {
                    $suspiciousCount += Report-ScoredFinding -Analysis $analysis -Name $package.Name -Category "Driver Store" `
                        -ExtraDetails @{ Path = $package.FullName; CreationTime = $package.CreationTime; DriverFile = $driverFile.Name }
                }
            }
        }
    }
    
    Add-AuditEntry -CheckName "Driver Store Scan" -Status "Completed" -ItemsScanned $totalPackages -SuspiciousFound $suspiciousCount -Details @{}
    # Silent
} catch {
    Add-AuditEntry -CheckName "Driver Store Scan" -Status "Error" -ItemsScanned 0 -SuspiciousFound 0 -Details @{ Error = $_.Exception.Message }
    # Silent error (logged)
}


# Check 6: Setup API Logs (Device Installation History)
Update-ScanProgress "Installation Logs"
# Silent scanning...
try {
    $setupApiLog = "C:\Windows\INF\setupapi.dev.log"
    $matchCount = 0
    
    if (Test-Path $setupApiLog) {
        $logContent = Get-Content $setupApiLog -Tail 5000 | Select-String -Pattern "FPGA|Xilinx|Altera|pcileech|screamer|VEN_10EE|VEN_1172" -Context 2
        $matchCount = if ($logContent) { $logContent.Count } else { 0 }
        
        if ($logContent) {
            # Suppressed finding
            Add-Finding -Category "Installation Log" -Severity "HIGH" `
                -Description "Suspicious device installation detected in logs" `
                -Details @{
                    LogFile = $setupApiLog
                    Matches = $logContent.Count
                    SampleEntries = ($logContent | Select-Object -First 5 | ForEach-Object { $_.Line })
                }
        }
    }
    
    Add-AuditEntry -CheckName "Setup API Logs" -Status "Completed" `
        -ItemsScanned 5000 -SuspiciousFound $matchCount `
        -Details @{ LogPath = $setupApiLog; LinesScanned = 5000; MatchesFound = $matchCount }
    
    # Silent
} catch {
    Add-AuditEntry -CheckName "Setup API Logs" -Status "Error" `
        -ItemsScanned 0 -SuspiciousFound 0 `
        -Details @{ Error = $_.Exception.Message }
    Write-Status "Error scanning setup logs: $($_.Exception.Message)" "Error"
}

# Check 7: Network Adapters
Update-ScanProgress "Network Configuration"
# Silent scanning...
try {
    $netAdapters = Get-NetAdapter
    $suspiciousCount = 0
    
    foreach ($adapter in $netAdapters) {
        # Check for generic or suspicious adapter names
        if ($adapter.InterfaceDescription -match "Unknown|Generic|FPGA|Xilinx") {
            # Suppressed finding
            $suspiciousCount++
            Add-Finding -Category "Network Adapter" -Severity "MEDIUM" `
                -Description "Unusual network adapter detected" `
                -Details @{
                    Name = $adapter.Name
                    Description = $adapter.InterfaceDescription
                    Status = $adapter.Status
                    MacAddress = $adapter.MacAddress
                    DriverVersion = $adapter.DriverVersion
                }
        }
    }
    
    Add-AuditEntry -CheckName "Network Adapters" -Status "Completed" `
        -ItemsScanned $netAdapters.Count -SuspiciousFound $suspiciousCount `
        -Details @{ TotalAdapters = $netAdapters.Count }
    
    # Silent
} catch {
    Add-AuditEntry -CheckName "Network Adapters" -Status "Error" `
        -ItemsScanned 0 -SuspiciousFound 0 `
        -Details @{ Error = $_.Exception.Message }
    Write-Status "Error scanning network adapters: $($_.Exception.Message)" "Error"
}

# Check 8: Check for DMA remapping (VT-d/IOMMU) status
# Silent scanning...
try {
    # Check if Kernel DMA Protection is enabled (Windows 10 1803+)
    $dmaProtection = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DmaSecurity" -Name "AllowExternalDevices" -ErrorAction SilentlyContinue
    $protectionEnabled = $false
    
    if ($dmaProtection) {
        if ($dmaProtection.AllowExternalDevices -eq 0) {
            # Silent
            $protectionEnabled = $true
        } else {
            # Silent
            Add-Finding -Category "Security Setting" -Severity "LOW" `
                -Description "Kernel DMA Protection is disabled" `
                -Details @{
                    Setting = "AllowExternalDevices"
                    Value = $dmaProtection.AllowExternalDevices
                    Recommendation = "Enable Kernel DMA Protection in BIOS/UEFI"
                }
        }
    } else {
        Write-Status "Kernel DMA Protection status unknown" "Info"
    }
    
    Add-AuditEntry -CheckName "DMA Protection Settings" -Status "Completed" `
        -ItemsScanned 1 -SuspiciousFound $(if (!$protectionEnabled -and $dmaProtection) { 1 } else { 0 }) `
        -Details @{ 
            ProtectionEnabled = $protectionEnabled
            RegistryKeyExists = ($null -ne $dmaProtection)
        }
} catch {
    Add-AuditEntry -CheckName "DMA Protection Settings" -Status "Error" `
        -ItemsScanned 0 -SuspiciousFound 0 `
        -Details @{ Error = $_.Exception.Message }
    Write-Status "Error checking DMA protection: $($_.Exception.Message)" "Error"
}

# Check 9: Suspicious Processes
Update-ScanProgress "Running Processes"
# Silent scanning...
try {
    $processes = Get-Process
    $suspiciousProcessNames = @("pcileech", "screamer", "kmboxnet", ".*loader.*", "ximenu", "aimassist", "triggerbot", 
        "bhop", "radar", "wallhack", "esp", "kdmapper", "drvmap", "kernelmap", ".*inject.*", ".*inj3ct.*", ".*bypass.*ac", ".*bypass.*eac", ".*bypass.*be")
    $suspiciousCount = 0
    
    foreach ($process in $processes) {
        foreach ($suspectName in $suspiciousProcessNames) {
            if ($process.Name -match $suspectName) {
                $cmdLine = Get-ProcessCommandLine -ProcessId $process.Id
                $analysis = Get-ProcessSuspicionScore -ProcessName $process.Name -ProcessPath $process.Path -CommandLine $cmdLine
                
                $suspiciousCount += Report-ScoredFinding -Analysis $analysis -Name "$($process.Name) (PID: $($process.Id))" -Category "Process" -IsActive $true `
                    -ExtraDetails @{ PID = $process.Id; Path = $process.Path; StartTime = $process.StartTime; CommandLine = $cmdLine }
                break
            }
        }
    }
    
    Add-AuditEntry -CheckName "Running Processes" -Status "Completed" -ItemsScanned $processes.Count -SuspiciousFound $suspiciousCount -Details @{}
    # Silent
} catch {
    Add-AuditEntry -CheckName "Running Processes" -Status "Error" -ItemsScanned 0 -SuspiciousFound 0 -Details @{ Error = $_.Exception.Message }
    # Silent error (logged)
}


# Check 10: Deep PCI Device Analysis
Update-ScanProgress "Device Verification"
# Silent scanning...
try {
    # Use cached PCI device lookup
    $allPciDevices = Get-CachedPciDevices
    $suspiciousCount = 0
    $spoofingIndicators = @()
    
    foreach ($device in $allPciDevices) {
        $hardwareId = ($device.HardwareID | Select-Object -First 1)
        $instanceId = $device.InstanceId
        $redFlags = @()
        
        # Extract VEN and DEV IDs
        if ($hardwareId -match "VEN_([0-9A-F]{4}).*DEV_([0-9A-F]{4})") {
            $venId = $matches[1]
            $devId = $matches[2]
            
            # Check 1: Commonly spoofed devices
            foreach ($spoofedSig in $commonlySpoofedDevices.Keys) {
                if ($hardwareId -like "*$spoofedSig*") {
                    $redFlags += "Device ID associated with hardware modifications"
                }
            }
            
            # Check 2: Mismatched class vs description (e.g., "Network" class but generic name)
            if ($device.Class -eq "Net" -and $device.FriendlyName -match "Generic|Unknown|Standard|Base") {
                $redFlags += "Network device with generic/suspicious name"
            }
            
            # Check 3: Multiple devices with same VEN/DEV (unusual for most hardware)
            $sameIdDevices = $allPciDevices | Where-Object { 
                $_.HardwareID -like "*VEN_$venId*" -and $_.HardwareID -like "*DEV_$devId*" 
            }
            if ($sameIdDevices.Count -gt 2) {
                $redFlags += "Multiple devices with identical VEN/DEV IDs (count: $($sameIdDevices.Count))"
            }
            
            # Check 4: Device location inconsistencies (check for missing parent or abnormal location)
            try {
                $devicePath = $instanceId -replace "\\", "\\"
                $regPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\$instanceId"
                if (Test-Path $regPath) {
                    $deviceProps = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
                    
                    # Check if ConfigFlags indicates issues
                    if ($deviceProps.ConfigFlags -and $deviceProps.ConfigFlags -ne 0) {
                        $redFlags += "Device has non-zero ConfigFlags (0x$($deviceProps.ConfigFlags.ToString('X')))"
                    }
                    
                    # Check if device has proper manufacturer info
                    if (-not $deviceProps.Mfg -or $deviceProps.Mfg -eq "") {
                        $redFlags += "Missing manufacturer information"
                    }
                    
                    # Check driver date - very old or very new drivers on "recent" hardware
                    if ($deviceProps.DriverDate) {
                        $driverDate = [DateTime]::Parse($deviceProps.DriverDate)
                        $now = Get-Date
                        if ($driverDate -lt (Get-Date "2010-01-01")) {
                            $redFlags += "Suspiciously old driver date: $driverDate"
                        }
                        if ($driverDate -gt $now.AddDays(1)) {
                            $redFlags += "Driver date in the future: $driverDate"
                        }
                    }
                }
            } catch { }
            
            # Check 5: Device not showing proper resources (DMA channels, memory ranges)
            try {
                $deviceResources = Get-PnpDeviceProperty -InstanceId $instanceId -KeyName "DEVPKEY_Device_ResourcePickerExceptions" -ErrorAction SilentlyContinue
                # Devices with no memory-mapped resources might be suspicious
            } catch { }
            
            # Check 6: Serial number analysis
            try {
                $serial = (Get-PnpDeviceProperty -InstanceId $instanceId -KeyName "DEVPKEY_Device_SerialNumber" -ErrorAction SilentlyContinue).Data
                if ($serial) {
                    if (Test-SuspiciousSerial -serial $serial) {
                        $redFlags += "Suspicious serial number pattern: $serial"
                    }
                }
            } catch { }
            
            # Check 7: Look for devices on unusual bus locations
            if ($instanceId -match 'PCI\\.*\\([0-9A-F]+)&') {
                $busLocation = $matches[1]
                # Most legitimate devices are on buses 0-10, higher numbers can be suspicious
                if ([int]"0x$busLocation" -gt 100) {
                    $redFlags += "Device on unusual high bus number: 0x$busLocation"
                }
            }
        }
        
        # If we found red flags, report it
        if ($redFlags.Count -gt 0) {
            # For commonly spoofed devices with only 1 red flag, add note about likely false positive
            if ($redFlags.Count -eq 1 -and $redFlags[0] -like "*Device ID commonly spoofed*") {
                # Silent - suppress output during scan
                
                # Still log as LOW severity for audit purposes
                $severity = "LOW"
                Add-Finding -Category "Spoofing Detection" -Severity $severity `
                    -Description "Device shows indicators of potential ID spoofing (likely false positive)" `
                    -Details @{
                        DeviceName = $device.FriendlyName
                        HardwareID = $hardwareId
                        InstanceID = $instanceId
                        Class = $device.Class
                        Status = $device.Status
                        RedFlags = $redFlags
                        RedFlagCount = $redFlags.Count
                        Note = "Only 1 red flag - commonly spoofed device ID but likely legitimate hardware"
                    }
            } else {
                # Multiple red flags - more suspicious
                $severity = if ($redFlags.Count -ge 3) { "HIGH" } elseif ($redFlags.Count -eq 2) { "MEDIUM" } else { "LOW" }
                $indicatorCount = $redFlags.Count
                $message = "Spoofing indicators detected on: $($device.FriendlyName) - $indicatorCount indicators"
                
                Write-Status $message "Warning"
                $suspiciousCount++
                
                Add-Finding -Category "Spoofing Detection" -Severity $severity `
                    -Description "Device shows indicators of potential ID spoofing" `
                    -Details @{
                        DeviceName = $device.FriendlyName
                        HardwareID = $hardwareId
                        InstanceID = $instanceId
                        Class = $device.Class
                        Status = $device.Status
                        RedFlags = $redFlags
                        RedFlagCount = $redFlags.Count
                    }
            }
        }
    }
    
    Add-AuditEntry -CheckName "Deep PCI Spoofing Analysis" -Status "Completed" `
        -ItemsScanned $allPciDevices.Count -SuspiciousFound $suspiciousCount `
        -Details @{ 
            TotalPCIDevices = $allPciDevices.Count
            DevicesWithSpoofingIndicators = $suspiciousCount
        }
    
    # Silent
} catch {
    Add-AuditEntry -CheckName "Deep PCI Spoofing Analysis" -Status "Error" `
        -ItemsScanned 0 -SuspiciousFound 0 `
        -Details @{ Error = $_.Exception.Message }
    Write-Status "Error in spoofing analysis: $($_.Exception.Message)" "Error"
}

# Check 11: Physical Device Verification (PCI Slot Analysis)
# Silent scanning...
try {
    $pciSlotInfo = @()
    $suspiciousCount = 0
    
    # Get PCI bus information using cached CIM data (faster than repeated queries)
    $pciBusDevices = Get-CachedWin32PnpEntity | Where-Object { 
        $_.PNPDeviceID -like "PCI\*" -and $_.Status -eq "OK" 
    }
    
    foreach ($pciDev in $pciBusDevices) {
        # Check device location strings for inconsistencies
        if ($pciDev.PNPDeviceID -match 'PCI\\VEN_([0-9A-F]{4})&DEV_([0-9A-F]{4})') {
            $venId = $matches[1]
            $devId = $matches[2]
            
            # Get location info
            try {
                $locationInfo = (Get-PnpDeviceProperty -InstanceId $pciDev.PNPDeviceID -KeyName "DEVPKEY_Device_LocationInfo" -ErrorAction SilentlyContinue).Data
                $busNumber = (Get-PnpDeviceProperty -InstanceId $pciDev.PNPDeviceID -KeyName "DEVPKEY_Device_BusNumber" -ErrorAction SilentlyContinue).Data
                
                # Check if device reports inconsistent location data
                if ($locationInfo -and $locationInfo -match "Internal|Unknown|Generic") {
                    $suspiciousCount++
                    Add-Finding -Category "Physical Location" -Severity "MEDIUM" `
                        -Description "Device reports suspicious physical location" `
                        -Details @{
                            DeviceName = $pciDev.Name
                            DeviceID = $pciDev.PNPDeviceID
                            LocationInfo = $locationInfo
                            BusNumber = $busNumber
                        }
                }
            } catch { }
        }
    }
    
    Add-AuditEntry -CheckName "Physical PCI Slot Analysis" -Status "Completed" `
        -ItemsScanned $pciBusDevices.Count -SuspiciousFound $suspiciousCount `
        -Details @{ TotalPCIBusDevices = $pciBusDevices.Count }
    
    # Silent
} catch {
    Add-AuditEntry -CheckName "Physical PCI Slot Analysis" -Status "Error" `
        -ItemsScanned 0 -SuspiciousFound 0 `
        -Details @{ Error = $_.Exception.Message }
    Write-Status "Error in physical slot analysis: $($_.Exception.Message)" "Error"
}

# Check 12: Device Capability Analysis (Check for DMA capabilities)
# Silent scanning...
try {
    # Use cached PCI devices and filter for OK status
    $allDevices = Get-CachedPciDevices | Where-Object { $_.Status -eq "OK" }
    $suspiciousCount = 0
    
    foreach ($dev in $allDevices) {
        try {
            # Check device capabilities
            $capabilities = Get-PnpDeviceProperty -InstanceId $dev.InstanceId -KeyName "DEVPKEY_Device_Capabilities" -ErrorAction SilentlyContinue
            $memRanges = Get-PnpDeviceProperty -InstanceId $dev.InstanceId -KeyName "DEVPKEY_Device_Address" -ErrorAction SilentlyContinue
            
            # Get device class - some classes should NOT have DMA
            $deviceClass = $dev.Class
            $deviceName = $dev.FriendlyName
            
            # Security: Device functionality cross-check (detect spoofed device classes)
            # If device claims to be network adapter, verify it has actual network functionality
            if ($deviceClass -eq "Net") {
                try {
                    $netAdapter = Get-NetAdapter -ErrorAction SilentlyContinue | 
                        Where-Object { $_.InterfaceDescription -eq $deviceName }
                    
                    if (-not $netAdapter) {
                        # Device claims to be network adapter but has no network interface
                        $suspiciousCount++
                        Add-Finding -Category "Device Functionality Mismatch" -Severity "HIGH" `
                            -Description "Device claims to be network adapter but has no active network interface" `
                            -Details @{
                                DeviceName = $deviceName
                                DeviceClass = $deviceClass
                                InstanceID = $dev.InstanceId
                                Issue = "Class=Net but not found in Get-NetAdapter - possible spoofing"
                            }
                    }
                } catch { }
            }
            
            # Check for certificate vs device manufacturer mismatch
            try {
                $deviceMfr = (Get-PnpDeviceProperty -InstanceId $dev.InstanceId -KeyName "DEVPKEY_Device_Manufacturer" -ErrorAction SilentlyContinue).Data
                $driverInfPath = (Get-PnpDeviceProperty -InstanceId $dev.InstanceId -KeyName "DEVPKEY_Device_DriverInfPath" -ErrorAction SilentlyContinue).Data
                
                if ($driverInfPath) {
                    $infFullPath = Join-Path "$env:SystemRoot\INF" $driverInfPath
                    if (Test-Path $infFullPath) {
                        $infContent = Get-Content $infFullPath -ErrorAction SilentlyContinue | Select-Object -First 50
                        $infProvider = ($infContent | Where-Object { $_ -match "^Provider\s*=" }) -replace "Provider\s*=\s*", "" -replace '["%]', ''
                        
                        # Check for manufacturer mismatch
                        if ($deviceMfr -and $infProvider) {
                            # If device says Intel but INF says WCH = suspicious
                            if ($deviceMfr -match "Intel" -and $infProvider -match "WCH|FTDI|Prolific") {
                                $suspiciousCount++
                                Add-Finding -Category "Device Functionality Mismatch" -Severity "HIGH" `
                                    -Description "Device manufacturer doesn't match driver provider" `
                                    -Details @{
                                        DeviceName = $deviceName
                                        DeviceManufacturer = $deviceMfr
                                        DriverProvider = $infProvider
                                        InstanceID = $dev.InstanceId
                                        Issue = "Manufacturer mismatch suggests device spoofing"
                                    }
                            }
                        }
                    }
                }
            } catch { }
            
            # Suspicious: USB devices reporting as PCI (may indicate hardware configuration anomaly)
            $compatIds = (Get-PnpDeviceProperty -InstanceId $dev.InstanceId -KeyName "DEVPKEY_Device_CompatibleIds" -ErrorAction SilentlyContinue).Data
            if ($dev.InstanceId -like "PCI\*" -and $compatIds -like "*USB*") {
                $suspiciousCount++
                Add-Finding -Category "Device Capability Mismatch" -Severity "HIGH" `
                    -Description "PCI device reporting USB compatibility (possible spoofing)" `
                    -Details @{
                        DeviceName = $deviceName
                        InstanceID = $dev.InstanceId
                        CompatibleIDs = $compatIds
                    }
            }
            
            # Check for devices with large memory ranges (hardware devices with extended memory mappings)
            $configResources = Get-PnpDeviceProperty -InstanceId $dev.InstanceId -KeyName "DEVPKEY_Device_ResourcePickerTags" -ErrorAction SilentlyContinue
            
            # Devices that are network adapters but have unusual memory configurations
            if ($deviceClass -eq "Net") {
                $driver = Get-PnpDeviceProperty -InstanceId $dev.InstanceId -KeyName "DEVPKEY_Device_DriverDesc" -ErrorAction SilentlyContinue
                if ($driver.Data -match "Generic|Unknown|Standard PCI") {
                    $suspiciousCount++
                    Add-Finding -Category "Device Capability Mismatch" -Severity "MEDIUM" `
                        -Description "Network device with generic driver description" `
                        -Details @{
                            DeviceName = $deviceName
                            InstanceID = $dev.InstanceId
                            DriverDescription = $driver.Data
                        }
                }
            }
        } catch { }
    }
    
    Add-AuditEntry -CheckName "Device DMA Capability Analysis" -Status "Completed" `
        -ItemsScanned $allDevices.Count -SuspiciousFound $suspiciousCount `
        -Details @{ TotalDevicesAnalyzed = $allDevices.Count }
    
    # Silent
} catch {
    Add-AuditEntry -CheckName "Device DMA Capability Analysis" -Status "Error" `
        -ItemsScanned 0 -SuspiciousFound 0 `
        -Details @{ Error = $_.Exception.Message }
    Write-Status "Error in capability analysis: $($_.Exception.Message)" "Error"
}

# Check 13: BIOS/UEFI Security Settings
Update-ScanProgress "Firmware Security"
# Silent scanning...
try {
    $securityIssues = 0
    
    # Check SecureBoot status
    try {
        $secureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
        if ($secureBoot -eq $false) {
            # Silent
            $securityIssues++
            Add-Finding -Category "BIOS Security" -Severity "MEDIUM" `
                -Description "SecureBoot is disabled - reduces system security" `
                -Details @{
                    Setting = "SecureBoot"
                    Status = "Disabled"
                    Recommendation = "Enable SecureBoot in BIOS/UEFI"
                }
        } else {
            # Silent
        }
    } catch {
        # Silent
    }
    
    # Check TPM status
    try {
        $tpm = Get-Tpm -ErrorAction SilentlyContinue
        if ($tpm -and -not $tpm.TpmPresent) {
            # Silent
            $securityIssues++
            Add-Finding -Category "BIOS Security" -Severity "LOW" `
                -Description "TPM not present or disabled" `
                -Details @{
                    Setting = "TPM"
                    Status = "Not Present"
                    Recommendation = "Enable TPM in BIOS if available"
                }
        } elseif ($tpm -and -not $tpm.TpmEnabled) {
            Write-Status "TPM present but not enabled" "Warning"
            $securityIssues++
            Add-Finding -Category "BIOS Security" -Severity "LOW" `
                -Description "TPM present but not enabled" `
                -Details @{
                    Setting = "TPM"
                    Status = "Disabled"
                    Recommendation = "Enable TPM in BIOS"
                }
        }
    } catch {
        Write-Status "TPM status could not be determined" "Info"
    }
    
    # Check for virtualization settings (VT-d/IOMMU should be enabled for DMA protection)
    try {
        # Use CIM instead of WMI
        $virtualization = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1 -ExpandProperty VirtualizationFirmwareEnabled
        if ($virtualization -eq $false) {
            # Silent
        }
    } catch { }
    
    Add-AuditEntry -CheckName "BIOS/UEFI Security Settings" -Status "Completed" `
        -ItemsScanned 3 -SuspiciousFound $securityIssues `
        -Details @{ 
            SecureBootChecked = $true
            TPMChecked = $true
            VirtualizationChecked = $true
        }
    
    # Silent
} catch {
    Add-AuditEntry -CheckName "BIOS/UEFI Security Settings" -Status "Error" `
        -ItemsScanned 0 -SuspiciousFound 0 `
        -Details @{ Error = $_.Exception.Message }
    Write-Status "Error checking BIOS settings: $($_.Exception.Message)" "Error"
}

# Check 14: Network Connection Anomalies (Secondary PC Detection)
# Silent scanning...
try {
    $suspiciousConnections = 0
    
    # Check local network connections (advanced configurations may use secondary systems)
    $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | 
        Where-Object { $_.RemoteAddress -match "^192\.168\.|^10\.|^172\.(1[6-9]|2[0-9]|3[01])\." }
    
    foreach ($conn in $connections) {
        $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
        if ($process) {
            $isSMB = $conn.RemotePort -in @(445, 139) -or $conn.LocalPort -in @(445, 139)
            $cmdLine = Get-ProcessCommandLine -ProcessId $process.Id
            $analysis = Get-ProcessSuspicionScore -ProcessName $process.Name -ProcessPath $process.Path -CommandLine $cmdLine
            
            # SMB from System is normal file sharing
            if ($isSMB -and $process.Name -eq "System") { continue }
            
            if ($analysis.RiskLevel -notin @("LIKELY-SAFE","INFO")) {
                $suspiciousConnections += Report-ScoredFinding -Analysis $analysis -Name "$($process.Name) → $($conn.RemoteAddress):$($conn.RemotePort)" `
                    -Category "Network Anomaly" -ExtraDetails @{ ProcessPath = $process.Path; LocalAddress = "$($conn.LocalAddress):$($conn.LocalPort)"; RemoteAddress = "$($conn.RemoteAddress):$($conn.RemotePort)" }
            }
        }
    }
    
    # Check suspicious port listeners
    $suspiciousPorts = @(35000..35100) + @(4444, 31337, 1337, 8888)
    $localListeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $suspiciousPorts -contains $_.LocalPort }
    
    foreach ($listener in $localListeners) {
        $process = Get-Process -Id $listener.OwningProcess -ErrorAction SilentlyContinue
        if ($process) {
            $cmdLine = Get-ProcessCommandLine -ProcessId $process.Id
            $analysis = Get-ProcessSuspicionScore -ProcessName $process.Name -ProcessPath $process.Path -CommandLine $cmdLine
            $analysis.Score += 10  # Suspicious port adds points
            $analysis.Evidence += "Listening on suspicious port $($listener.LocalPort)"
            $analysis.RiskLevel = if ($analysis.Score -ge 30) { "HIGH" } elseif ($analysis.Score -ge 15) { "MEDIUM" } elseif ($analysis.Score -ge 5) { "LOW" } else { "INFO" }
            
            if ($analysis.RiskLevel -notin @("LIKELY-SAFE","INFO")) {
                $suspiciousConnections += Report-ScoredFinding -Analysis $analysis -Name "$($process.Name) on port $($listener.LocalPort)" `
                    -Category "Network Anomaly" -ExtraDetails @{ ProcessPath = $process.Path; Port = $listener.LocalPort }
            }
        }
    }
    
    Add-AuditEntry -CheckName "Network Connection Anomalies" -Status "Completed" -ItemsScanned ($connections.Count + $localListeners.Count) -SuspiciousFound $suspiciousConnections -Details @{}
    # Silent
} catch {
    Add-AuditEntry -CheckName "Network Connection Anomalies" -Status "Error" -ItemsScanned 0 -SuspiciousFound 0 -Details @{ Error = $_.Exception.Message }
    # Silent error (logged)
}


# Check 15: Registry Timestamp Analysis (Recent Device Installations)
# Silent scanning...
try {
    $recentInstalls = 0
    $cutoffDate = (Get-Date).AddHours(-24)  # Flag devices installed in last 24 hours
    
    # Use cached PCI devices
    $pciDevices = Get-CachedPciDevices
    
    foreach ($device in $pciDevices) {
        try {
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\$($device.InstanceId)"
            if (Test-Path $regPath) {
                $regKey = Get-Item $regPath -ErrorAction SilentlyContinue
                
                if ($regKey) {
                    # Get registry key last write time
                    $lastWriteTime = $regKey.LastWriteTime
                    
                    # Check if device was recently added/modified
                    if ($lastWriteTime -gt $cutoffDate) {
                        $recentInstalls++
                        # Suppressed finding
                        
                        Add-Finding -Category "Recent Installation" -Severity "MEDIUM" `
                            -Description "Device registry modified in last 24 hours" `
                            -Details @{
                                DeviceName = $device.FriendlyName
                                InstanceID = $device.InstanceId
                                LastModified = $lastWriteTime
                                HoursSinceModification = [math]::Round(((Get-Date) - $lastWriteTime).TotalHours, 1)
                            }
                    }
                }
            }
        } catch { }
    }
    
    Add-AuditEntry -CheckName "Registry Timestamp Analysis" -Status "Completed" `
        -ItemsScanned $pciDevices.Count -SuspiciousFound $recentInstalls `
        -Details @{ 
            TotalDevicesChecked = $pciDevices.Count
            RecentInstallations = $recentInstalls
            CutoffDate = $cutoffDate
        }
    
    # Silent
} catch {
    Add-AuditEntry -CheckName "Registry Timestamp Analysis" -Status "Error" `
        -ItemsScanned 0 -SuspiciousFound 0 `
        -Details @{ Error = $_.Exception.Message }
    Write-Status "Error analyzing registry timestamps: $($_.Exception.Message)" "Error"
}

# Check 16: Memory Access Pattern Analysis
# Silent scanning...
try {
    $suspiciousMemory = 0
    $processes = Get-Process | Where-Object { $_.WorkingSet64 -gt 0 }
    
    foreach ($process in $processes) {
        try {
            # Check for processes with unusually large memory footprints
            # (excluding known memory-hungry apps)
            if ($process.WorkingSet64 -gt 2GB -and 
                $process.Name -notmatch "chrome|firefox|edge|game|unreal|unity|photoshop|premiere|aftereffects") {
                
                $suspiciousMemory++
                Add-Finding -Category "Memory Pattern" -Severity "LOW" `
                    -Description "Process with large memory footprint" `
                    -Details @{
                        ProcessName = $process.Name
                        ProcessPath = $process.Path
                        WorkingSetGB = [math]::Round($process.WorkingSet64 / 1GB, 2)
                        PrivateMemoryGB = [math]::Round($process.PrivateMemorySize64 / 1GB, 2)
                    }
            }
        } catch { }
    }
    
    Add-AuditEntry -CheckName "Memory Access Pattern Analysis" -Status "Completed" `
        -ItemsScanned $processes.Count -SuspiciousFound $suspiciousMemory `
        -Details @{ TotalProcessesAnalyzed = $processes.Count }
    
    # Silent
} catch {
    Add-AuditEntry -CheckName "Memory Access Pattern Analysis" -Status "Error" `
        -ItemsScanned 0 -SuspiciousFound 0 `
        -Details @{ Error = $_.Exception.Message }
    Write-Status "Error in memory analysis: $($_.Exception.Message)" "Error"
}

# Check 17: Registry Anomaly Detection
# Silent scanning...
try {
    $suspiciousRegEntries = 0
    $registryChecks = 0
    
    # 1. Check for orphaned device entries (devices removed but registry remains)
    Write-Verbose "Checking for orphaned device entries..."
    $pciRegPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\PCI"
    if (Test-Path $pciRegPath) {
        $pciRegDevices = Get-ChildItem -Path $pciRegPath -Recurse -ErrorAction SilentlyContinue | 
            Where-Object { $_.PSChildName -match "^[0-9]+" }
        
        $currentDeviceIds = (Get-CachedPciDevices).InstanceId
        $registryChecks += $pciRegDevices.Count
        
        foreach ($regDevice in $pciRegDevices) {
            $instanceId = $regDevice.PSPath -replace ".*\\Enum\\", ""
            $instanceId = $instanceId -replace "\\[0-9]+$", "\$($regDevice.PSChildName)"
            
            # Check if device exists in current system
            if ($instanceId -notin $currentDeviceIds) {
                try {
                    $friendlyName = (Get-ItemProperty -Path $regDevice.PSPath -Name "FriendlyName" -ErrorAction SilentlyContinue).FriendlyName
                    $hardwareId = (Get-ItemProperty -Path $regDevice.PSPath -Name "HardwareID" -ErrorAction SilentlyContinue).HardwareID
                    $installDate = (Get-ItemProperty -Path $regDevice.PSPath -Name "InstallDate" -ErrorAction SilentlyContinue).InstallDate
                    
                    # Check if it was recently removed (suspicious if removed in last 31 days)
                    if ($installDate) {
                        $installDateTime = [DateTime]::ParseExact($installDate, "yyyyMMdd", $null)
                        $daysSinceInstall = ((Get-Date) - $installDateTime).Days
                        
                        if ($daysSinceInstall -le 31 -and $friendlyName) {
                            Write-Host "[$(Get-Date -Format 'HH:mm:ss')] " -NoNewline
                            Write-Host "[i] " -ForegroundColor Yellow -NoNewline
                            Write-Host "Recently removed device found in registry: $friendlyName" -ForegroundColor Yellow
                            
                            $suspiciousRegEntries++
                            Add-Finding -Category "Registry Anomaly" -Severity "LOW" `
                                -Description "Recently removed PCI device found in registry (removed within 31 days)" `
                                -Details @{
                                    FriendlyName = $friendlyName
                                    InstanceID = $instanceId
                                    HardwareID = $hardwareId -join "; "
                                    InstallDate = $installDate
                                    DaysSinceInstall = $daysSinceInstall
                                    Note = "Device was installed but is no longer connected - may indicate DMA hardware temporarily connected"
                                }
                        }
                    }
                } catch { }
            }
        }
    }
    
    # 2. Check for registry entries with suspicious patterns
    Write-Verbose "Checking for suspicious registry values..."
    
    # Check for tampered device capabilities
    foreach ($device in (Get-CachedPciDevices | Select-Object -First 50)) {
        try {
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\$($device.InstanceId)"
            if (Test-Path $regPath) {
                $registryChecks++
                
                # Check for suspicious ConfigFlags (device disabled/hidden flags)
                $configFlags = (Get-ItemProperty -Path $regPath -Name "ConfigFlags" -ErrorAction SilentlyContinue).ConfigFlags
                if ($configFlags -band 0x00000001) {  # CONFIGFLAG_DISABLED
                    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] " -NoNewline
                    Write-Host "[!] " -ForegroundColor Yellow -NoNewline
                    Write-Host "Device with DISABLED flag: $($device.FriendlyName)" -ForegroundColor Yellow
                    
                    $suspiciousRegEntries++
                    Add-Finding -Category "Registry Anomaly" -Severity "LOW" `
                        -Description "Device has DISABLED configuration flag in registry" `
                        -Details @{
                            DeviceName = $device.FriendlyName
                            InstanceID = $device.InstanceId
                            ConfigFlags = "0x{0:X8}" -f $configFlags
                            Note = "Device appears disabled in registry but may still be accessible - potential hiding attempt"
                        }
                }
                
                # Check for missing or suspicious driver entries
                $driver = (Get-ItemProperty -Path $regPath -Name "Driver" -ErrorAction SilentlyContinue).Driver
                $service = (Get-ItemProperty -Path $regPath -Name "Service" -ErrorAction SilentlyContinue).Service
                
                if (-not $driver -and -not $service) {
                    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] " -NoNewline
                    Write-Host "[i] " -ForegroundColor Yellow -NoNewline
                    Write-Host "Device without driver reference: $($device.FriendlyName)" -ForegroundColor Yellow
                    
                    $suspiciousRegEntries++
                    Add-Finding -Category "Registry Anomaly" -Severity "LOW" `
                        -Description "PCI device has no driver or service reference in registry" `
                        -Details @{
                            DeviceName = $device.FriendlyName
                            InstanceID = $device.InstanceId
                            Status = $device.Status
                            Note = "Device operational but missing driver reference - may indicate driver tampering"
                        }
                }
            }
        } catch { }
    }
    
    # 3. Check for suspicious service entries (kernel drivers)
    Write-Verbose "Analyzing all kernel driver services..."
    $services = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\*" -ErrorAction SilentlyContinue | 
        Where-Object { $_.Type -eq 1 }  # Type 1 = Kernel Driver
    
    foreach ($service in $services) {
        $registryChecks++
        $serviceName = $service.PSChildName
        
        # Analyze each driver based on evidence, not path whitelisting
        if ($service.ImagePath) {
            $imagePath = $service.ImagePath -replace '\\SystemRoot\\', 'C:\Windows\'
            $imagePath = $imagePath -replace '\\\?\?\\', ''  # Remove device path prefix
            
            # Score the driver based on all characteristics
            $suspicionScore = 0
            $evidence = @()
            
            # Check for suspicious name patterns
            foreach ($suspectName in $suspiciousDrivers) {
                if ($serviceName -like "*$suspectName*" -or $imagePath -like "*$suspectName*") {
                    $suspicionScore += 15
                    $evidence += "Matches suspicious driver pattern: $suspectName"
                    break
                }
            }
            
            # Check path characteristics (evidence, not filter)
            if ($imagePath -match "\\temp\\|\\downloads\\|\\users\\.*\\appdata\\") {
                $suspicionScore += 20
                $evidence += "Located in suspicious user directory"
            }
            
            # Windows system paths are GOOD, not bad
            $isWindowsPath = $imagePath -match "\\Windows\\System32\\|\\Windows\\SysWOW64\\|^System32\\|C:\\Windows\\"
            if (-not $isWindowsPath -and $imagePath -notmatch "\\Program Files") {
                $suspicionScore += 5
                $evidence += "Located outside Windows directories"
            }
            
            # Check for no file extension or wrong extension
            if ($imagePath -notmatch "\.(sys|dll)$") {
                $suspicionScore += 10
                $evidence += "Missing or unusual file extension"
            }
            
            # Check Start type (0=boot, 1=system, 2=auto, 3=manual, 4=disabled)
            if ($service.Start -eq 0 -or $service.Start -eq 1) {
                # Boot/System start drivers with suspicious characteristics are higher risk
                if ($suspicionScore -gt 0) {
                    $suspicionScore += 10
                    $evidence += "Boot/System start driver with suspicious traits"
                }
            }
            
            # Check for missing or unsigned file - resolve Windows path variables
            $fullPath = $imagePath
            if ($imagePath -match "^System32\\") {
                $fullPath = "C:\Windows\$imagePath"
            }
            
            if (Test-Path $fullPath -ErrorAction SilentlyContinue) {
                try {
                    $sig = Get-AuthenticodeSignature $fullPath -ErrorAction SilentlyContinue
                    if ($sig.Status -ne "Valid") {
                        # Microsoft signed drivers are OK even if "expired"
                        if ($sig.SignerCertificate.Subject -notmatch "Microsoft") {
                            $suspicionScore += 15
                            $evidence += "Driver file not properly signed"
                        }
                    }
                } catch {
                    # Ignore signature check errors for Windows system files
                    if (-not $isWindowsPath) {
                        $suspicionScore += 10
                        $evidence += "Could not verify driver signature"
                    }
                }
            } else {
                # Missing file - only flag if not a Windows system path
                if (-not $isWindowsPath) {
                    $suspicionScore += 20
                    $evidence += "Driver file does not exist at specified path"
                }
            }
            
            # Report based on total evidence score - much higher threshold
            if ($suspicionScore -ge 40) {
                $suspiciousRegEntries++
                $severity = if ($suspicionScore -ge 60) { "HIGH" } elseif ($suspicionScore -ge 50) { "MEDIUM" } else { "LOW" }
                
                Add-Finding -Category "Driver Service Analysis" -Severity $severity `
                    -Description "Kernel driver service with suspicious characteristics (Score: $suspicionScore)" `
                    -Details @{
                        ServiceName = $serviceName
                        ImagePath = $imagePath
                        Start = $service.Start
                        Type = $service.Type
                        SuspicionScore = $suspicionScore
                        Evidence = ($evidence -join "; ")
                    }
            }
        }
    }
    
    # 4. Check for tampered DeviceDesc (device spoofing indicator)
    Write-Verbose "Checking for tampered device descriptions..."
    foreach ($device in (Get-CachedPciDevices | Select-Object -First 30)) {
        try {
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\$($device.InstanceId)"
            if (Test-Path $regPath) {
                $deviceDesc = (Get-ItemProperty -Path $regPath -Name "DeviceDesc" -ErrorAction SilentlyContinue).DeviceDesc
                $friendlyName = (Get-ItemProperty -Path $regPath -Name "FriendlyName" -ErrorAction SilentlyContinue).FriendlyName
                
                # Check for mismatches or generic descriptions
                if ($deviceDesc -and $friendlyName -and $deviceDesc -ne $friendlyName) {
                    if ($deviceDesc -match "Generic|Unknown|Standard|Base" -or $friendlyName -match "Generic|Unknown|Standard|Base") {
                        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] " -NoNewline
                        Write-Host "[i] " -ForegroundColor Yellow -NoNewline
                        Write-Host "Device with generic description: $friendlyName" -ForegroundColor Yellow
                        
                        $suspiciousRegEntries++
                        Add-Finding -Category "Registry Anomaly" -Severity "LOW" `
                            -Description "Device has generic or mismatched description in registry" `
                            -Details @{
                                DeviceName = $device.FriendlyName
                                DeviceDesc = $deviceDesc
                                FriendlyName = $friendlyName
                                InstanceID = $device.InstanceId
                                Note = "Generic device description may indicate spoofed or improperly configured device"
                            }
                    }
                }
            }
        } catch { }
    }
    
    Add-AuditEntry -CheckName "Registry Anomaly Detection" -Status "Completed" `
        -ItemsScanned $registryChecks -SuspiciousFound $suspiciousRegEntries `
        -Details @{ 
            RegistryEntriesChecked = $registryChecks
            OrphanedDevices = "Checked for removed devices"
            ServiceEntries = "Checked kernel driver services"
        }
    
    # Silent
} catch {
    Add-AuditEntry -CheckName "Registry Anomaly Detection" -Status "Error" `
        -ItemsScanned 0 -SuspiciousFound 0 `
        -Details @{ Error = $_.Exception.Message }
    Write-Status "Error scanning registry: $($_.Exception.Message)" "Error"
}

# Forensic Data Collection for Offline Auditing
Write-Host "`n========================================" -ForegroundColor Magenta
Write-Host "    FORENSIC DATA COLLECTION" -ForegroundColor Magenta
Write-Host "========================================`n" -ForegroundColor Magenta
Update-ScanProgress "Collecting Logs"

# Create results folder structure with timestamp and computer name
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$resultsFolder = Join-Path $PSScriptRoot "results"

# Security: Validate base results directory
if (-not (Test-Path $resultsFolder)) {
    try {
        $null = New-Item -Path $resultsFolder -ItemType Directory -Force
        
        # Security: Set restrictive ACLs on results folder (only current user + admins)
        $acl = Get-Acl $resultsFolder
        $acl.SetAccessRuleProtection($true, $false)  # Disable inheritance
        
        # Add current user
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($currentUser, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        $acl.AddAccessRule($accessRule)
        
        # Add Administrators group
        $adminsGroup = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
        $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule($adminsGroup, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        $acl.AddAccessRule($adminRule)
        
        Set-Acl -Path $resultsFolder -AclObject $acl
    } catch {
        Write-Host "[ERROR] Failed to create secure results folder: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "[!] Continuing with default permissions..." -ForegroundColor Yellow
    }
}

# Security: Sanitize computer name for safe folder creation
$safeComputerName = Get-SafeFileName -FileName $env:COMPUTERNAME
$scanFolder = Join-Path $resultsFolder "${timestamp}_${safeComputerName}"

# Security: Validate scan folder path is within results folder
if (-not (Test-SafePath -Path $scanFolder -BaseDirectory $resultsFolder)) {
    Write-Host "[ERROR] Security violation: Invalid scan folder path detected" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $scanFolder)) {
    $null = New-Item -Path $scanFolder -ItemType Directory -Force
}

$forensicFolder = Join-Path $scanFolder "System-Analysis-Data"

# Security: Validate forensic folder path
if (-not (Test-SafePath -Path $forensicFolder -BaseDirectory $scanFolder)) {
    Write-Host "[ERROR] Security violation: Invalid forensic folder path detected" -ForegroundColor Red
    exit 1
}

$null = New-Item -Path $forensicFolder -ItemType Directory -Force

# Initialize comprehensive operation log for forensic verification
$operationLogPath = Join-Path $forensicFolder "OPERATION_LOG.txt"
Initialize-OperationLog -LogPath $operationLogPath

Write-OperationLog "═══════════════════════════════════════════════════════════════" "INFO"
Write-OperationLog "SYSTEM ANALYSIS STARTING" "INFO"
Write-OperationLog "═══════════════════════════════════════════════════════════════" "INFO"
Write-OperationLog "Forensic data collection folder created" "ACTION" -Details @{
    Path = $forensicFolder
    CreatedAt = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
}

try {
    # 1. Collect System Information
    # Silent collection
    $sysInfoPath = Join-Path $forensicFolder "SystemInfo.txt"
    
    Write-OperationLog "Collecting system information" "QUERY" -Details @{
        Command = "systeminfo.exe"
        OutputPath = $sysInfoPath
    }
    
    # Security: Validate systeminfo command exists and execute safely
    $systeminfoCmd = Get-Command systeminfo.exe -ErrorAction SilentlyContinue
    if ($systeminfoCmd) {
        try {
            & $systeminfoCmd.Source | Out-File -FilePath $sysInfoPath -Encoding UTF8 -ErrorAction Stop
            Write-OperationLog "System information collected successfully" "SUCCESS" -Details @{
                FileSize = (Get-Item $sysInfoPath).Length
                Lines = (Get-Content $sysInfoPath).Count
            }
        } catch {
            Write-OperationLog "Failed to collect system information" "ERROR" -Details @{
                Error = $_.Exception.Message
            }
            Write-Host "[!] Warning: Failed to collect system information: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    } else {
        Write-OperationLog "systeminfo.exe command not found" "WARNING"
    }
    
    Get-ComputerInfo -ErrorAction SilentlyContinue | ConvertTo-Json -Depth 5 -WarningAction SilentlyContinue | Out-File -FilePath (Join-Path $forensicFolder "ComputerInfo.json") -Encoding UTF8
    
    # 2. Export Registry Keys (Device History)
    # Silent collection
    $regFolder = Join-Path $forensicFolder "Registry"
    $null = New-Item -Path $regFolder -ItemType Directory -Force
    
    Write-OperationLog "═══════════════════════════════════════════════════════════════" "INFO"
    Write-OperationLog "REGISTRY EXPORT PHASE STARTING" "INFO"
    Write-OperationLog "═══════════════════════════════════════════════════════════════" "INFO"
    
    # Security: Validate reg.exe and execute registry exports safely
    $regCmd = Get-Command reg.exe -ErrorAction SilentlyContinue
    if (-not $regCmd) {
        Write-OperationLog "reg.exe command not found - skipping registry exports" "WARNING"
        Write-Host "[!] Warning: reg.exe not found, skipping registry exports" -ForegroundColor Yellow
    } else {
        Write-OperationLog "reg.exe located" "INFO" -Details @{
            Path = $regCmd.Source
            Version = $regCmd.Version
        }
        
        # Security: Define allowed registry keys for export (defense-in-depth)
        $allowedRegistryKeys = @(
            "HKLM\SYSTEM\CurrentControlSet\Enum",
            "HKLM\SYSTEM\CurrentControlSet\Services",
            "HKLM\SYSTEM\CurrentControlSet\Control\Class",
            "HKLM\SYSTEM\CurrentControlSet\Enum\USB",
            "HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR",
            "HKLM\SYSTEM\CurrentControlSet\Enum\PCI",
            "HKLM\SYSTEM\DriverDatabase"
        )
        
        # Device enumeration keys - validate each export
        $regExports = @(
            @{ Key = "HKLM\SYSTEM\CurrentControlSet\Enum"; File = "DeviceEnum.reg" }
            @{ Key = "HKLM\SYSTEM\CurrentControlSet\Services"; File = "Services.reg" }
            @{ Key = "HKLM\SYSTEM\CurrentControlSet\Control\Class"; File = "DeviceClasses.reg" }
            @{ Key = "HKLM\SYSTEM\CurrentControlSet\Enum\USB"; File = "USB_History.reg" }
            @{ Key = "HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR"; File = "USBStorage_History.reg" }
            @{ Key = "HKLM\SYSTEM\CurrentControlSet\Enum\PCI"; File = "PCI_Devices.reg" }
            @{ Key = "HKLM\SYSTEM\DriverDatabase"; File = "DriverDatabase.reg" }
        )
        
        Write-OperationLog "Starting registry exports" "ACTION" -Details @{
            TotalExports = $regExports.Count
            OutputFolder = $regFolder
        }
        
        foreach ($export in $regExports) {
            # Security: Validate registry key against allowlist
            if ($allowedRegistryKeys -notcontains $export.Key) {
                Write-OperationLog "Registry key not in allowlist - skipping" "WARNING" -Details @{
                    Key = $export.Key
                }
                Write-Verbose "Skipping unauthorized registry key: $($export.Key)"
                continue
            }
            
            Write-OperationLog "Exporting registry key" "QUERY" -Details @{
                RegistryKey = $export.Key
                OutputFile = $export.File
                Command = "reg.exe export"
            }
            
            try {
                $outputFile = Join-Path $regFolder $export.File
                $startTime = Get-Date
                $result = & $regCmd.Source export $export.Key $outputFile /y 2>&1
                $duration = ((Get-Date) - $startTime).TotalMilliseconds
                
                if ($LASTEXITCODE -ne 0) {
                    Write-OperationLog "Registry export failed" "ERROR" -Details @{
                        Key = $export.Key
                        ExitCode = $LASTEXITCODE
                        ErrorOutput = $result
                        DurationMs = [math]::Round($duration, 2)
                    }
                    Write-Verbose "Registry export failed for $($export.Key): $result"
                } else {
                    $fileSize = if (Test-Path $outputFile) { (Get-Item $outputFile).Length } else { 0 }
                    Write-OperationLog "Registry export successful" "SUCCESS" -Details @{
                        Key = $export.Key
                        OutputFile = $outputFile
                        FileSizeBytes = $fileSize
                        FileSizeKB = [math]::Round($fileSize / 1KB, 2)
                        DurationMs = [math]::Round($duration, 2)
                    }
                }
            } catch {
                Write-OperationLog "Registry export exception" "ERROR" -Details @{
                    Key = $export.Key
                    Exception = $_.Exception.Message
                    StackTrace = $_.ScriptStackTrace
                }
                Write-Verbose "Error exporting registry key $($export.Key): $($_.Exception.Message)"
            }
        }
        
        Write-OperationLog "Registry export phase completed" "SUCCESS" -Details @{
            SuccessfulExports = (Get-ChildItem $regFolder -Filter "*.reg" -ErrorAction SilentlyContinue).Count
            TotalAttempted = $regExports.Count
        }
    }
    
    # 3. Collect Hardware IDs (Current and Historical)
    Write-OperationLog "═══════════════════════════════════════════════════════════════" "INFO"
    Write-OperationLog "HARDWARE ID COLLECTION STARTING" "INFO"
    Write-OperationLog "═══════════════════════════════════════════════════════════════" "INFO"
    
    $hwidPath = Join-Path $forensicFolder "HARDWARE_IDS.txt"
    $hwidContent = @()
    
    $hwidContent += "════════════════════════════════════════════════════════════════════════════════"
    $hwidContent += "                        HARDWARE ID INVENTORY REPORT"
    $hwidContent += "════════════════════════════════════════════════════════════════════════════════"
    $hwidContent += ""
    $hwidContent += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $hwidContent += "Computer: $(if ($script:redactInfo) { 'REDACTED' } else { $env:COMPUTERNAME })"
    $hwidContent += ""
    $hwidContent += "This document contains Hardware IDs (HWIDs) for all devices - both currently"
    $hwidContent += "connected and historically installed. HWIDs uniquely identify hardware components"
    $hwidContent += "and can be used to detect device substitution, cloning, or tampering."
    $hwidContent += ""
    $hwidContent += "════════════════════════════════════════════════════════════════════════════════"
    $hwidContent += ""
    
    Write-OperationLog "Collecting current device HWIDs via WMI" "QUERY"
    
    # Section 1: Currently Connected Devices
    $hwidContent += ""
    $hwidContent += "╔════════════════════════════════════════════════════════════════════════════╗"
    $hwidContent += "║                     SECTION 1: CURRENTLY CONNECTED DEVICES                 ║"
    $hwidContent += "╚════════════════════════════════════════════════════════════════════════════╝"
    $hwidContent += ""
    
    try {
        $currentDevices = Get-CimInstance -ClassName Win32_PnPEntity -ErrorAction Stop | 
            Where-Object { $_.DeviceID -and $_.Name } |
            Sort-Object Name
        
        $deviceCount = 0
        $categorizedDevices = @{}
        
        foreach ($device in $currentDevices) {
            # Categorize devices by class
            $class = if ($device.PNPClass) { $device.PNPClass } else { "Unknown" }
            
            if (-not $categorizedDevices.ContainsKey($class)) {
                $categorizedDevices[$class] = @()
            }
            
            $categorizedDevices[$class] += $device
            $deviceCount++
        }
        
        $hwidContent += "Total Currently Connected Devices: $deviceCount"
        $hwidContent += "Device Classes Found: $($categorizedDevices.Keys.Count)"
        $hwidContent += ""
        $hwidContent += "─" * 80
        $hwidContent += ""
        
        # Output devices by category
        foreach ($class in ($categorizedDevices.Keys | Sort-Object)) {
            $hwidContent += ""
            $hwidContent += "┌─ Device Class: $class ($($categorizedDevices[$class].Count) devices) " + ("─" * (60 - $class.Length))
            $hwidContent += ""
            
            foreach ($device in $categorizedDevices[$class]) {
                $hwidContent += "  Device Name: $($device.Name)"
                $hwidContent += "  Hardware ID: $($device.DeviceID)"
                
                if ($device.Manufacturer -and $device.Manufacturer -ne "") {
                    $hwidContent += "  Manufacturer: $($device.Manufacturer)"
                }
                
                if ($device.Status) {
                    $hwidContent += "  Status: $($device.Status)"
                }
                
                if ($device.ConfigManagerErrorCode -ne 0) {
                    $hwidContent += "  ⚠ Error Code: $($device.ConfigManagerErrorCode)"
                }
                
                # Get compatible IDs if available
                if ($device.CompatibleID) {
                    $hwidContent += "  Compatible IDs:"
                    foreach ($compatId in $device.CompatibleID) {
                        $hwidContent += "    - $compatId"
                    }
                }
                
                $hwidContent += "  $("─" * 78)"
            }
        }
        
        Write-OperationLog "Current device HWIDs collected" "SUCCESS" -Details @{
            TotalDevices = $deviceCount
            DeviceClasses = $categorizedDevices.Keys.Count
        }
        
    } catch {
        $hwidContent += "ERROR: Failed to collect current device information - $($_.Exception.Message)"
        Write-OperationLog "Failed to collect current device HWIDs" "ERROR" -Details @{
            Error = $_.Exception.Message
        }
    }
    
    # Section 2: Historical Devices (from Registry)
    $hwidContent += ""
    $hwidContent += ""
    $hwidContent += "╔════════════════════════════════════════════════════════════════════════════╗"
    $hwidContent += "║                     SECTION 2: HISTORICAL DEVICE RECORDS                   ║"
    $hwidContent += "╚════════════════════════════════════════════════════════════════════════════╝"
    $hwidContent += ""
    $hwidContent += "These are devices that were previously connected but may not be present now."
    $hwidContent += "This includes USB devices, PCIe cards, and other hardware that has been"
    $hwidContent += "installed at any point in the system's history."
    $hwidContent += ""
    
    Write-OperationLog "Collecting historical device HWIDs from registry" "QUERY"
    
    try {
        # Read from DeviceClasses registry which stores historical device info
        $deviceClassesPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceClasses"
        
        if (Test-Path $deviceClassesPath) {
            $historicalDevices = @()
            $interfaceGuids = Get-ChildItem -Path $deviceClassesPath -ErrorAction SilentlyContinue
            
            foreach ($guid in $interfaceGuids) {
                $devices = Get-ChildItem -Path $guid.PSPath -ErrorAction SilentlyContinue
                
                foreach ($device in $devices) {
                    # Extract hardware ID from registry path
                    $hwid = $device.PSChildName
                    
                    # Skip if not a valid device path
                    if ($hwid -match '##\?#') {
                        # Parse the device ID
                        $cleanHwid = $hwid -replace '##\?#', '' -replace '##{.*}', ''
                        
                        # Get additional properties if available
                        $deviceProps = Get-ItemProperty -Path $device.PSPath -ErrorAction SilentlyContinue
                        
                        $historicalDevices += [PSCustomObject]@{
                            HardwareID = $cleanHwid
                            InterfaceGUID = $guid.PSChildName
                            RegistryPath = $device.PSPath
                        }
                    }
                }
            }
            
            # Remove duplicates
            $uniqueHistorical = $historicalDevices | Sort-Object HardwareID -Unique
            
            $hwidContent += "Total Historical Device Records: $($uniqueHistorical.Count)"
            $hwidContent += ""
            $hwidContent += "─" * 80
            $hwidContent += ""
            
            foreach ($histDevice in $uniqueHistorical) {
                $hwidContent += "  Hardware ID: $($histDevice.HardwareID)"
                $hwidContent += "  Interface GUID: $($histDevice.InterfaceGUID)"
                $hwidContent += "  $("─" * 78)"
            }
            
            Write-OperationLog "Historical device HWIDs collected" "SUCCESS" -Details @{
                TotalHistoricalRecords = $uniqueHistorical.Count
            }
            
        } else {
            $hwidContent += "WARNING: DeviceClasses registry path not accessible"
            Write-OperationLog "DeviceClasses registry not accessible" "WARNING"
        }
        
    } catch {
        $hwidContent += "ERROR: Failed to collect historical device information - $($_.Exception.Message)"
        Write-OperationLog "Failed to collect historical device HWIDs" "ERROR" -Details @{
            Error = $_.Exception.Message
        }
    }
    
    # Section 3: USB Device History (SetupAPI logs)
    $hwidContent += ""
    $hwidContent += ""
    $hwidContent += "╔════════════════════════════════════════════════════════════════════════════╗"
    $hwidContent += "║                     SECTION 3: USB DEVICE INSTALLATION HISTORY             ║"
    $hwidContent += "╚════════════════════════════════════════════════════════════════════════════╝"
    $hwidContent += ""
    
    Write-OperationLog "Parsing setupapi.dev.log for USB device history" "QUERY"
    
    try {
        $setupapiLog = "C:\Windows\inf\setupapi.dev.log"
        
        if (Test-Path $setupapiLog) {
            $logContent = Get-Content $setupapiLog -ErrorAction Stop
            $usbDevices = @{}
            
            # Parse setupapi log for USB device installations
            for ($i = 0; $i -lt $logContent.Count; $i++) {
                $line = $logContent[$i]
                
                # Look for USB device installations
                if ($line -match 'USB\\VID_([0-9A-F]{4})&PID_([0-9A-F]{4})') {
                    $vid = $matches[1]
                    $pid = $matches[2]
                    $hwid = "USB\VID_$vid&PID_$pid"
                    
                    # Try to find the timestamp
                    $timestamp = "Unknown"
                    for ($j = [Math]::Max(0, $i - 10); $j -lt $i; $j++) {
                        if ($logContent[$j] -match '\[(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})') {
                            $timestamp = $matches[1]
                            break
                        }
                    }
                    
                    # Try to find device description
                    $description = "Unknown"
                    for ($j = $i; $j -lt [Math]::Min($logContent.Count, $i + 20); $j++) {
                        if ($logContent[$j] -match 'Device Install') {
                            if ($logContent[$j + 1] -match '\"(.+?)\"') {
                                $description = $matches[1]
                                break
                            }
                        }
                    }
                    
                    if (-not $usbDevices.ContainsKey($hwid)) {
                        $usbDevices[$hwid] = @{
                            Description = $description
                            FirstSeen = $timestamp
                            VID = $vid
                            PID = $pid
                        }
                    }
                }
            }
            
            $hwidContent += "USB Devices Found in Installation Logs: $($usbDevices.Keys.Count)"
            $hwidContent += ""
            $hwidContent += "─" * 80
            $hwidContent += ""
            
            foreach ($hwid in ($usbDevices.Keys | Sort-Object)) {
                $dev = $usbDevices[$hwid]
                $hwidContent += "  Hardware ID: $hwid"
                $hwidContent += "  Vendor ID (VID): $($dev.VID)"
                $hwidContent += "  Product ID (PID): $($dev.PID)"
                $hwidContent += "  Description: $($dev.Description)"
                $hwidContent += "  First Detected: $($dev.FirstSeen)"
                $hwidContent += "  $("─" * 78)"
            }
            
            Write-OperationLog "USB device history parsed from setupapi.dev.log" "SUCCESS" -Details @{
                USBDevicesFound = $usbDevices.Keys.Count
            }
            
        } else {
            $hwidContent += "WARNING: setupapi.dev.log not found at C:\Windows\inf\setupapi.dev.log"
            Write-OperationLog "setupapi.dev.log not found" "WARNING"
        }
        
    } catch {
        $hwidContent += "ERROR: Failed to parse setupapi.dev.log - $($_.Exception.Message)"
        Write-OperationLog "Failed to parse setupapi.dev.log" "ERROR" -Details @{
            Error = $_.Exception.Message
        }
    }
    
    # Footer
    $hwidContent += ""
    $hwidContent += ""
    $hwidContent += "════════════════════════════════════════════════════════════════════════════════"
    $hwidContent += "                             END OF HWID REPORT"
    $hwidContent += "════════════════════════════════════════════════════════════════════════════════"
    $hwidContent += ""
    $hwidContent += "IMPORTANT NOTES:"
    $hwidContent += "- Hardware IDs are unique identifiers assigned by manufacturers"
    $hwidContent += "- VID (Vendor ID) identifies the manufacturer"
    $hwidContent += "- PID (Product ID) identifies the specific product"
    $hwidContent += "- Historical records may include devices no longer connected"
    $hwidContent += "- Suspicious patterns: Duplicate HWIDs, generic IDs, missing manufacturer info"
    $hwidContent += ""
    
    # Save HWID report
    $hwidContent | Out-File -FilePath $hwidPath -Encoding UTF8
    
    Write-OperationLog "Hardware ID inventory report saved" "SUCCESS" -Details @{
        OutputPath = $hwidPath
        FileSize = (Get-Item $hwidPath).Length
        Lines = $hwidContent.Count
    }
    
    Write-OperationLog "═══════════════════════════════════════════════════════════════" "INFO"
    Write-OperationLog "HARDWARE ID COLLECTION COMPLETE" "SUCCESS"
    Write-OperationLog "═══════════════════════════════════════════════════════════════" "INFO"
    
    # 4. Collect Log Files
    # Silent collection
    $logFolder = Join-Path $forensicFolder "Logs"
    $null = New-Item -Path $logFolder -ItemType Directory -Force
    
    # Security: Check for log tampering before collection
    $logTamperingSuspicious = @()
    
    # Check setupapi.dev.log integrity
    $setupLogPath = "C:\Windows\inf\setupapi.dev.log"
    if (Test-Path $setupLogPath) {
        $setupLog = Get-Item $setupLogPath
        $logSizeKB = [math]::Round($setupLog.Length / 1KB, 2)
        
        # Setup log should be substantial on any used system
        if ($setupLog.Length -lt 10KB) {
            $logTamperingSuspicious += "setupapi.dev.log unusually small ($logSizeKB KB) - may have been cleared"
        }
        
        # Check if log was recently modified (beyond normal append operations)
        $logAge = ((Get-Date) - $setupLog.LastWriteTime).TotalDays
        if ($logAge -gt 30) {
            $logTamperingSuspicious += "setupapi.dev.log hasn't been updated in $([math]::Round($logAge)) days - no recent device installations?"
        }
    } else {
        $logTamperingSuspicious += "setupapi.dev.log is missing entirely - highly suspicious on active system"
    }
    
    # Check for Event Log clearing events (Security Event ID 1102, System Event ID 104)
    try {
        # Check if Security log was cleared
        $securityClears = Get-WinEvent -FilterHashtable @{
            LogName='Security'; ID=1102; StartTime=(Get-Date).AddDays(-90)
        } -ErrorAction SilentlyContinue -MaxEvents 10
        
        if ($securityClears) {
            $logTamperingSuspicious += "Security event log was cleared $($securityClears.Count) time(s) in last 90 days"
            foreach ($clear in $securityClears) {
                $logTamperingSuspicious += "  - Cleared on: $($clear.TimeCreated) by: $($clear.Properties[1].Value)"
            }
        }
        
        # Check if System log was cleared
        $systemClears = Get-WinEvent -FilterHashtable @{
            LogName='System'; ID=104; StartTime=(Get-Date).AddDays(-90)
        } -ErrorAction SilentlyContinue -MaxEvents 10
        
        if ($systemClears) {
            $logTamperingSuspicious += "System event log was cleared $($systemClears.Count) time(s) in last 90 days"
        }
    } catch {
        # Event log queries can fail, not critical
    }
    
    # Report log tampering findings
    if ($logTamperingSuspicious.Count -gt 0) {
        Add-Finding -Category "System" -Severity "HIGH" `
            -Description "Evidence of log tampering or clearing detected" `
            -Details @{ 
                Issues = $logTamperingSuspicious
                Impact = "Log tampering may indicate attempt to hide evidence of hardware modifications"
                Recommendation = "Investigate why logs were cleared or are unusually small"
            }
        Add-AuditEntry -CheckName "Log Integrity Check" -Status "Completed" `
            -ItemsScanned 3 -SuspiciousFound $logTamperingSuspicious.Count `
            -Details @{ TamperingIndicators = $logTamperingSuspicious }
    }
    
    # Setup API log (device installation history)
    if (Test-Path "C:\Windows\inf\setupapi.dev.log") {
        Copy-Item "C:\Windows\inf\setupapi.dev.log" (Join-Path $logFolder "setupapi.dev.log") -ErrorAction SilentlyContinue
    }
    if (Test-Path "C:\Windows\inf\setupapi.app.log") {
        Copy-Item "C:\Windows\inf\setupapi.app.log" (Join-Path $logFolder "setupapi.app.log") -ErrorAction SilentlyContinue
    }
    
    #endregion Log Tampering Detection
    
    #region IOMMU/VT-d Detection
    Write-Progress -Activity "System Analysis" -Status "Check 19/26: IOMMU/VT-d Status" -PercentComplete 73
    Write-OperationLog "Starting IOMMU/VT-d detection" "INFO"
    
    try {
        $iommuFindings = @()
        
        # Check for IOMMU/VT-d capable devices
        $iommuDevices = Get-CimInstance -ClassName Win32_PnPEntity -ErrorAction SilentlyContinue | Where-Object {
            $_.Name -match "IOMMU|VT-d|AMD-Vi|DMAR" -or
            $_.DeviceID -match "ACPI\\PNP0A08|ACPI\\PNP0A03"  # PCI Express Root Complex
        }
        
        # Check Windows Kernel DMA Protection registry
        $dmaProtection = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\DmaSecurity" -ErrorAction SilentlyContinue
        
        if ($dmaProtection -and $dmaProtection.DmaProtectionEnabled -eq 1) {
            Write-OperationLog "Kernel DMA Protection is ENABLED" "INFO"
        } else {
            $iommuFindings += @{
                Category = "Kernel DMA Protection Disabled"
                Severity = "CRITICAL"
                Evidence = "HKLM:\SYSTEM\CurrentControlSet\Control\DmaSecurity\DmaProtectionEnabled is not set to 1"
                Impact = "DMA attacks are NOT mitigated by Windows Kernel"
                Mitigation = "Enable VT-d/AMD-Vi in BIOS, ensure modern UEFI firmware"
                SuspicionScore = 60
            }
            Write-OperationLog "CRITICAL: Kernel DMA Protection is DISABLED - DMA attacks possible" "WARNING"
        }
        
        # Check for Thunderbolt devices (high DMA risk if IOMMU disabled)
        $thunderboltDevices = Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object {
            $_.FriendlyName -match "Thunderbolt" -or
            $_.HardwareID -match "THUNDERBOLT|TBT"
        }
        
        if ($thunderboltDevices -and (-not $dmaProtection -or $dmaProtection.DmaProtectionEnabled -ne 1)) {
            $iommuFindings += @{
                Category = "Thunderbolt + No DMA Protection"
                Severity = "CRITICAL"
                Evidence = "Thunderbolt controller present but Kernel DMA Protection disabled"
                Impact = "Thunderbolt ports can be used for DMA attacks"
                DeviceCount = $thunderboltDevices.Count
                Mitigation = "Enable Kernel DMA Protection or disable Thunderbolt in BIOS"
                SuspicionScore = 80
            }
            Write-OperationLog "CRITICAL: Thunderbolt detected without DMA protection" "WARNING"
        }
        
        # Check for external PCI/PCIe devices (potential DMA attack vectors)
        $externalPCIe = Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object {
            $_.Class -eq "System" -and
            ($_.FriendlyName -match "External|Hot.*Plug|Thunderbolt" -or
             $_.Status -eq "OK" -and $_.ConfigManagerErrorCode -eq 0)
        }
        
        if ($iommuFindings.Count -gt 0) {
            [void](Report-ScoredFinding -Category "IOMMU/DMA Protection" -Findings $iommuFindings)
        }
        
        Add-AuditEntry -CheckName "IOMMU/VT-d Detection" -Status "Completed" `
            -ItemsScanned 2 -SuspiciousFound $iommuFindings.Count `
            -Details @{ 
                DMAProtectionEnabled = ($dmaProtection.DmaProtectionEnabled -eq 1)
                ThunderboltDevices = $thunderboltDevices.Count
                CriticalFindings = $iommuFindings.Count
            }
    } catch {
        Write-OperationLog "Error during IOMMU detection: $_" "ERROR"
    }
    #endregion IOMMU/VT-d Detection
    
    #region Secure Boot Verification
    Write-Progress -Activity "System Analysis" -Status "Check 20/26: Secure Boot Status" -PercentComplete 77
    Write-OperationLog "Starting Secure Boot verification" "INFO"
    
    try {
        $secureBootFindings = @()
        
        # Check if Secure Boot is enabled
        try {
            $secureBootEnabled = Confirm-SecureBootUEFI -ErrorAction Stop
            
            if (-not $secureBootEnabled) {
                $secureBootFindings += @{
                    Category = "Secure Boot Disabled"
                    Severity = "HIGH"
                    Evidence = "Confirm-SecureBootUEFI returned False"
                    Impact = "System can load unsigned/modified drivers and bootloaders"
                    Mitigation = "Enable Secure Boot in UEFI/BIOS settings"
                    SuspicionScore = 50
                }
                Write-OperationLog "HIGH: Secure Boot is DISABLED - unsigned drivers can load" "WARNING"
            } else {
                Write-OperationLog "Secure Boot is ENABLED" "INFO"
            }
        } catch {
            # Secure Boot not supported or can't be checked
            $secureBootFindings += @{
                Category = "Secure Boot Status Unknown"
                Severity = "MEDIUM"
                Evidence = "Unable to verify Secure Boot status: $_"
                Impact = "Cannot confirm boot integrity protection"
                SuspicionScore = 30
            }
            Write-OperationLog "MEDIUM: Unable to verify Secure Boot status" "WARNING"
        }
        
        # Check for UEFI vs Legacy BIOS
        $firmwareType = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control" -ErrorAction SilentlyContinue).PEFirmwareType
        
        if ($firmwareType -eq 1) {
            # Legacy BIOS (no Secure Boot possible)
            $secureBootFindings += @{
                Category = "Legacy BIOS Mode"
                Severity = "HIGH"
                Evidence = "System is using Legacy BIOS (not UEFI)"
                Impact = "Secure Boot not available, boot process vulnerable to modification"
                Mitigation = "Convert to UEFI mode if hardware supports it"
                SuspicionScore = 40
            }
            Write-OperationLog "HIGH: System using Legacy BIOS (no Secure Boot support)" "WARNING"
        }
        
        # Check BitLocker status (often disabled when Secure Boot is off)
        $bitlockerVolumes = Get-BitLockerVolume -ErrorAction SilentlyContinue | Where-Object {
            $_.VolumeType -eq "OperatingSystem"
        }
        
        if ($bitlockerVolumes) {
            foreach ($vol in $bitlockerVolumes) {
                if ($vol.ProtectionStatus -ne "On") {
                    $secureBootFindings += @{
                        Category = "BitLocker Disabled on OS Drive"
                        Severity = "MEDIUM"
                        Evidence = "OS drive $($vol.MountPoint) has BitLocker disabled"
                        Impact = "Disk encryption not protecting against offline attacks"
                        Mitigation = "Enable BitLocker on OS drives"
                        SuspicionScore = 20
                    }
                    Write-OperationLog "MEDIUM: BitLocker disabled on $($vol.MountPoint)" "WARNING"
                }
            }
        }
        
        if ($secureBootFindings.Count -gt 0) {
            [void](Report-ScoredFinding -Category "Secure Boot / Firmware" -Findings $secureBootFindings)
        }
        
        Add-AuditEntry -CheckName "Secure Boot Verification" -Status "Completed" `
            -ItemsScanned 3 -SuspiciousFound $secureBootFindings.Count `
            -Details @{ 
                SecureBootEnabled = $secureBootEnabled
                FirmwareType = if ($firmwareType -eq 2) { "UEFI" } else { "Legacy BIOS" }
                CriticalFindings = $secureBootFindings.Count
            }
    } catch {
        Write-OperationLog "Error during Secure Boot verification: $_" "ERROR"
    }
    #endregion Secure Boot Verification
    
    #region Kernel Driver Enumeration Comparison (DKOM Detection)
    Write-Progress -Activity "System Analysis" -Status "Check 21/26: Kernel Rootkit Detection (DKOM)" -PercentComplete 81
    Write-OperationLog "Starting kernel driver enumeration comparison (DKOM detection)" "INFO"
    
    try {
        $dkomFindings = @()
        
        # Method 1: CIM query (can be hooked by rootkits)
        $cimDrivers = @(Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue | 
                       Where-Object {$_.State -eq "Running"} | 
                       Select-Object -ExpandProperty Name)
        
        # Method 2: Registry enumeration (harder to hook)
        $regDrivers = @(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\*" -ErrorAction SilentlyContinue | 
                       Where-Object {$_.Type -eq 1 -and $_.Start -le 2} |  # Type 1 = Kernel driver, Start <= 2 = Auto/Boot
                       Select-Object -ExpandProperty PSChildName)
        
        # Method 3: Filter manager drivers (for filesystem filters)
        $fltmcOutput = & fltmc.exe 2>&1 | Out-String
        $filterDrivers = @()
        if ($fltmcOutput -match "Filter Name") {
            $filterDrivers = @($fltmcOutput -split "`n" | Where-Object {
                $_ -match "^\S+" -and $_ -notmatch "Filter Name|Instances|-----"
            } | ForEach-Object {
                ($_ -split "\s+")[0]
            })
        }
        
        Write-OperationLog "Driver count - CIM: $($cimDrivers.Count), Registry: $($regDrivers.Count), FilterMgr: $($filterDrivers.Count)" "INFO"
        
        # Compare counts - significant mismatch indicates hiding
        $countDifference = [Math]::Abs($cimDrivers.Count - $regDrivers.Count)
        
        if ($countDifference -gt 5) {
            $dkomFindings += @{
                Category = "Driver Enumeration Mismatch"
                Severity = "CRITICAL"
                Evidence = "CIM reports $($cimDrivers.Count) drivers, Registry shows $($regDrivers.Count) drivers (difference: $countDifference)"
                Impact = "Possible kernel rootkit using Direct Kernel Object Manipulation (DKOM)"
                Mitigation = "Perform offline scan with bootable antivirus, check for known rootkits"
                SuspicionScore = 90
            }
            Write-OperationLog "CRITICAL: Driver enumeration mismatch detected - possible DKOM rootkit!" "WARNING"
        }
        
        # Find drivers in registry but not in CIM (hidden drivers)
        $hiddenDrivers = @($regDrivers | Where-Object {$_ -notin $cimDrivers})
        
        if ($hiddenDrivers.Count -gt 0) {
            $dkomFindings += @{
                Category = "Hidden Drivers Detected"
                Severity = "CRITICAL"
                Evidence = "Found $($hiddenDrivers.Count) drivers in Registry but not visible via CIM"
                HiddenDriverList = ($hiddenDrivers -join ", ")
                Impact = "Drivers are hiding from standard enumeration - rootkit behavior"
                SuspicionScore = 95
            }
            Write-OperationLog "CRITICAL: Hidden drivers detected: $($hiddenDrivers -join ', ')" "WARNING"
        }
        
        # Check for suspicious filter drivers (common in rootkits)
        $suspiciousFilters = @($filterDrivers | Where-Object {
            $_ -notmatch "^(luafv|wcifs|FileCrypt|storqosflt|wcnfs|bindflat|FileInfo|npsvctrig|Wof|FileCrypt|CldFlt)$" -and
            $_ -match "[a-z]{6,}" -and  # Unusual naming pattern
            $_ -notmatch "^(Microsoft|Windows|WdFilter|SysmonDrv)"
        })
        
        if ($suspiciousFilters.Count -gt 0) {
            $dkomFindings += @{
                Category = "Suspicious Filesystem Filters"
                Severity = "HIGH"
                Evidence = "Unusual filter drivers detected: $($suspiciousFilters -join ', ')"
                Impact = "Unknown filters can intercept file operations, hide files, or modify data"
                FilterCount = $suspiciousFilters.Count
                SuspicionScore = 60
            }
            Write-OperationLog "HIGH: Suspicious filter drivers: $($suspiciousFilters -join ', ')" "WARNING"
        }
        
        if ($dkomFindings.Count -gt 0) {
            [void](Report-ScoredFinding -Category "Kernel Rootkit Detection (DKOM)" -Findings $dkomFindings)
        }
        
        Add-AuditEntry -CheckName "DKOM Detection" -Status "Completed" `
            -ItemsScanned 3 -SuspiciousFound $dkomFindings.Count `
            -Details @{ 
                CIMDriverCount = $cimDrivers.Count
                RegistryDriverCount = $regDrivers.Count
                FilterDriverCount = $filterDrivers.Count
                HiddenDrivers = $hiddenDrivers.Count
                CriticalFindings = $dkomFindings.Count
            }
    } catch {
        Write-OperationLog "Error during DKOM detection: $_" "ERROR"
    }
    #endregion Kernel Driver Enumeration Comparison
    
    # Event logs (last 7 days)
    # Silent collection
    $eventLogPath = Join-Path $logFolder "EventLogs"
    $null = New-Item -Path $eventLogPath -ItemType Directory -Force
    
    $sevenDaysAgo = (Get-Date).AddDays(-7)
    
    # System events
    Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$sevenDaysAgo} -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, Id, LevelDisplayName, Message |
        Export-Csv (Join-Path $eventLogPath "System_Events.csv") -NoTypeInformation
    
    # Application events
    Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=$sevenDaysAgo} -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, Id, LevelDisplayName, Message |
        Export-Csv (Join-Path $eventLogPath "Application_Events.csv") -NoTypeInformation
    
    # Security events (driver loading)
    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4697,4698,4699; StartTime=$sevenDaysAgo} -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, Id, Message |
        Export-Csv (Join-Path $eventLogPath "Security_DriverEvents.csv") -NoTypeInformation
    
    #region HVCI/Memory Integrity Checks
    Write-Progress -Activity "System Analysis" -Status "Check 22/26: Memory Integrity (HVCI)" -PercentComplete 85
    Write-OperationLog "Starting HVCI/Memory Integrity verification" "INFO"
    
    try {
        $hvciFindings = @()
        
        # Check Device Guard / HVCI status via CIM
        $deviceGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
        
        if ($deviceGuard) {
            # Check Code Integrity Policy Enforcement
            if ($deviceGuard.CodeIntegrityPolicyEnforcementStatus -ne 1) {
                $hvciFindings += @{
                    Category = "Hypervisor Code Integrity (HVCI) Disabled"
                    Severity = "HIGH"
                    Evidence = "CodeIntegrityPolicyEnforcementStatus = $($deviceGuard.CodeIntegrityPolicyEnforcementStatus) (expected: 1)"
                    Impact = "Memory-based attacks (process injection, kernel exploitation) not mitigated"
                    Mitigation = "Enable Memory Integrity in Windows Security > Device Security > Core Isolation"
                    SuspicionScore = 45
                }
                Write-OperationLog "HIGH: HVCI/Memory Integrity is DISABLED" "WARNING"
            } else {
                Write-OperationLog "HVCI/Memory Integrity is ENABLED" "INFO"
            }
            
            # Check if VBS (Virtualization-Based Security) is running
            if ($deviceGuard.VirtualizationBasedSecurityStatus -ne 2) {
                $hvciFindings += @{
                    Category = "Virtualization-Based Security Not Running"
                    Severity = "MEDIUM"
                    Evidence = "VirtualizationBasedSecurityStatus = $($deviceGuard.VirtualizationBasedSecurityStatus) (expected: 2)"
                    Impact = "Hardware-based security features not active"
                    SuspicionScore = 30
                }
                Write-OperationLog "MEDIUM: VBS is not running" "WARNING"
            }
        } else {
            $hvciFindings += @{
                Category = "Device Guard Status Unknown"
                Severity = "MEDIUM"
                Evidence = "Unable to query Win32_DeviceGuard CIM class"
                Impact = "Cannot verify hardware-based security status"
                SuspicionScore = 25
            }
            Write-OperationLog "MEDIUM: Cannot query Device Guard status" "WARNING"
        }
        
        # Check for Code Integrity violations in event log
        $codeIntegrityViolations = Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-CodeIntegrity/Operational'
            Id = 3076,3077  # Driver load blocked by code integrity
            StartTime = (Get-Date).AddDays(-30)
        } -ErrorAction SilentlyContinue
        
        if ($codeIntegrityViolations -and $codeIntegrityViolations.Count -gt 0) {
            # Extract unique driver names from violations
            $blockedDrivers = @($codeIntegrityViolations | ForEach-Object {
                if ($_.Message -match "\\([^\\]+\.sys)") {
                    $matches[1]
                }
            } | Select-Object -Unique)
            
            $hvciFindings += @{
                Category = "Unsigned Driver Load Attempts"
                Severity = "CRITICAL"
                Evidence = "Detected $($codeIntegrityViolations.Count) driver load attempts blocked by Code Integrity (last 30 days)"
                BlockedDrivers = ($blockedDrivers -join ", ")
                Impact = "System is being targeted with unsigned/malicious drivers"
                ViolationCount = $codeIntegrityViolations.Count
                SuspicionScore = 85
            }
            Write-OperationLog "CRITICAL: $($codeIntegrityViolations.Count) unsigned driver load attempts detected!" "WARNING"
        }
        
        # Check for Credential Guard status
        if ($deviceGuard -and $deviceGuard.SecurityServicesRunning -notcontains 2) {
            $hvciFindings += @{
                Category = "Credential Guard Not Running"
                Severity = "LOW"
                Evidence = "Credential Guard is not active"
                Impact = "Credentials may be vulnerable to memory dumping attacks"
                SuspicionScore = 15
            }
        }
        
        if ($hvciFindings.Count -gt 0) {
            [void](Report-ScoredFinding -Category "Memory Integrity / HVCI" -Findings $hvciFindings)
        }
        
        Add-AuditEntry -CheckName "HVCI/Memory Integrity" -Status "Completed" `
            -ItemsScanned 4 -SuspiciousFound $hvciFindings.Count `
            -Details @{ 
                HVCIEnabled = ($deviceGuard.CodeIntegrityPolicyEnforcementStatus -eq 1)
                VBSRunning = ($deviceGuard.VirtualizationBasedSecurityStatus -eq 2)
                CodeIntegrityViolations = if ($codeIntegrityViolations) { $codeIntegrityViolations.Count } else { 0 }
                CriticalFindings = $hvciFindings.Count
            }
    } catch {
        Write-OperationLog "Error during HVCI verification: $_" "ERROR"
    }
    #endregion HVCI/Memory Integrity Checks
    
    #region PCILeech-Specific Detection
    Write-Progress -Activity "System Analysis" -Status "Check 23/26: PCILeech Indicators" -PercentComplete 88
    Write-OperationLog "Starting PCILeech-specific detection" "INFO"
    
    try {
        $pcileechFindings = @()
        
        # Check for PCILeech driver (various names)
        $pcileechDriverNames = @('pcileech', 'screamer', 'dmascreamer', 'fpga')
        $suspiciousDrivers = @(Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue | Where-Object {
            $driver = $_
            $pcileechDriverNames | Where-Object {$driver.Name -match $_ -or $driver.PathName -match $_}
        })
        
        if ($suspiciousDrivers.Count -gt 0) {
            $pcileechFindings += @{
                Category = "PCILeech Driver Detected"
                Severity = "CRITICAL"
                Evidence = "Found driver(s) matching PCILeech signatures: $($suspiciousDrivers.Name -join ', ')"
                DriverPaths = ($suspiciousDrivers.PathName -join '; ')
                Impact = "PCILeech DMA attack tool is installed"
                SuspicionScore = 100
            }
            Write-OperationLog "CRITICAL: PCILeech driver detected: $($suspiciousDrivers.Name -join ', ')" "WARNING"
        }
        
        # Check for FPGA development boards (Xilinx 7-Series, Altera, etc.)
        $fpgaDevices = @(Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object {
            ($_.FriendlyName -match "Xilinx|Altera|Lattice|FPGA|7-Series|Artix|Kintex|Virtex" -or
             $_.HardwareID -match "VEN_10EE") -and  # Xilinx vendor ID
            $_.Class -ne "Display"  # Exclude GPUs that use FPGA tech
        })
        
        if ($fpgaDevices.Count -gt 0) {
            $pcileechFindings += @{
                Category = "FPGA Development Board Detected"
                Severity = "HIGH"
                Evidence = "FPGA device(s) detected: $($fpgaDevices.FriendlyName -join ', ')"
                DeviceIDs = ($fpgaDevices.InstanceId -join '; ')
                Impact = "FPGA boards are commonly used for DMA attacks (PCILeech hardware)"
                DeviceCount = $fpgaDevices.Count
                SuspicionScore = 75
            }
            Write-OperationLog "HIGH: FPGA development board detected: $($fpgaDevices.FriendlyName -join ', ')" "WARNING"
        }
        
        # Check for excessive memory-mapped I/O regions (sign of DMA activity)
        $memoryRegions = @(Get-CimInstance Win32_DeviceMemoryAddress -ErrorAction SilentlyContinue)
        
        if ($memoryRegions.Count -gt 150) {
            $pcileechFindings += @{
                Category = "Excessive Memory-Mapped I/O Regions"
                Severity = "MEDIUM"
                Evidence = "Found $($memoryRegions.Count) memory-mapped I/O regions (normal: <100)"
                Impact = "May indicate DMA hardware accessing system memory"
                RegionCount = $memoryRegions.Count
                SuspicionScore = 40
            }
            Write-OperationLog "MEDIUM: Excessive memory-mapped I/O regions: $($memoryRegions.Count)" "WARNING"
        }
        
        # Check for PCIe hotplug activity (DMA cards often appear as hot-pluggable)
        $hotplugDevices = @(Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object {
            $_.Capabilities -match "Removable" -and
            $_.Class -in @("System", "Unknown") -and
            $_.InstanceId -match "PCI"
        })
        
        if ($hotplugDevices.Count -gt 2) {
            $pcileechFindings += @{
                Category = "Suspicious Hot-Pluggable PCI Devices"
                Severity = "MEDIUM"
                Evidence = "Found $($hotplugDevices.Count) hot-pluggable PCI devices"
                Devices = ($hotplugDevices.FriendlyName -join ', ')
                Impact = "DMA attack hardware often appears as hot-pluggable PCI devices"
                SuspicionScore = 35
            }
            Write-OperationLog "MEDIUM: Suspicious hot-pluggable PCI devices: $($hotplugDevices.Count)" "WARNING"
        }
        
        # Check for Xilinx Platform Cable USB (used to program FPGA boards)
        $xilinxCable = @(Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object {
            $_.FriendlyName -match "Xilinx.*Platform.*Cable|Digilent.*JTAG" -or
            $_.HardwareID -match "VID_03FD"  # Xilinx USB vendor ID
        })
        
        if ($xilinxCable.Count -gt 0) {
            $pcileechFindings += @{
                Category = "FPGA Programming Interface Detected"
                Severity = "HIGH"
                Evidence = "Xilinx/Digilent programming cable detected: $($xilinxCable.FriendlyName -join ', ')"
                Impact = "Tool for programming FPGA-based DMA attack hardware"
                SuspicionScore = 70
            }
            Write-OperationLog "HIGH: FPGA programming cable detected" "WARNING"
        }
        
        if ($pcileechFindings.Count -gt 0) {
            [void](Report-ScoredFinding -Category "PCILeech-Specific Indicators" -Findings $pcileechFindings)
        }
        
        Add-AuditEntry -CheckName "PCILeech Detection" -Status "Completed" `
            -ItemsScanned 5 -SuspiciousFound $pcileechFindings.Count `
            -Details @{ 
                PCILeechDrivers = $suspiciousDrivers.Count
                FPGADevices = $fpgaDevices.Count
                MemoryRegions = $memoryRegions.Count
                CriticalFindings = ($pcileechFindings | Where-Object {$_.Severity -eq "CRITICAL"}).Count
            }
    } catch {
        Write-OperationLog "Error during PCILeech detection: $_" "ERROR"
    }
    #endregion PCILeech-Specific Detection
    
    #region Baseline Comparison
    Write-Progress -Activity "System Analysis" -Status "Check 24/26: Baseline Comparison" -PercentComplete 92
    Write-OperationLog "Starting baseline comparison" "INFO"
    
    try {
        $baselineFindings = Compare-ToBaseline
        
        if ($baselineFindings) {
            if ($baselineFindings -is [Array]) {
                foreach ($finding in $baselineFindings) {
                    if ($finding.Severity -ne "INFO") {
                        [void](Report-ScoredFinding -Category "Baseline Comparison" -Findings @($finding))
                    }
                }
                Add-AuditEntry -CheckName "Baseline Comparison" -Status "Completed" `
                    -ItemsScanned 1 -SuspiciousFound $baselineFindings.Count `
                    -Details @{ BaselineFindings = $baselineFindings.Count }
            } else {
                if ($baselineFindings.Severity -eq "INFO") {
                    Write-OperationLog "No baseline found - create with Export-SystemBaseline" "INFO"
                } else {
                    [void](Report-ScoredFinding -Category "Baseline Comparison" -Findings @($baselineFindings))
                }
                Add-AuditEntry -CheckName "Baseline Comparison" -Status "Completed" `
                    -ItemsScanned 1 -SuspiciousFound 0 `
                    -Details @{ Message = $baselineFindings.Evidence }
            }
        }
    } catch {
        Write-OperationLog "Error during baseline comparison: $_" "ERROR"
    }
    #endregion Baseline Comparison
    
    #region Network-Based Indicators
    Write-Progress -Activity "System Analysis" -Status "Check 25/26: Network Indicators" -PercentComplete 96
    Write-OperationLog "Starting network-based indicator detection" "INFO"
    
    try {
        $networkFindings = @()
        
        # Check DNS cache for suspicious domains
        $suspiciousDomainPatterns = @(
            "*cheat*", "*hack*", "*aimbot*", "*wallhack*", "*esp*",
            "*dma*card*", "*pcileech*", "*screamer*", "*kernel*cheat*"
        )
        
        $dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue | Where-Object {
            $entry = $_.Entry
            $suspiciousDomainPatterns | Where-Object {$entry -like $_}
        }
        
        if ($dnsCache) {
            $networkFindings += @{
                Category = "Suspicious DNS Cache Entries"
                Severity = "HIGH"
                Evidence = "Found DNS lookups for cheat/hack-related domains"
                DomainList = ($dnsCache.Entry -join ", ")
                Impact = "User may have accessed cheat provider websites"
                DomainCount = $dnsCache.Count
                SuspicionScore = 70
            }
            Write-OperationLog "HIGH: Suspicious DNS cache entries: $($dnsCache.Entry -join ', ')" "WARNING"
        }
        
        # Check for unusual active connections (non-standard ports)
        $connections = Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object {
            $_.State -eq "Established" -and
            $_.RemotePort -notin @(80, 443, 53, 22, 3389, 445, 139) -and  # Common legitimate ports
            $_.RemoteAddress -notmatch "^(127\.|::1|169\.254\.)" # Not localhost/link-local
        }
        
        if ($connections.Count -gt 20) {
            $unusualConnections = $connections | Group-Object RemotePort | 
                                 Where-Object {$_.Count -gt 2} | 
                                 Sort-Object Count -Descending | 
                                 Select-Object -First 5
            
            if ($unusualConnections) {
                $networkFindings += @{
                    Category = "Unusual Network Connections"
                    Severity = "MEDIUM"
                    Evidence = "Multiple connections to non-standard ports"
                    TopPorts = ($unusualConnections | ForEach-Object {"Port $($_.Name): $($_.Count) connections"}) -join "; "
                    Impact = "May indicate C2 communication or cheat software updates"
                    ConnectionCount = $connections.Count
                    SuspicionScore = 35
                }
                Write-OperationLog "MEDIUM: Unusual network connections detected: $($connections.Count) total" "WARNING"
            }
        }
        
        # Check for connections from suspicious processes
        $suspiciousProcesses = Get-Process -ErrorAction SilentlyContinue | Where-Object {
            $_.ProcessName -match "injector|loader|bypass|hook|cheat" -or
            ($_.Path -and $_.Path -match "temp|appdata\\local\\temp")
        }
        
        if ($suspiciousProcesses) {
            foreach ($proc in $suspiciousProcesses) {
                $procConnections = Get-NetTCPConnection -ErrorAction SilentlyContinue | 
                                  Where-Object {$_.OwningProcess -eq $proc.Id -and $_.State -eq "Established"}
                
                if ($procConnections) {
                    $networkFindings += @{
                        Category = "Suspicious Process Network Activity"
                        Severity = "HIGH"
                        Evidence = "Process '$($proc.ProcessName)' has active network connections"
                        ProcessPath = $proc.Path
                        RemoteAddresses = ($procConnections.RemoteAddress | Select-Object -Unique -join ", ")
                        SuspicionScore = 65
                    }
                    Write-OperationLog "HIGH: Suspicious process with network activity: $($proc.ProcessName)" "WARNING"
                }
            }
        }
        
        if ($networkFindings.Count -gt 0) {
            [void](Report-ScoredFinding -Category "Network Indicators" -Findings $networkFindings)
        }
        
        Add-AuditEntry -CheckName "Network Indicators" -Status "Completed" `
            -ItemsScanned 3 -SuspiciousFound $networkFindings.Count `
            -Details @{
                SuspiciousDNS = if ($dnsCache) { $dnsCache.Count } else { 0 }
                UnusualConnections = $connections.Count
                CriticalFindings = $networkFindings.Count
            }
    } catch {
        Write-OperationLog "Error during network indicator detection: $_" "ERROR"
    }
    #endregion Network-Based Indicators
    
    #region Boot Configuration Checks
    Write-Progress -Activity "System Analysis" -Status "Check 26/26: Boot Configuration" -PercentComplete 100
    Write-OperationLog "Starting boot configuration checks (bcdedit)" "INFO"
    
    try {
        $bootFindings = @()
        
        # Run bcdedit to check for dangerous boot flags
        $bcdeditOutput = & bcdedit.exe /enum all 2>&1 | Out-String
        
        # Check for test signing enabled (allows unsigned drivers)
        if ($bcdeditOutput -match "testsigning\s+Yes") {
            $bootFindings += @{
                Category = "Test Signing Enabled"
                Severity = "CRITICAL"
                Evidence = "Boot configuration has 'testsigning Yes' - unsigned drivers can load"
                Impact = "System will load unsigned/malicious drivers without warnings"
                Mitigation = "Run: bcdedit /set testsigning off"
                SuspicionScore = 95
            }
            Write-OperationLog "CRITICAL: Test signing is ENABLED - unsigned drivers allowed!" "WARNING"
        }
        
        # Check for integrity checks disabled
        if ($bcdeditOutput -match "nointegritychecks\s+(Yes|On)") {
            $bootFindings += @{
                Category = "Integrity Checks Disabled"
                Severity = "CRITICAL"
                Evidence = "Boot configuration has 'nointegritychecks' enabled"
                Impact = "Kernel code signing checks are bypassed"
                Mitigation = "Run: bcdedit /deletevalue nointegritychecks"
                SuspicionScore = 95
            }
            Write-OperationLog "CRITICAL: Kernel integrity checks DISABLED!" "WARNING"
        }
        
        # Check for debug mode enabled
        if ($bcdeditOutput -match "debug\s+Yes") {
            $bootFindings += @{
                Category = "Kernel Debugging Enabled"
                Severity = "HIGH"
                Evidence = "Boot configuration has 'debug Yes'"
                Impact = "Kernel can be debugged/modified at runtime"
                Mitigation = "Run: bcdedit /set debug off (unless actively debugging)"
                SuspicionScore = 60
            }
            Write-OperationLog "HIGH: Kernel debugging enabled" "WARNING"
        }
        
        # Check for DISABLE_INTEGRITY_CHECKS
        if ($bcdeditOutput -match "DISABLE_INTEGRITY_CHECKS") {
            $bootFindings += @{
                Category = "Driver Signing Enforcement Disabled"
                Severity = "CRITICAL"
                Evidence = "Boot option DISABLE_INTEGRITY_CHECKS detected"
                Impact = "All driver signature verification is disabled"
                SuspicionScore = 98
            }
            Write-OperationLog "CRITICAL: Driver signing enforcement disabled!" "WARNING"
        }
        
        # Check for hypervisorlaunchtype disabled (needed for VBS/HVCI)
        if ($bcdeditOutput -match "hypervisorlaunchtype\s+(Off|disabled)") {
            $bootFindings += @{
                Category = "Hypervisor Disabled"
                Severity = "MEDIUM"
                Evidence = "Hypervisor launch type is disabled"
                Impact = "Virtualization-based security (VBS/HVCI) cannot function"
                Mitigation = "Run: bcdedit /set hypervisorlaunchtype auto"
                SuspicionScore = 40
            }
            Write-OperationLog "MEDIUM: Hypervisor disabled - VBS unavailable" "WARNING"
        }
        
        if ($bootFindings.Count -gt 0) {
            [void](Report-ScoredFinding -Category "Boot Configuration" -Findings $bootFindings)
        }
        
        Add-AuditEntry -CheckName "Boot Configuration" -Status "Completed" `
            -ItemsScanned 5 -SuspiciousFound $bootFindings.Count `
            -Details @{
                CriticalFindings = ($bootFindings | Where-Object {$_.Severity -eq "CRITICAL"}).Count
                HighFindings = ($bootFindings | Where-Object {$_.Severity -eq "HIGH"}).Count
            }
    } catch {
        Write-OperationLog "Error during boot configuration checks: $_" "ERROR"
    }
    #endregion Boot Configuration Checks
    
    #region Hardware Behavior Analysis
    Write-Progress -Activity "System Analysis" -Status "Check 27/29: Hardware Behavior Patterns" -PercentComplete 93
    
    Write-OperationLog "═══════════════════════════════════════════════════════════════" "INFO"
    Write-OperationLog "CHECK 27/29: HARDWARE BEHAVIOR ANALYSIS" "INFO"
    Write-OperationLog "═══════════════════════════════════════════════════════════════" "INFO"
    Write-OperationLog "Starting hardware behavior analysis" "INFO"
    
    try {
        $behaviorFindings = @()
        
        # Monitor memory access patterns via performance counters
        try {
            Write-OperationLog "Querying performance counters for memory metrics" "QUERY" -Details @{
                Counters = "\Memory\Pages/sec, \Memory\Available MBytes, \Memory\Cache Bytes, \Memory\Pool Nonpaged Bytes"
            }
            
            $memCounters = Get-Counter -Counter @(
                "\Memory\Pages/sec",
                "\Memory\Available MBytes",
                "\Memory\Cache Bytes",
                "\Memory\Pool Nonpaged Bytes"
            ) -ErrorAction SilentlyContinue
            
            # High page fault rate can indicate DMA thrashing
            $pagesPerSec = ($memCounters.CounterSamples | Where-Object {$_.Path -match "Pages/sec"}).CookedValue
            $availableMB = ($memCounters.CounterSamples | Where-Object {$_.Path -match "Available MBytes"}).CookedValue
            
            Write-OperationLog "Performance counters collected" "SUCCESS" -Details @{
                PagesPerSec = [math]::Round($pagesPerSec, 2)
                AvailableMB = [math]::Round($availableMB, 2)
                Threshold = 1000
            }
            
            if ($pagesPerSec -gt 1000) {
                $behaviorFindings += @{
                    Category = "Excessive Memory Paging"
                    Severity = "MEDIUM"
                    Evidence = "Memory pages/sec: $([math]::Round($pagesPerSec, 2)) (normal: <500)"
                    Impact = "May indicate DMA device accessing memory aggressively"
                    SuspicionScore = 35
                }
                Write-OperationLog "MEDIUM: High memory paging rate detected" "FINDING" -Details @{
                    PagesPerSec = [math]::Round($pagesPerSec, 2)
                    SuspicionScore = 35
                }
            }
        } catch {
            Write-OperationLog "Could not query memory performance counters" "WARNING" -Details @{
                Exception = $_.Exception.Message
            }
        }
        
        # Check for devices with excessive IRQ (Interrupt Request) allocations
        Write-OperationLog "Querying Win32_PnPAllocatedResource for IRQ analysis" "QUERY"
        
        $irqResources = Get-CimInstance Win32_PnPAllocatedResource -ErrorAction SilentlyContinue | Where-Object {
            $_.ResourceType -eq 4  # IRQ resource type
        }
        
        Write-OperationLog "IRQ resources collected" "SUCCESS" -Details @{
            TotalIRQAllocations = $irqResources.Count
        }
        
        if ($irqResources) {
            # Group by device, count IRQs per device
            $irqByDevice = $irqResources | Group-Object -Property Dependent | Where-Object {
                $_.Count -gt 8  # Normal devices use 1-4 IRQs, suspicious if >8
            }
            
            foreach ($deviceGroup in $irqByDevice) {
                # Extract device instance ID from CIM path
                if ($deviceGroup.Name -match 'DeviceID="([^"]+)"') {
                    $deviceId = $matches[1]
                    $device = Get-CachedPnpDevices | Where-Object {$_.InstanceId -eq $deviceId} | Select-Object -First 1
                    
                    if ($device -and $device.Class -ne "Display") {  # GPUs legitimately use many IRQs
                        $behaviorFindings += @{
                            Category = "Excessive IRQ Allocation"
                            Severity = "MEDIUM"
                            Evidence = "Device '$($device.FriendlyName)' allocated $($deviceGroup.Count) IRQ lines (normal: 1-4)"
                            DeviceID = $deviceId
                            Impact = "High interrupt rate typical of DMA devices performing rapid memory access"
                            SuspicionScore = 40
                        }
                        Write-OperationLog "MEDIUM: Device with excessive IRQs: $($device.FriendlyName)" "WARNING"
                    }
                }
            }
        }
        
        # Check for devices accessing high memory addresses (>4GB) - unusual for non-GPU PCIe devices
        $memoryAddresses = Get-CimInstance Win32_DeviceMemoryAddress -ErrorAction SilentlyContinue
        
        if ($memoryAddresses) {
            $highMemDevices = @($memoryAddresses | Where-Object {
                try {
                    # Convert hex address to int64
                    $endAddr = [Convert]::ToInt64($_.EndingAddress, 16)
                    # Check if accessing above 4GB (0x100000000)
                    $endAddr -gt 4294967296 -and $_.Name -notmatch "Display|Video|GPU|Graphics"
                } catch {
                    $false
                }
            })
            
            foreach ($mem in $highMemDevices) {
                $behaviorFindings += @{
                    Category = "High Memory Access Pattern"
                    Severity = "MEDIUM"
                    Evidence = "Device '$($mem.Name)' accessing memory above 4GB (ending: 0x$($mem.EndingAddress))"
                    Impact = "Non-GPU devices rarely need >4GB addressing - potential DMA scanning all memory"
                    MemoryRange = "0x$($mem.StartingAddress) - 0x$($mem.EndingAddress)"
                    SuspicionScore = 45
                }
                Write-OperationLog "MEDIUM: High memory access by: $($mem.Name)" "WARNING"
            }
        }
        
        # Check for PCIe devices with unusually large BAR (Base Address Register) sizes
        # DMA devices often request large memory-mapped regions
        $pciDevices = Get-CachedPciDevices
        $largeBarDevices = @()
        
        foreach ($device in $pciDevices) {
            # Get all memory resources for this device
            $deviceMemory = $memoryAddresses | Where-Object {$_.Name -eq $device.FriendlyName}
            
            if ($deviceMemory) {
                foreach ($mem in $deviceMemory) {
                    try {
                        $start = [Convert]::ToInt64($mem.StartingAddress, 16)
                        $end = [Convert]::ToInt64($mem.EndingAddress, 16)
                        $size = $end - $start
                        
                        # BAR size >256MB is unusual for non-GPU devices
                        if ($size -gt 268435456 -and $device.Class -ne "Display") {
                            $largeBarDevices += @{
                                Device = $device.FriendlyName
                                SizeMB = [math]::Round($size / 1MB, 2)
                                Range = "0x$($mem.StartingAddress) - 0x$($mem.EndingAddress)"
                            }
                        }
                    } catch {
                        # Skip devices with invalid addresses
                    }
                }
            }
        }
        
        if ($largeBarDevices.Count -gt 0) {
            $behaviorFindings += @{
                Category = "Large Memory-Mapped I/O Regions"
                Severity = "MEDIUM"
                Evidence = "Found $($largeBarDevices.Count) non-GPU device(s) with >256MB memory regions"
                Devices = ($largeBarDevices | ForEach-Object {"$($_.Device): $($_.SizeMB) MB"}) -join "; "
                Impact = "Large BARs allow device to access significant memory ranges - DMA attack vector"
                SuspicionScore = 50
            }
            Write-OperationLog "MEDIUM: Large BAR devices detected: $($largeBarDevices.Count)" "WARNING"
        }
        
        # Check for devices with DMA capabilities explicitly enabled
        $dmaCapableDevices = @(Get-CachedPnpDevices | Where-Object {
            $_.Capabilities -match "DMA" -or
            $_.ConfigManagerErrorCode -eq 0 -and  # Working properly
            ($_.InstanceId -match "PCI" -and $_.Class -in @("System", "Unknown", "Other"))
        })
        
        if ($dmaCapableDevices.Count -gt 5) {
            # More than 5 unknown/system PCI devices with potential DMA is suspicious
            $behaviorFindings += @{
                Category = "Multiple DMA-Capable System Devices"
                Severity = "MEDIUM"
                Evidence = "Found $($dmaCapableDevices.Count) PCI devices in System/Unknown class with DMA capability"
                Impact = "Legitimate systems typically have 2-4 such devices; excess may indicate attack hardware"
                DeviceCount = $dmaCapableDevices.Count
                SuspicionScore = 35
            }
            Write-OperationLog "MEDIUM: Multiple DMA-capable devices: $($dmaCapableDevices.Count)" "WARNING"
        }
        
        if ($behaviorFindings.Count -gt 0) {
            [void](Report-ScoredFinding -Category "Hardware Behavior Analysis" -Findings $behaviorFindings)
        }
        
        Add-AuditEntry -CheckName "Hardware Behavior Analysis" -Status "Completed" `
            -ItemsScanned 6 -SuspiciousFound $behaviorFindings.Count `
            -Details @{
                MemoryPageRate = if ($pagesPerSec) { [math]::Round($pagesPerSec, 2) } else { "N/A" }
                HighIRQDevices = ($irqByDevice | Measure-Object).Count
                HighMemoryDevices = $highMemDevices.Count
                LargeBARDevices = $largeBarDevices.Count
                DMACapableDevices = $dmaCapableDevices.Count
            }
    } catch {
        Write-OperationLog "Error during hardware behavior analysis: $_" "ERROR"
    }
    #endregion Hardware Behavior Analysis
    
    #region UEFI Integrity Checking
    Write-Progress -Activity "System Analysis" -Status "Check 28/29: UEFI Integrity Verification" -PercentComplete 96
    Write-OperationLog "Starting UEFI integrity checks" "INFO"
    
    try {
        $uefiFindings = @()
        
        # Check if system supports UEFI
        $firmwareType = (Get-ComputerInfo).BiosFirmwareType
        
        if ($firmwareType -ne "Uefi") {
            Write-OperationLog "System uses legacy BIOS, skipping UEFI checks" "INFO"
            Add-AuditEntry -CheckName "UEFI Integrity" -Status "Skipped" `
                -ItemsScanned 0 -SuspiciousFound 0 `
                -Details @{ Reason = "Legacy BIOS system" }
        } else {
            Write-OperationLog "UEFI firmware detected, performing integrity checks" "INFO"
            
            # 1. Locate and scan EFI System Partition (ESP)
            try {
                $espPartitions = Get-Partition | Where-Object {
                    $_.GptType -eq "{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}"  # EFI System Partition GUID
                }
                
                foreach ($esp in $espPartitions) {
                    try {
                        # Temporarily assign drive letter if not present
                        $hadLetter = $esp.DriveLetter
                        
                        if (-not $hadLetter) {
                            $availableLetter = (68..90 | ForEach-Object {[char]$_} | Where-Object {
                                (Get-Volume -DriveLetter $_ -ErrorAction SilentlyContinue) -eq $null
                            })[0]
                            
                            $esp | Set-Partition -NewDriveLetter $availableLetter
                            $espDrive = "${availableLetter}:"
                        } else {
                            $espDrive = "$($esp.DriveLetter):"
                        }
                        
                        # Scan for .efi files
                        $efiFiles = Get-ChildItem -Path "$espDrive\EFI" -Filter "*.efi" -Recurse -ErrorAction SilentlyContinue
                        
                        $unsignedEfiFiles = @()
                        $suspiciousNames = @("pcileech", "dma", "kernel", "exploit", "inject", "loader")
                        
                        foreach ($efiFile in $efiFiles) {
                            # Check digital signature
                            $sig = Get-AuthenticodeSignature -FilePath $efiFile.FullName -ErrorAction SilentlyContinue
                            
                            if ($sig.Status -ne "Valid") {
                                $unsignedEfiFiles += @{
                                    Path = $efiFile.FullName.Replace($espDrive, "ESP:")
                                    Name = $efiFile.Name
                                    SignatureStatus = $sig.Status
                                    SizeMB = [math]::Round($efiFile.Length / 1MB, 2)
                                }
                                
                                # Extra scrutiny for suspicious names
                                $isSuspiciousName = $suspiciousNames | Where-Object {$efiFile.Name -match $_}
                                
                                if ($isSuspiciousName) {
                                    $uefiFindings += @{
                                        Category = "Suspicious UEFI Executable"
                                        Severity = "HIGH"
                                        Evidence = "Unsigned/invalid EFI file with suspicious name: $($efiFile.FullName)"
                                        SignatureStatus = $sig.Status
                                        Impact = "UEFI-level malware/rootkit can hide DMA devices from OS detection"
                                        SuspicionScore = 85
                                    }
                                    Write-OperationLog "HIGH: Suspicious EFI file: $($efiFile.Name)" "WARNING"
                                }
                            }
                        }
                        
                        if ($unsignedEfiFiles.Count -gt 3) {
                            # Most systems have 0-2 unsigned EFI files; >3 is unusual
                            $uefiFindings += @{
                                Category = "Multiple Unsigned UEFI Executables"
                                Severity = "MEDIUM"
                                Evidence = "Found $($unsignedEfiFiles.Count) unsigned/invalid .efi files in ESP"
                                Files = ($unsignedEfiFiles | Select-Object -First 5 | ForEach-Object {$_.Path}) -join "; "
                                Impact = "Unsigned UEFI executables bypass Secure Boot; potential bootkit vector"
                                SuspicionScore = 55
                            }
                            Write-OperationLog "MEDIUM: Multiple unsigned EFI files: $($unsignedEfiFiles.Count)" "WARNING"
                        }
                        
                        # Remove temporary drive letter if we added it
                        if (-not $hadLetter) {
                            $esp | Remove-PartitionAccessPath -AccessPath "$espDrive\"
                        }
                        
                    } catch {
                        Write-OperationLog "Could not scan ESP partition: $_" "INFO"
                    }
                }
                
            } catch {
                Write-OperationLog "Could not locate EFI System Partition: $_" "INFO"
            }
            
            # 2. Check TPM Platform Configuration Registers (PCRs) if available
            try {
                $tpm = Get-Tpm -ErrorAction SilentlyContinue
                
                if ($tpm -and $tpm.TpmPresent) {
                    # Check if TPM is enabled and ready
                    if (-not $tpm.TpmReady) {
                        $uefiFindings += @{
                            Category = "TPM Not Ready"
                            Severity = "MEDIUM"
                            Evidence = "TPM present but not in ready state (Enabled: $($tpm.TpmEnabled), Owned: $($tpm.TpmOwned))"
                            Impact = "TPM should validate firmware integrity; disabled TPM allows bootkit persistence"
                            SuspicionScore = 45
                        }
                        Write-OperationLog "MEDIUM: TPM not ready - bootkit risk" "WARNING"
                    }
                    
                    # Note: Direct PCR reading requires low-level TPM commands not available via Get-Tpm
                    # We can infer issues if measured boot is disabled
                    $measuredBoot = Get-CimInstance -Namespace "root\cimv2\Security\MicrosoftTpm" `
                        -ClassName Win32_Tpm -ErrorAction SilentlyContinue
                    
                    if ($measuredBoot -and -not $measuredBoot.IsEnabled_InitialValue) {
                        $uefiFindings += @{
                            Category = "Measured Boot Disabled"
                            Severity = "MEDIUM"
                            Evidence = "TPM-based measured boot is disabled"
                            Impact = "Firmware modifications not recorded in TPM PCRs - bootkit can evade detection"
                            SuspicionScore = 50
                        }
                        Write-OperationLog "MEDIUM: Measured boot disabled" "WARNING"
                    }
                } else {
                    Write-OperationLog "TPM not present or not accessible" "INFO"
                }
            } catch {
                Write-OperationLog "Could not check TPM status: $_" "INFO"
            }
            
            # 3. Verify UEFI Secure Boot database integrity
            try {
                $secureBootEnabled = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
                
                if ($secureBootEnabled) {
                    # Check UEFI variable databases
                    $uefiDatabases = @("PK", "KEK", "db", "dbx")  # Platform Key, Key Exchange Key, Signature DB, Forbidden DB
                    $corruptDatabases = @()
                    
                    foreach ($dbName in $uefiDatabases) {
                        try {
                            $dbContent = Get-SecureBootUEFI -Name $dbName -ErrorAction Stop
                            
                            # Basic sanity check - databases shouldn't be empty
                            if ($dbContent.Bytes.Length -eq 0) {
                                $corruptDatabases += $dbName
                            }
                        } catch {
                            $corruptDatabases += $dbName
                        }
                    }
                    
                    if ($corruptDatabases.Count -gt 0) {
                        $uefiFindings += @{
                            Category = "UEFI Variable Database Corruption"
                            Severity = "HIGH"
                            Evidence = "UEFI Secure Boot databases are missing or corrupted: $($corruptDatabases -join ', ')"
                            Impact = "Compromised UEFI variables allow bootkit to persist across reboots"
                            CorruptedDBs = $corruptDatabases -join ", "
                            SuspicionScore = 75
                        }
                        Write-OperationLog "HIGH: UEFI database corruption detected: $($corruptDatabases -join ', ')" "WARNING"
                    }
                    
                } else {
                    Write-OperationLog "Secure Boot is disabled, skipping database checks" "INFO"
                }
            } catch {
                Write-OperationLog "Could not verify Secure Boot databases: $_" "INFO"
            }
            
            # 4. Check for known UEFI rootkit indicators
            # LoJax, MosaicRegressor, etc. often modify specific UEFI modules
            $knownRootkitPaths = @(
                "ESP:\EFI\Boot\lojax.efi",
                "ESP:\EFI\Microsoft\Boot\bootmgfw_backup.efi",  # Backup created by some rootkits
                "ESP:\EFI\Boot\grubx64.efi",  # Suspicious if not a dual-boot system
                "ESP:\EFI\Boot\fallback.efi"  # Sometimes abused
            )
            
            # Check registry for UEFI boot order modifications
            try {
                $bootOrder = bcdedit /enum firmware | Select-String -Pattern "identifier|description|path" -Context 0,2
                
                # Look for unusual boot entries
                $suspiciousBootEntries = $bootOrder | Where-Object {
                    $_.Line -match "pcileech|dma|kernel|exploit|unknown"
                }
                
                if ($suspiciousBootEntries) {
                    $uefiFindings += @{
                        Category = "Suspicious UEFI Boot Entry"
                        Severity = "HIGH"
                        Evidence = "Found suspicious entries in UEFI boot configuration"
                        Impact = "Modified boot order can load malicious UEFI applications before OS"
                        SuspicionScore = 80
                    }
                    Write-OperationLog "HIGH: Suspicious UEFI boot entry detected" "WARNING"
                }
            } catch {
                Write-OperationLog "Could not enumerate UEFI boot entries: $_" "INFO"
            }
            
            if ($uefiFindings.Count -gt 0) {
                [void](Report-ScoredFinding -Category "UEFI Integrity" -Findings $uefiFindings)
            }
            
            Add-AuditEntry -CheckName "UEFI Integrity" -Status "Completed" `
                -ItemsScanned 4 -SuspiciousFound $uefiFindings.Count `
                -Details @{
                    FirmwareType = $firmwareType
                    SecureBootEnabled = (try { Confirm-SecureBootUEFI } catch { $false })
                    TPMPresent = (try { (Get-Tpm).TpmPresent } catch { $false })
                    UnsignedEFIFiles = if ($unsignedEfiFiles) { $unsignedEfiFiles.Count } else { 0 }
                }
        }
        
    } catch {
        Write-OperationLog "Error during UEFI integrity checks: $_" "ERROR"
    }
    #endregion UEFI Integrity Checking
    
    #region Device Timing Analysis
    Write-Progress -Activity "System Analysis" -Status "Check 29/29: Device Connection Pattern Analysis" -PercentComplete 100
    Write-OperationLog "Starting historical device timing analysis" "INFO"
    
    try {
        $timingFindings = @()
        $lookbackDays = 90  # Analyze last 90 days of device activity
        
        # 1. Analyze Windows Event Logs for device arrival/removal patterns
        try {
            $startDate = (Get-Date).AddDays(-$lookbackDays)
            
            # Event IDs: 20001 (Device Installation), 20003 (Device Removal), 10000 (Driver Install Start)
            $deviceEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'System'
                ProviderName = 'Microsoft-Windows-UserPnp', 'Microsoft-Windows-Kernel-PnP'
                StartTime = $startDate
            } -ErrorAction SilentlyContinue | Where-Object {
                $_.Id -in @(20001, 20003, 10000, 10001)
            }
            
            if ($deviceEvents) {
                # Group events by device instance ID
                $deviceActivity = @{}
                
                foreach ($event in $deviceEvents) {
                    # Extract device ID from event message
                    if ($event.Message -match 'Device ([A-Z0-9\\]+)') {
                        $deviceId = $matches[1]
                        
                        if (-not $deviceActivity.ContainsKey($deviceId)) {
                            $deviceActivity[$deviceId] = @{
                                Arrivals = @()
                                Removals = @()
                                DeviceID = $deviceId
                            }
                        }
                        
                        if ($event.Id -in @(20001, 10000)) {
                            $deviceActivity[$deviceId].Arrivals += $event.TimeCreated
                        } elseif ($event.Id -in @(20003, 10001)) {
                            $deviceActivity[$deviceId].Removals += $event.TimeCreated
                        }
                    }
                }
                
                # Analyze connection patterns
                foreach ($deviceId in $deviceActivity.Keys) {
                    $activity = $deviceActivity[$deviceId]
                    $totalConnections = $activity.Arrivals.Count
                    
                    # Suspicious pattern 1: Very few connections (<5) but recent activity
                    if ($totalConnections -gt 0 -and $totalConnections -lt 5) {
                        $mostRecentConnection = $activity.Arrivals | Sort-Object -Descending | Select-Object -First 1
                        $daysSinceLastConnect = ((Get-Date) - $mostRecentConnection).Days
                        
                        # Get device details
                        $device = Get-CachedPnpDevices | Where-Object {$_.InstanceId -eq $deviceId} | Select-Object -First 1
                        
                        if ($daysSinceLastConnect -lt 7 -and $device) {
                            $timingFindings += @{
                                Category = "Intermittent Device Connection"
                                Severity = "MEDIUM"
                                Evidence = "Device '$($device.FriendlyName)' connected only $totalConnections time(s) in $lookbackDays days"
                                DeviceID = $deviceId
                                LastConnection = $mostRecentConnection.ToString("yyyy-MM-dd HH:mm:ss")
                                Impact = "Attack hardware often only connected during gaming sessions to avoid detection"
                                SuspicionScore = 40
                            }
                            Write-OperationLog "MEDIUM: Intermittent device: $($device.FriendlyName)" "WARNING"
                        }
                    }
                    
                    # Suspicious pattern 2: Rapid connect/disconnect cycles (potential testing/evasion)
                    if ($totalConnections -gt 10) {
                        $sortedArrivals = $activity.Arrivals | Sort-Object
                        $shortIntervals = 0
                        
                        for ($i = 1; $i -lt $sortedArrivals.Count; $i++) {
                            $interval = ($sortedArrivals[$i] - $sortedArrivals[$i-1]).TotalMinutes
                            if ($interval -lt 5) {
                                $shortIntervals++
                            }
                        }
                        
                        # More than 30% of connections within 5 minutes of previous
                        if ($shortIntervals -gt ($totalConnections * 0.3)) {
                            $device = Get-CachedPnpDevices | Where-Object {$_.InstanceId -eq $deviceId} | Select-Object -First 1
                            
                            if ($device) {
                                $timingFindings += @{
                                    Category = "Rapid Connect/Disconnect Pattern"
                                    Severity = "MEDIUM"
                                    Evidence = "Device '$($device.FriendlyName)' shows $shortIntervals rapid reconnections (>30% within 5min)"
                                    DeviceID = $deviceId
                                    TotalConnections = $totalConnections
                                    Impact = "Rapid cycling may indicate attacker testing device or evading detection"
                                    SuspicionScore = 45
                                }
                                Write-OperationLog "MEDIUM: Rapid cycling device: $($device.FriendlyName)" "WARNING"
                            }
                        }
                    }
                }
                
                Write-OperationLog "Analyzed $($deviceActivity.Keys.Count) unique devices from event logs" "INFO"
            }
            
        } catch {
            Write-OperationLog "Could not analyze device event logs: $_" "INFO"
        }
        
        # 2. Parse setupapi.dev.log for installation timing patterns
        try {
            $setupApiLog = "$env:windir\inf\setupapi.dev.log"
            
            if (Test-Path $setupApiLog) {
                # Read last 10,000 lines to avoid parsing entire log (can be huge)
                $logContent = Get-Content $setupApiLog -Tail 10000 -ErrorAction SilentlyContinue
                
                # Look for device installations with timestamps
                $recentInstalls = @{}
                
                foreach ($line in $logContent) {
                    # Match timestamp lines: ">>>  [Device Install (Hardware initiated) - PCI\VEN_..."
                    if ($line -match '>>>\s+\[Device Install.*?\]\s+-\s+([A-Z0-9\\&_]+)') {
                        $deviceId = $matches[1]
                        
                        # Next line usually contains timestamp
                        $timestampIndex = [array]::IndexOf($logContent, $line) + 1
                        if ($timestampIndex -lt $logContent.Length) {
                            $timestampLine = $logContent[$timestampIndex]
                            
                            if ($timestampLine -match '>>>\s+Section start (\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d+)') {
                                $timestamp = $matches[1]
                                
                                try {
                                    $installTime = [DateTime]::ParseExact($timestamp, "yyyy/MM/dd HH:mm:ss.fff", $null)
                                    
                                    if (-not $recentInstalls.ContainsKey($deviceId)) {
                                        $recentInstalls[$deviceId] = @()
                                    }
                                    
                                    $recentInstalls[$deviceId] += $installTime
                                } catch {
                                    # Skip invalid timestamps
                                }
                            }
                        }
                    }
                }
                
                # Check for devices installed very recently (within last 7 days) but not currently present
                $recentThreshold = (Get-Date).AddDays(-7)
                $currentDevices = Get-CachedPnpDevices | ForEach-Object {$_.InstanceId}
                
                foreach ($deviceId in $recentInstalls.Keys) {
                    $latestInstall = $recentInstalls[$deviceId] | Sort-Object -Descending | Select-Object -First 1
                    
                    if ($latestInstall -gt $recentThreshold -and $deviceId -notin $currentDevices) {
                        # Device was installed recently but is now gone
                        $timingFindings += @{
                            Category = "Recently Removed Device"
                            Severity = "MEDIUM"
                            Evidence = "Device installed on $($latestInstall.ToString('yyyy-MM-dd HH:mm')) but no longer present"
                            DeviceID = $deviceId
                            InstallCount = $recentInstalls[$deviceId].Count
                            Impact = "Device removal after use typical of covert attack hardware"
                            SuspicionScore = 50
                        }
                        Write-OperationLog "MEDIUM: Recently removed device: $deviceId" "WARNING"
                    }
                }
                
                Write-OperationLog "Parsed setupapi.dev.log: found $($recentInstalls.Keys.Count) recent installations" "INFO"
            }
            
        } catch {
            Write-OperationLog "Could not parse setupapi.dev.log: $_" "INFO"
        }
        
        # 3. Check for devices with suspicious connection time correlation
        # (e.g., always connects around same time - possible automated attack)
        try {
            if ($deviceActivity -and $deviceActivity.Keys.Count -gt 0) {
                foreach ($deviceId in $deviceActivity.Keys) {
                    $arrivals = $deviceActivity[$deviceId].Arrivals
                    
                    if ($arrivals.Count -gt 5) {
                        # Group by hour of day
                        $hourGroups = $arrivals | Group-Object {$_.Hour}
                        
                        # If >70% of connections happen in same 2-hour window, flag it
                        $largestGroup = $hourGroups | Sort-Object Count -Descending | Select-Object -First 1
                        
                        if ($largestGroup -and ($largestGroup.Count / $arrivals.Count) -gt 0.7) {
                            $device = Get-CachedPnpDevices | Where-Object {$_.InstanceId -eq $deviceId} | Select-Object -First 1
                            
                            if ($device) {
                                $timingFindings += @{
                                    Category = "Predictable Connection Times"
                                    Severity = "LOW"
                                    Evidence = "Device '$($device.FriendlyName)' connects $($largestGroup.Count)/$($arrivals.Count) times around $($largestGroup.Name):00"
                                    DeviceID = $deviceId
                                    Impact = "Consistent connection timing may indicate scripted/automated attack setup"
                                    SuspicionScore = 25
                                }
                                Write-OperationLog "LOW: Predictable timing: $($device.FriendlyName)" "INFO"
                            }
                        }
                    }
                }
            }
            
        } catch {
            Write-OperationLog "Could not analyze connection time correlation: $_" "INFO"
        }
        
        if ($timingFindings.Count -gt 0) {
            [void](Report-ScoredFinding -Category "Device Timing Analysis" -Findings $timingFindings)
        }
        
        Add-AuditEntry -CheckName "Device Timing Analysis" -Status "Completed" `
            -ItemsScanned 3 -SuspiciousFound $timingFindings.Count `
            -Details @{
                LookbackDays = $lookbackDays
                DevicesAnalyzed = if ($deviceActivity) { $deviceActivity.Keys.Count } else { 0 }
                IntermittentDevices = ($timingFindings | Where-Object {$_.Category -eq "Intermittent Device Connection"}).Count
                RapidCyclingDevices = ($timingFindings | Where-Object {$_.Category -eq "Rapid Connect/Disconnect Pattern"}).Count
                RecentlyRemovedDevices = ($timingFindings | Where-Object {$_.Category -eq "Recently Removed Device"}).Count
            }
        
    } catch {
        Write-OperationLog "Error during device timing analysis: $_" "ERROR"
    }
    #endregion Device Timing Analysis
    
    # 4. Collect Current Device List
    # Silent collection
    $deviceFolder = Join-Path $forensicFolder "Devices"
    $null = New-Item -Path $deviceFolder -ItemType Directory -Force
    
    # All PnP devices
    Get-CachedPnpDevices | Select-Object FriendlyName, InstanceId, Status, Class, Manufacturer, DriverVersion, DriverDate, HardwareID |
        Export-Csv (Join-Path $deviceFolder "AllDevices.csv") -NoTypeInformation
    
    # PCI devices specifically
    Get-CachedPciDevices | Select-Object FriendlyName, InstanceId, Status, Class, HardwareID |
        Export-Csv (Join-Path $deviceFolder "PCI_Devices.csv") -NoTypeInformation
    
    # USB devices
    Get-CachedPnpDevices | Where-Object { $_.InstanceId -like "USB\*" } |
        Select-Object FriendlyName, InstanceId, Status, Class, HardwareID |
        Export-Csv (Join-Path $deviceFolder "USB_Devices.csv") -NoTypeInformation
    
    # Detailed device properties
    $deviceDetails = @()
    foreach ($dev in (Get-CachedPciDevices | Select-Object -First 50)) {
        try {
            $props = @{
                FriendlyName = $dev.FriendlyName
                InstanceId = $dev.InstanceId
                Status = $dev.Status
                Class = $dev.Class
                HardwareID = $dev.HardwareID -join "; "
            }
            
            # Get additional properties
            $serial = (Get-PnpDeviceProperty -InstanceId $dev.InstanceId -KeyName "DEVPKEY_Device_SerialNumber" -ErrorAction SilentlyContinue).Data
            if ($serial) { $props['SerialNumber'] = $serial }
            
            $location = (Get-PnpDeviceProperty -InstanceId $dev.InstanceId -KeyName "DEVPKEY_Device_LocationInfo" -ErrorAction SilentlyContinue).Data
            if ($location) { $props['LocationInfo'] = $location }
            
            $installDate = (Get-PnpDeviceProperty -InstanceId $dev.InstanceId -KeyName "DEVPKEY_Device_InstallDate" -ErrorAction SilentlyContinue).Data
            if ($installDate) { $props['InstallDate'] = $installDate }
            
            $deviceDetails += [PSCustomObject]$props
        } catch { }
    }
    $deviceDetails | Export-Csv (Join-Path $deviceFolder "PCI_DetailedProperties.csv") -NoTypeInformation
    
    # 5. Collect Driver Information
    # Silent collection
    $driverFolder = Join-Path $forensicFolder "Drivers"
    $null = New-Item -Path $driverFolder -ItemType Directory -Force
    
    # All installed drivers
    Get-WindowsDriver -Online -All | Select-Object OriginalFileName, ProviderName, ClassName, Version, Date, BootCritical |
        Export-Csv (Join-Path $driverFolder "InstalledDrivers.csv") -NoTypeInformation
    
    # Running drivers
    Get-CimInstance Win32_SystemDriver | Select-Object Name, DisplayName, PathName, State, Status, StartMode, ServiceType |
        Export-Csv (Join-Path $driverFolder "RunningDrivers.csv") -NoTypeInformation
    
    # Driver store packages
    if (Test-Path "C:\Windows\System32\DriverStore\FileRepository") {
        Get-ChildItem "C:\Windows\System32\DriverStore\FileRepository" -Directory |
            Select-Object Name, CreationTime, LastWriteTime, @{N='SizeKB';E={[math]::Round((Get-ChildItem $_.FullName -Recurse -File | Measure-Object Length -Sum).Sum / 1KB, 2)}} |
            Export-Csv (Join-Path $driverFolder "DriverStorePackages.csv") -NoTypeInformation
    }
    
    # 6. Collect Network Configuration
    # Silent collection
    $networkFolder = Join-Path $forensicFolder "Network"
    $null = New-Item -Path $networkFolder -ItemType Directory -Force
    
    # Network adapters
    Get-NetAdapter | Select-Object Name, InterfaceDescription, MacAddress, Status, LinkSpeed, DriverVersion, DriverDate, DriverProvider |
        Export-Csv (Join-Path $networkFolder "NetworkAdapters.csv") -NoTypeInformation
    
    # Active connections
    Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess, CreationTime |
        Export-Csv (Join-Path $networkFolder "ActiveConnections.csv") -NoTypeInformation
    
    # Routing table
    Get-NetRoute | Select-Object DestinationPrefix, NextHop, InterfaceAlias, RouteMetric |
        Export-Csv (Join-Path $networkFolder "RoutingTable.csv") -NoTypeInformation
    
    # Security: Validate ipconfig command and execute safely
    $ipconfigCmd = Get-Command ipconfig.exe -ErrorAction SilentlyContinue
    if ($ipconfigCmd) {
        try {
            & $ipconfigCmd.Source /all | Out-File (Join-Path $networkFolder "ipconfig.txt") -Encoding UTF8 -ErrorAction Stop
        } catch {
            Write-Verbose "Failed to collect ipconfig data: $($_.Exception.Message)"
        }
    }
    
    # 7. Collect Running Processes
    # Silent collection
    $processFolder = Join-Path $forensicFolder "Processes"
    $null = New-Item -Path $processFolder -ItemType Directory -Force
    
    # Process list with details
    Get-Process | Select-Object Id, Name, Path, Company, ProductVersion, StartTime, 
        @{N='CPU_Seconds';E={$_.CPU}}, 
        @{N='WorkingSet_MB';E={[math]::Round($_.WorkingSet64/1MB,2)}},
        @{N='PrivateMemory_MB';E={[math]::Round($_.PrivateMemorySize64/1MB,2)}} |
        Export-Csv (Join-Path $processFolder "RunningProcesses.csv") -NoTypeInformation
    
    # Process command lines
    Get-CimInstance Win32_Process | Select-Object ProcessId, Name, CommandLine, ExecutablePath, CreationDate |
        Export-Csv (Join-Path $processFolder "ProcessCommandLines.csv") -NoTypeInformation
    
    # 8. Collect BIOS/Firmware Info
    # Silent collection
    Get-CimInstance Win32_BIOS | ConvertTo-Json -Depth 5 -WarningAction SilentlyContinue | Out-File (Join-Path $forensicFolder "BIOS_Info.json") -Encoding UTF8
    Get-CimInstance Win32_ComputerSystem | ConvertTo-Json -Depth 5 -WarningAction SilentlyContinue | Out-File (Join-Path $forensicFolder "ComputerSystem_Info.json") -Encoding UTF8
    
    # 9. Copy DMA Scan Results
    # Silent collection
    # This will be copied after the report is generated
    
    # Silent collection
    # Silent collection
    
} catch {
    # Error logged during forensic collection
}

# Complete the progress bar
Write-Progress -Activity "System Analysis Scan" -Completed

# Turn off silent mode for final report display
$script:silentMode = $false

# Generate Report
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "           SCAN COMPLETE" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Use the scan folder that was already created during forensic collection
# (scanFolder variable is already set earlier in the script)

# Create findings summary file
$findingsSummaryPath = Join-Path $scanFolder "Total-Findings.txt"
$summaryContent = @()

if ($script:findings.Count -eq 0) {
    $summaryContent += "No suspicious artifacts detected"
    Write-Host "[✓] Analysis complete - Results saved" -ForegroundColor Green
} else {
    $summaryContent += "Total findings: $($script:findings.Count)"
    $summaryContent += ""
    
    $critical = ($script:findings | Where-Object { $_.Severity -eq "CRITICAL" }).Count
    $high = ($script:findings | Where-Object { $_.Severity -eq "HIGH" }).Count
    $medium = ($script:findings | Where-Object { $_.Severity -eq "MEDIUM" }).Count
    $low = ($script:findings | Where-Object { $_.Severity -eq "LOW" }).Count
    
    $summaryContent += "Findings by Severity:"
    if ($critical -gt 0) { $summaryContent += "  CRITICAL: $critical" }
    if ($high -gt 0) { $summaryContent += "  HIGH: $high" }
    if ($medium -gt 0) { $summaryContent += "  MEDIUM: $medium" }
    if ($low -gt 0) { $summaryContent += "  LOW: $low" }
    
    $summaryContent += ""
    $summaryContent += "Detailed Findings:"
    $summaryContent += "=" * 80
    
    $script:findings | Sort-Object Severity,Category | ForEach-Object {
        $summaryContent += ""
        $summaryContent += "[$($_.Severity)] $($_.Category): $($_.Description)"
        $_.Details.GetEnumerator() | ForEach-Object {
            $summaryContent += "  $($_.Key): $($_.Value)"
        }
    }
    
    Write-Host "[✓] Analysis complete - Results saved" -ForegroundColor Green
}

# Write findings summary to file
$summaryContent | Out-File -FilePath $findingsSummaryPath -Encoding UTF8

# Export report
$reportPath = Join-Path $scanFolder "System-Analysis.json"

# Security: Redact sensitive information if requested
$computerName = if ($script:redactInfo) { "REDACTED" } else { $env:COMPUTERNAME }
$userName = if ($script:redactInfo) { "REDACTED" } else { $env:USERNAME }

$reportData = @{
    ScanDate = Get-Date
    ComputerName = $computerName
    UserName = $userName
    SensitiveInfoRedacted = $script:redactInfo
    TotalFindings = $script:findings.Count
    Findings = $script:findings
    AuditLog = $script:auditLog
    ScanSummary = @{
        TotalChecksPerformed = $script:auditLog.Count
        ChecksCompleted = ($script:auditLog | Where-Object { $_.Status -eq "Completed" }).Count
        ChecksWithErrors = ($script:auditLog | Where-Object { $_.Status -eq "Error" }).Count
        TotalItemsScanned = ($script:auditLog | Measure-Object -Property ItemsScanned -Sum).Sum
        TotalSuspiciousItemsFound = ($script:auditLog | Measure-Object -Property SuspiciousFound -Sum).Sum
    }
}

$reportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $reportPath -Encoding UTF8
Write-Host "`nDetailed JSON report saved to: " -NoNewline -ForegroundColor White
Write-Host "$reportPath" -ForegroundColor Yellow
Write-Host "Findings summary saved to: " -NoNewline -ForegroundColor White
Write-Host "$findingsSummaryPath" -ForegroundColor Yellow

# Copy scan report and findings summary to forensic folder
if (Test-Path $forensicFolder) {
    Copy-Item $reportPath (Join-Path $forensicFolder "System-Analysis.json") -ErrorAction SilentlyContinue
    Copy-Item $findingsSummaryPath (Join-Path $forensicFolder "Total-Findings.txt") -ErrorAction SilentlyContinue
    
    # Create a README file in the forensic folder
    $readmePath = Join-Path $forensicFolder "README.txt"
    $collectionDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $readmeContent = @"
SYSTEM ANALYZER - FORENSIC DATA COLLECTION
==============================================

Collection Date: $collectionDate
Computer Name: $env:COMPUTERNAME
User: $env:USERNAME

This folder contains comprehensive forensic data collected for offline analysis.

FOLDER STRUCTURE:
-----------------
/Registry/              - Exported registry keys (device history, drivers, services)
/Logs/                  - System log files and event logs (last 7 days)
  /EventLogs/           - Windows Event Log exports (System, Application, Security)
/Devices/               - Current and historical device inventories
/Drivers/               - Installed and running driver information
/Network/               - Network adapter and connection details
/Processes/             - Running process information with command lines
SystemInfo.txt          - System information (systeminfo output)
ComputerInfo.json       - Detailed computer information
BIOS_Info.json          - BIOS/UEFI firmware information
ComputerSystem_Info.json - Computer system details
System-Analysis.json    - System analysis scan results

KEY FILES FOR ANALYSIS:
-----------------------
1. System-Analysis.json - Main scan findings and suspicious indicators
2. /Registry/DeviceEnum.reg - Complete device enumeration history
3. /Registry/PCI_Devices.reg - PCI device registry entries
4. /Registry/USB_History.reg - USB device connection history
5. /Logs/setupapi.dev.log - Device installation log (timestamps, drivers)
6. /Devices/PCI_DetailedProperties.csv - Detailed PCI device properties
7. /Drivers/InstalledDrivers.csv - All installed drivers
8. /Drivers/RunningDrivers.csv - Currently running kernel drivers
9. /Network/ActiveConnections.csv - Active network connections
10. /Processes/ProcessCommandLines.csv - Process command line arguments

REGISTRY EXPORTS:
-----------------
- DeviceEnum.reg: HKLM\SYSTEM\CurrentControlSet\Enum (all device history)
- Services.reg: HKLM\SYSTEM\CurrentControlSet\Services (driver services)
- DeviceClasses.reg: Device class registrations
- USB_History.reg: USB device connection history
- PCI_Devices.reg: PCI device configurations
- DriverDatabase.reg: Windows driver database

ANALYSIS TIPS:
--------------
1. Check PCI_DetailedProperties.csv for suspicious serial numbers or device IDs
2. Review setupapi.dev.log for recent device installations (last 24-48 hours)
3. Compare USB_History.reg against currently connected devices
4. Analyze ProcessCommandLines.csv for suspicious process arguments
5. Review Security_DriverEvents.csv for unexpected driver loading events
6. Cross-reference System-Analysis.json findings with device/driver data

OFFLINE ANALYSIS TOOLS:
-----------------------
- Registry Editor (regedit.exe) - View .reg files
- RegScanner / Registry Explorer - Advanced registry analysis
- Excel / CSV viewers - Analyze CSV exports
- JSON viewers - Parse JSON reports
- Text editors - Review log files

For questions or support, refer to the System Analyzer documentation.
"@
    $readmeContent | Out-File -FilePath $readmePath -Encoding UTF8
    
    # Security: Generate integrity hashes for forensic data
    Write-Host "`n[*] Generating integrity hashes for forensic data..." -ForegroundColor Cyan
    $hashFile = Join-Path $scanFolder "INTEGRITY_HASHES.txt"
    $hashContent = @()
    $hashContent += "FORENSIC DATA INTEGRITY VERIFICATION"
    $hashContent += ("=" * 80)
    $hashContent += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $hashContent += "Algorithm: SHA256"
    $hashContent += ""
    $hashContent += "FILE HASHES:"
    $hashContent += ("-" * 80)
    $hashContent += ""
    
    try {
        $filesToHash = Get-ChildItem -Path $forensicFolder -Recurse -File | Where-Object { $_.Extension -ne '.tmp' }
        foreach ($file in $filesToHash) {
            try {
                $hash = Get-FileHash -Path $file.FullName -Algorithm SHA256 -ErrorAction Stop
                $relativePath = $file.FullName -replace [regex]::Escape($forensicFolder), "."
                $hashContent += "$($hash.Hash)  $relativePath"
            } catch {
                $hashContent += "ERROR  $($file.Name) - Failed to hash: $($_.Exception.Message)"
            }
        }
        $hashContent | Out-File -FilePath $hashFile -Encoding UTF8
        Write-Host "[✓] Integrity hashes saved to INTEGRITY_HASHES.txt" -ForegroundColor Green
    } catch {
        Write-Host "[!] Warning: Failed to generate integrity hashes: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  FORENSIC DATA PACKAGE CREATED" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Location: " -NoNewline -ForegroundColor White
    Write-Host "$forensicFolder" -ForegroundColor Yellow
    Write-Host "Contents: " -NoNewline -ForegroundColor White
    Write-Host "Registry exports, event logs, device history, drivers, network data, processes" -ForegroundColor Gray
    
    # Calculate total size
    $totalSize = (Get-ChildItem $forensicFolder -Recurse -File | Measure-Object -Property Length -Sum).Sum
    $totalSizeMB = [math]::Round($totalSize / 1MB, 2)
    Write-Host "Size: " -NoNewline -ForegroundColor White
    Write-Host "$totalSizeMB MB" -ForegroundColor Cyan
    
    # Create a ZIP file for easy transport
    Write-Host "`nCreating compressed archive..." -ForegroundColor Gray
    $zipPath = "$forensicFolder.zip"
    
    # Security: Log file operations
    $operationLog = Join-Path $scanFolder "OPERATION_LOG.txt"
    $logContent = @()
    $logContent += "FORENSIC COLLECTION OPERATION LOG"
    $logContent += ("=" * 80)
    $logContent += "Start Time: $($startTime.ToString('yyyy-MM-dd HH:mm:ss'))"
    $logContent += "End Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $logContent += "Duration: $([math]::Round(((Get-Date) - $startTime).TotalSeconds, 2)) seconds"
    $logContent += "Computer: $(if ($script:redactInfo) { 'REDACTED' } else { $env:COMPUTERNAME })"
    $logContent += "User: $(if ($script:redactInfo) { 'REDACTED' } else { $env:USERNAME })"
    $logContent += ""
    $logContent += "FILE OPERATIONS:"
    $logContent += ("-" * 80)
    
    # Finalize the comprehensive operation log BEFORE compression/deletion
    Write-OperationLog "═══════════════════════════════════════════════════════════════" "INFO"
    Write-OperationLog "SYSTEM ANALYSIS COMPLETE" "SUCCESS"
    Write-OperationLog "═══════════════════════════════════════════════════════════════" "INFO"
    
    Write-OperationLog "Scan summary" "INFO" -Details @{
        TotalFindings = $script:findings.Count
        TotalChecks = $script:auditLog.Count
        ChecksCompleted = (($script:auditLog | Where-Object { $_.Status -eq 'Completed' }).Count)
        ChecksWithErrors = (($script:auditLog | Where-Object { $_.Status -eq 'Error' }).Count)
        ScanDurationSeconds = [math]::Round(((Get-Date) - $startTime).TotalSeconds, 2)
    }
    
    # Save the comprehensive operation log with statistics BEFORE compression
    Save-OperationLog
    
    # Copy the comprehensive operation log to the scan folder (root) for easy access
    $scanFolderOperationLog = Join-Path $scanFolder "OPERATION_LOG.txt"
    Copy-Item -Path $script:operationLogPath -Destination $scanFolderOperationLog -Force -ErrorAction SilentlyContinue
    
    try {
        # Log compression operation
        $logContent += "Compressing forensic data to: $zipPath"
        Write-OperationLog "Creating compressed archive" "ACTION" -Details @{
            SourceFolder = $forensicFolder
            DestinationZip = $zipPath
        }
        
        Compress-Archive -Path $forensicFolder -DestinationPath $zipPath -CompressionLevel Optimal -Force -ErrorAction Stop
        $zipSize = [math]::Round((Get-Item $zipPath).Length / 1MB, 2)
        $logContent += "SUCCESS: Archive created ($zipSize MB)"
        
        Write-Host "[✓] " -NoNewline -ForegroundColor Green
        Write-Host "Compressed archive created: " -NoNewline -ForegroundColor White
        Write-Host "$zipPath" -ForegroundColor Yellow
        Write-Host "    Compressed size: " -NoNewline -ForegroundColor White
        Write-Host "$zipSize MB" -ForegroundColor Cyan
        
        # Delete the uncompressed folder to save space
        Write-Host "`nCleaning up temporary files..." -ForegroundColor Gray
        $logContent += "Removing uncompressed folder: $forensicFolder"
        Remove-Item -Path $forensicFolder -Recurse -Force -ErrorAction Stop
        $logContent += "SUCCESS: Temporary files removed"
        Write-Host "[✓] " -NoNewline -ForegroundColor Green
        Write-Host "Uncompressed files removed" -ForegroundColor White
    } catch {
        $logContent += "ERROR: Failed to compress or cleanup - $($_.Exception.Message)"
        Write-Host "[!] " -NoNewline -ForegroundColor Yellow
        Write-Host "Could not create ZIP archive: $($_.Exception.Message)" -ForegroundColor Gray
    }
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "   SYSTEM ANALYSIS COMPLETE" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
$scanDuration = ((Get-Date) - $startTime).TotalSeconds
Write-Host "Scan completed in " -NoNewline -ForegroundColor White
Write-Host "$([math]::Round($scanDuration, 1)) seconds" -ForegroundColor Cyan
Write-Host ""


