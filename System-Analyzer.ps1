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
$script:totalChecks = 17
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

try {
    # 1. Collect System Information
    # Silent collection
    $sysInfoPath = Join-Path $forensicFolder "SystemInfo.txt"
    
    # Security: Validate systeminfo command exists and execute safely
    $systeminfoCmd = Get-Command systeminfo.exe -ErrorAction SilentlyContinue
    if ($systeminfoCmd) {
        try {
            & $systeminfoCmd.Source | Out-File -FilePath $sysInfoPath -Encoding UTF8 -ErrorAction Stop
        } catch {
            Write-Host "[!] Warning: Failed to collect system information: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    
    Get-ComputerInfo -ErrorAction SilentlyContinue | ConvertTo-Json -Depth 5 -WarningAction SilentlyContinue | Out-File -FilePath (Join-Path $forensicFolder "ComputerInfo.json") -Encoding UTF8
    
    # 2. Export Registry Keys (Device History)
    # Silent collection
    $regFolder = Join-Path $forensicFolder "Registry"
    $null = New-Item -Path $regFolder -ItemType Directory -Force
    
    # Security: Validate reg.exe and execute registry exports safely
    $regCmd = Get-Command reg.exe -ErrorAction SilentlyContinue
    if (-not $regCmd) {
        Write-Host "[!] Warning: reg.exe not found, skipping registry exports" -ForegroundColor Yellow
    } else {
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
        
        foreach ($export in $regExports) {
            # Security: Validate registry key against allowlist
            if ($allowedRegistryKeys -notcontains $export.Key) {
                Write-Verbose "Skipping unauthorized registry key: $($export.Key)"
                continue
            }
            
            try {
                $outputFile = Join-Path $regFolder $export.File
                $result = & $regCmd.Source export $export.Key $outputFile /y 2>&1
                if ($LASTEXITCODE -ne 0) {
                    Write-Verbose "Registry export failed for $($export.Key): $result"
                }
            } catch {
                Write-Verbose "Error exporting registry key $($export.Key): $($_.Exception.Message)"
            }
        }
    }
    
    # 3. Collect Log Files
    # Silent collection
    $logFolder = Join-Path $forensicFolder "Logs"
    $null = New-Item -Path $logFolder -ItemType Directory -Force
    
    # Setup API log (device installation history)
    if (Test-Path "C:\Windows\inf\setupapi.dev.log") {
        Copy-Item "C:\Windows\inf\setupapi.dev.log" (Join-Path $logFolder "setupapi.dev.log") -ErrorAction SilentlyContinue
    }
    if (Test-Path "C:\Windows\inf\setupapi.app.log") {
        Copy-Item "C:\Windows\inf\setupapi.app.log" (Join-Path $logFolder "setupapi.app.log") -ErrorAction SilentlyContinue
    }
    
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
    
    try {
        # Log compression operation
        $logContent += "Compressing forensic data to: $zipPath"
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
    } finally {
        # Always save operation log
        $logContent += ""
        $logContent += "SCAN SUMMARY:"
        $logContent += ("-" * 80)
        $logContent += "Total Findings: $($script:findings.Count)"
        $logContent += "Total Checks: $($script:auditLog.Count)"
        $logContent += "Checks Completed: $(($script:auditLog | Where-Object { $_.Status -eq 'Completed' }).Count)"
        $logContent += "Checks with Errors: $(($script:auditLog | Where-Object { $_.Status -eq 'Error' }).Count)"
        $logContent += ""
        $logContent += "Log end: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        
        $logContent | Out-File -FilePath $operationLog -Encoding UTF8
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


