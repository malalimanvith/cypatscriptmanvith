<#
SYNOPSIS
    CyberPatriot Windows Hardening Script

DESCRIPTION
    Automates as many items as possible from the provided CyberPatriot Windows checklist:
    - Firewall, Windows Update, UAC, Network adapters
    - Password policies and Guest account
    - Remote Desktop disable and lockdown
    - AutoRun/AutoPlay, File/Printer sharing
    - Patch management (Windows Update + optional winget)
    - Microsoft Defender configuration & scans
    - Group Policy-alike hardening via registry and auditpol
    - BitLocker (optional, with confirmation)a
    - AppLocker (Audit by default; Enforce optional, Enterprise/Education only)
    - Disable risky/unused services, Remote Assistance, WinRM
    - Advanced firewall rules (examples) and rule review
    - Network monitoring snapshot
    - Forensics helper: locate suspect firewall rule and report remote IPs
    - VNC/IIS/TFTP removal/disable
    - Temp cleanup and evidence collection
    - Local users review and optional disable/delete
    - Event log sizing and auditing enablement
    - Summary report

    IMPORTANT:
    - Run as Administrator.
    - Some changes may require restart.
    - High-impact items (BitLocker, AppLocker Enforce, disabling adapters/users) prompt for confirmation.
    - Review the script and test in a safe environment before use.
    - Use at your own risk; no warranty or liability.
    - DO NOT USE for ANYTHING related to CyberPatriot competition itself without express permission from Manvith Malali.
    - Designed for Windows 10/11; may work on Server versions with modifications.
    - Some features require specific editions (e.g., AppLocker needs Enterprise/Education).
    - Some features may require internet access (e.g., winget, Windows Update).
    - Some features may not be available on all Windows versions.
    - Some features may require additional configuration or prerequisites (e.g., BitLocker needs TPM).
    - Some features may require additional permissions or roles (e.g., AppLocker needs local admin).
#>

# ----------------------------- Safety, prompts, and logging -----------------------------

# Create a transcript log to capture actions and output
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$LogDir = "$env:SystemDrive\CyPatSL"
$ReportDir = Join-Path $LogDir "Reports"
New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null
$TranscriptPath = Join-Path $LogDir "Hardening_$timestamp.log"
Start-Transcript -Path $TranscriptPath -Force | Out-Null
Write-Host "Transcript log started at $TranscriptPath" -ForegroundColor Green
$ErrorActionPreference = "Continue"

# Ensure the script runs as Administrator (elevated)
function Test-IsAdmin {
    # Returns $true if the current PowerShell session is elevated
    $currentUser = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    Write-Host "[!] Please run this script as Administrator. Exiting..." -ForegroundColor Yellow
    Start-Sleep -Seconds 2
    Stop-Transcript | Out-Null
    exit 1
}

# Gate the entire operation behind a compliance menu
Write-Host "CyberPatriot Pre-Run Checklist" -ForegroundColor Cyan
Write-Host "1) Have you completed all forensics questions? Please answer with" -NoNewline
$ans1 = Read-Host "  (Yes/No)"
Write-Host "2) Have you noted down all current passwords and credential-related details? Please answer with" -NoNewline
$ans2 = Read-Host "  (Yes/No)"
Write-Host "3) Have you finished all software updates, Control Panel settings, and Settings uses? Please answer with" -NoNewline
$ans3 = Read-Host "  (Yes/No)"

if (@("yes","y") -notcontains $ans1.Trim().ToLower() -or @("yes","y") -notcontains $ans2.Trim().ToLower() -or @("yes","y") -notcontains $ans3.Trim().ToLower()) {
    Write-Host "`nPlease complete forensics questions, note passwords, and finish updates/settings BEFORE running the script." -ForegroundColor Yellow
    Write-Host "After that, re-run this script as Administrator." -ForegroundColor Yellow
    Start-Sleep -Seconds 5
    Stop-Transcript | Out-Null
    exit 0
}

# ----------------------------- Utility helpers -----------------------------

# Simple try wrapper to continue on error and record details
function Invoke-Safe {
    param(
        [Parameter(Mandatory=$true)][ScriptBlock] $Script,
        [string] $Task = "Task"
    )
    try {
        & $Script
        Write-Host "[OK] $Task" -ForegroundColor Green
    } catch {
        Write-Host "[ERR] $Task : $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Write a line to the summary report
$SummaryPath = Join-Path $ReportDir "Summary_$timestamp.txt"
function Add-Summary {
    param([string] $Line)
    $Line | Out-File -FilePath $SummaryPath -Encoding UTF8 -Append
}

# ----------------------------- System/account discovery -----------------------------

# Gather basic system info for the report
Invoke-Safe -Task "Collect system info" -Script {
    $sys = Get-ComputerInfo
    $sys | Select-Object CsName,OsName,OsVersion,OsHardwareAbstractionLayer,WindowsProductName,WindowsEditionId,OsBuildNumber,OsLanguage |
        Format-List | Out-String | Out-File (Join-Path $ReportDir "SystemInfo_$timestamp.txt")
}

# Check current user admin group membership
Invoke-Safe -Task "Check if current user is in Administrators" -Script {
    $inAdmins = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Add-Summary ("Current user in Administrators: {0}" -f $inAdmins)
}

# ----------------------------- Ensure registry permissions for script execution -----------------------------

Invoke-Safe -Task "Ensure registry permissions for script execution" -Script {
    $currentUser = "$env:COMPUTERNAME\$env:USERNAME"
    $regPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
    )
    foreach ($path in $regPaths) {
        try {
            if (-not (Test-Path $path)) {
                New-Item -Path $path -Force | Out-Null
            }
            $acl = Get-Acl $path
            $rule = New-Object System.Security.AccessControl.RegistryAccessRule($currentUser, "FullControl", "ContainerInherit", "None", "Allow")
            $acl.SetAccessRule($rule)
            Set-Acl -Path $path -AclObject $acl
        } catch {
            Add-Summary ("Failed to set registry permissions for '$path': {0}" -f $_.Exception.Message)
        }
    }
    Add-Summary "Registry permissions for required keys set to FullControl for $currentUser."
}

# ----------------------------- Grant current user full control over Users -----------------------------

Invoke-Safe -Task "Grant current user full control over all folders in C:\Users" -Script {
    $currentUser = "$env:COMPUTERNAME\$env:USERNAME"
    $folders = Get-ChildItem -Path "$env:SystemDrive\Users" -Directory -Force
    foreach ($folder in $folders) {
        icacls $folder.FullName /grant "'$currentUser':(OI)(CI)F" /inheritance:e | Out-Null
    }
    icacls "$env:SystemDrive\Users" /grant "'$currentUser':(OI)(CI)F" /inheritance:e | Out-Null
    Add-Summary "Granted $currentUser full control over all folders in $env:SystemDrive\Users with inheritance enabled."
}


# ----------------------------- Pre-flight: SFC, DISM, Malwarebytes install -----------------------------

$runSFC = Read-Host "Would you like to run SFC (System File Checker)? (Yes/No)"
if (@("yes","y") -contains $runSFC.Trim().ToLower()) {
    Write-Host "Running SFC (System File Checker)..." -ForegroundColor Cyan
    Invoke-Safe -Task "Run SFC /scannow" -Script {
        sfc /scannow | Tee-Object -FilePath (Join-Path $ReportDir "SFC_$timestamp.txt")
    }
} else {
    Add-Summary "SFC scan skipped by user choice."
}

$runDISM = Read-Host "Would you like to run DISM health check? (Yes/No)"
if (@("yes","y") -contains $runDISM.Trim().ToLower()) {
    Write-Host "Running DISM health check..." -ForegroundColor Cyan
    Invoke-Safe -Task "Run DISM /Online /Cleanup-Image /RestoreHealth" -Script {
        DISM /Online /Cleanup-Image /RestoreHealth | Tee-Object -FilePath (Join-Path $ReportDir "DISM_$timestamp.txt")
    }
} else {
    Add-Summary "DISM health check skipped by user choice."
}

Write-Host "Installing Malwarebytes (if not present)..." -ForegroundColor Cyan
Invoke-Safe -Task "Install Malwarebytes" -Script {
    $mbamExe = "$env:TEMP\mbsetup.exe"
    $url = "https://downloads.malwarebytes.com/file/mb-windows?_gl=1*6oqowb*_gcl_au*MTAzODEzNzY2MC4xNzU2NDgxODI2*_ga*MzQ2MzMxMDYxLjE3NTY0ODE4MjY.*_ga_K8KCHE3KSC*czE3NTY0ODE4MjUkbzEkZzEkdDE3NTY0ODE4MjckajU4JGwwJGgw"
    Invoke-WebRequest -Uri $url -OutFile $mbamExe -UseBasicParsing
    Start-Process -FilePath $mbamExe -ArgumentList "/silent" -Wait
    Add-Summary "Malwarebytes installation attempted; check if installed."
}

# ----------------------------- Auditing: Set all categories, key subcategories, and PowerShell logging -----------------------------

Invoke-Safe -Task "Configure auditing: all categories, key subcategories, and PowerShell logging" -Script {
    # Set all audit categories to Success and Failure
    $categories = auditpol /get /category:* | Select-String "Category" | ForEach-Object {
        ($_ -split ":")[1].Trim()
    }
    foreach ($cat in $categories) {
        auditpol /set /category:"$cat" /success:enable /failure:enable | Out-Null
    }

    # Set key subcategories for detailed auditing
    $subcats = @(
        "Credential Validation",
        "Logon",
        "Computer Account Management",
        "Process Creation"
    )
    foreach ($subcat in $subcats) {
        auditpol /set /subcategory:"$subcat" /success:enable /failure:enable | Out-Null
    }

    # Enable PowerShell script block and module logging
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -PropertyType DWord -Value 1 -Force | Out-Null
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -PropertyType DWord -Value 1 -Force | Out-Null
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Name "*" -PropertyType String -Value "*" -Force | Out-Null

    Add-Summary "Auditing configured: all categories Success/Failure, key subcategories, PowerShell logging enabled."
}

# ----------------------------- Firewall configuration -----------------------------

Invoke-Safe -Task "Enable Windows Firewall on all profiles" -Script {
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
}

# ----------------------------- Security and Service Hardening Section -----------------------------

Invoke-Safe -Task "Security and Service Hardening" -Script {
    # Disable 'Turn off real time protection' (enable real-time protection)
    Set-MpPreference -DisableRealtimeMonitoring $false

    # Enable DEP systemwide
    bcdedit /set {current} nx AlwaysOn | Out-Null

    # Disable 'Let Everyone permissions be applied to anonymous users'
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "EveryoneIncludesAnonymous" -PropertyType DWord -Value 0 -Force | Out-Null

    # Enable and set DHCP, Windows Update, and Windows Event Log services to automatic
    $services = @("Dhcp", "wuauserv", "EventLog")
    foreach ($svc in $services) {
        try {
            Set-Service -Name $svc -StartupType Automatic
            Start-Service -Name $svc
            Add-Summary ("Service '$svc' set to Automatic and started.")
        } catch {
            Add-Summary ("Failed to configure service '$svc': {0}" -f $_.Exception.Message)
        }
    }

    # Disable 'Enable insecure guest logons'
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "AllowInsecureGuestAuth" -PropertyType DWord -Value 0 -Force | Out-Null

    # Make sure no user has passwords set to never expire
    Get-LocalUser | Where-Object { $_.PasswordNeverExpires } | ForEach-Object {
        Set-LocalUser -Name $_.Name -PasswordNeverExpires $false
        Add-Summary ("Password expiration enforced for user '$($_.Name)'.")
    }

    # Make sure no user can act as part of the OS or log on as a service using secedit
    $infPath = "$env:TEMP\secedit_harden.inf"
    $logPath = "$env:TEMP\secedit_harden.log"
    @"
[Unicode]
Unicode=yes
[System Access]
[Event Audit]
[Privilege Rights]
SeServiceLogonRight =
SeTcbPrivilege =
"@ | Set-Content $infPath -Encoding Unicode
    secedit /configure /db "$env:TEMP\secedit_harden.sdb" /cfg $infPath /log $logPath /quiet
    Add-Summary "Removed 'Act as part of the OS' and 'Log on as a service' rights from all users using secedit."

    # Remove all Everyone and Guest permissions from system drive and Users folder
    $paths = @("$env:SystemDrive\", "$env:SystemDrive\Users")
    foreach ($path in $paths) {
        icacls $path /remove:g Everyone /remove:g Guest /T /C | Out-Null
        Add-Summary ("Removed Everyone and Guest permissions from '$path'.")
    }
}

# ----------------------------- Windows Update (scan + start install) -----------------------------

Invoke-Safe -Task "Trigger Windows Update scan and start install (best-effort)" -Script {
    # Try modern UsoClient where available
    $usopath = "$env:SystemRoot\System32\UsoClient.exe"
    if (Test-Path $usopath) {
        & $usopath StartScan | Out-Null
        Start-Sleep -Seconds 5
        & $usopath StartDownload | Out-Null
        Start-Sleep -Seconds 5
        & $usopath StartInstall | Out-Null
    } else {
        # Fallback older wuauclt (often a no-op on Win10/11 but harmless)
        & "$env:SystemRoot\System32\wuauclt.exe" /detectnow | Out-Null
        & "$env:SystemRoot\System32\wuauclt.exe" /updatenow | Out-Null
    }
    Add-Summary "Windows Update triggered (scan/download/install). Some updates may require reboot."
}

# Optional: use winget to upgrade third-party apps
Invoke-Safe -Task "Optional: winget upgrade --all (if available)" -Script {
    $winget = (Get-Command winget -ErrorAction SilentlyContinue)
    if ($winget) {
        winget upgrade --all --silent --accept-package-agreements --accept-source-agreements | Tee-Object -FilePath (Join-Path $ReportDir "WingetUpgrade_$timestamp.txt")
        Add-Summary "winget upgrade attempted; see WingetUpgrade log."
    } else {
        Add-Summary "winget not found; skipping third-party upgrades."
    }
}

# ----------------------------- Install and launch Everything (voidtools) -----------------------------
Invoke-Safe -Task "Install and launch Everything (voidtools)" -Script {
    # Common install locations to check for Everything executable
    $everythingPaths = @(
        "$env:ProgramFiles\Everything\Everything.exe",
        "$env:ProgramFiles(x86)\Everything\Everything.exe",
        "$env:ProgramFiles\voidtools\Everything.exe",
        "$env:ProgramFiles(x86)\voidtools\Everything.exe"
    )

    $exe = $everythingPaths | Where-Object { Test-Path $_ } | Select-Object -First 1

    if (-not $exe) {
        Write-Host "Everything not found. Attempting to download and install silently from voidtools..." -ForegroundColor Cyan
        try {
            # Ensure modern TLS for the web request
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

            $downloadsPage = 'https://www.voidtools.com/downloads/'
            $resp = Invoke-WebRequest -Uri $downloadsPage -UseBasicParsing -ErrorAction Stop

            $arch = if ([Environment]::Is64BitOperatingSystem) { 'x64' } else { 'x86' }

            # Try to find an installer link that contains the architecture, fallback to any Setup.exe
            $link = $null
            if ($resp.Links) {
                $link = $resp.Links | Where-Object { $_.href -match 'Everything.*Setup\.exe' -and $_.href -match $arch } | Select-Object -First 1
                if (-not $link) { $link = $resp.Links | Where-Object { $_.href -match 'Everything.*Setup\.exe' } | Select-Object -First 1 }
            } else {
                # Older PowerShell versions may not populate Links; fall back to regex on RawContent
                $html = $resp.RawContent
                $pattern = @'
href=(?:"|')(?<u>[^"']*Everything[^"']*Setup\.exe)(?:"|')
'@
                $m = [regex]::Match($html, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                if ($m.Success) { $url = $m.Groups['u'].Value }
            }

            if ($link -or $url) {
                if ($link) { $url = $link.href }
                if ($url -notmatch '^https?://') { $url = (New-Object System.Uri((New-Object System.Uri($downloadsPage)), $url)).AbsoluteUri }

                $setupPath = Join-Path $env:TEMP 'Everything-Setup.exe'
                Invoke-WebRequest -Uri $url -OutFile $setupPath -UseBasicParsing -ErrorAction Stop

                # Run the installer silently. voidtools setup uses NSIS; /S is the silent switch.
                Start-Process -FilePath $setupPath -ArgumentList '/S' -Wait -NoNewWindow
                Add-Summary ("Downloaded and ran Everything installer from {0}" -f $url)
            } else {
                Add-Summary "Could not locate Everything installer link on voidtools downloads page."
                Start-Process $downloadsPage
                Add-Summary "Opened voidtools downloads page for manual install."
            }
        } catch {
            Add-Summary ("Failed to download/install Everything automatically: {0}" -f $_.Exception.Message)
            Start-Process "https://www.voidtools.com/downloads/"
            Add-Summary "Opened voidtools downloads page for manual install due to failure."
        }

        # Re-check for installed executable after attempted install
        $exe = $everythingPaths | Where-Object { Test-Path $_ } | Select-Object -First 1
    }

    if ($exe) {
        try {
            Start-Process -FilePath $exe
            Add-Summary ("Everything started from '{0}'." -f $exe)
        } catch {
            Add-Summary ("Failed to start Everything: {0}" -f $_.Exception.Message)
        }
    } else {
        Add-Summary "Everything not installed; user intervention required to install it from voidtools."
    }
}

# ----------------------------- Install Sysinternals Suite to Desktop -----------------------------
Invoke-Safe -Task "Install Sysinternals Suite to Desktop" -Script {
    try {
        # Ensure modern TLS for the web request
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        $desktopPath = [Environment]::GetFolderPath('Desktop')
        $sysinternalsPath = Join-Path $desktopPath 'SysinternalsSuite'

        # Create Sysinternals folder on desktop if it doesn't exist
        if (-not (Test-Path $sysinternalsPath)) {
            New-Item -ItemType Directory -Path $sysinternalsPath -Force | Out-Null
            Add-Summary "Created Sysinternals Suite folder on desktop: $sysinternalsPath"
        }

        # Download the Sysinternals Suite zip file
        $zipUrl = 'https://download.sysinternals.com/files/SysinternalsSuite.zip'
        $zipPath = Join-Path $env:TEMP 'SysinternalsSuite.zip'

        Write-Host "Downloading Sysinternals Suite from $zipUrl..." -ForegroundColor Cyan
        Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath -UseBasicParsing -ErrorAction Stop
        Add-Summary "Downloaded Sysinternals Suite to $zipPath"

        # Extract the zip file to the desktop folder
        Write-Host "Extracting Sysinternals Suite to $sysinternalsPath..." -ForegroundColor Cyan
        Expand-Archive -Path $zipPath -DestinationPath $sysinternalsPath -Force
        Add-Summary "Extracted Sysinternals Suite to $sysinternalsPath"

        # Clean up the zip file
        Remove-Item -Path $zipPath -Force -ErrorAction SilentlyContinue

        # Verify installation
        $exeCount = (Get-ChildItem -Path $sysinternalsPath -Filter '*.exe' -ErrorAction SilentlyContinue).Count
        if ($exeCount -gt 0) {
            Write-Host "Sysinternals Suite installed successfully with $exeCount executable(s)." -ForegroundColor Green
            Add-Summary "Sysinternals Suite installed successfully to desktop with $exeCount tools."
        } else {
            Add-Summary "Sysinternals Suite extraction completed but no executables found."
        }
    } catch {
        Add-Summary ("Failed to install Sysinternals Suite: {0}" -f $_.Exception.Message)
        Write-Host "Failed to install Sysinternals Suite. You can download manually from https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite" -ForegroundColor Yellow
    }
}

# ----------------------------- Checklist compliance (GUI checks, policies, users, forensic Qs) -----------------------------
Invoke-Safe -Task "Checklist compliance: ReadMe, forensic Qs, policies, accounts, firewall, updates, apps" -Script {
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

    # 1) Read the ReadMe (Will have Important Information)
    $readmePaths = @(
        Join-Path $scriptDir 'README.md',
        Join-Path $scriptDir 'ReadMe.md',
        Join-Path $scriptDir 'README.txt'
    )
    $foundReadme = $readmePaths | Where-Object { Test-Path $_ } | Select-Object -First 1
    if ($foundReadme) {
        Start-Process -FilePath $foundReadme
        Add-Summary "Opened README at $foundReadme"
    } else {
        Add-Summary "No README found in script directory ($scriptDir)."
    }

    # 2) Answer Forensic Questions (try do it first)
    $forensicAnswers = @{}
    $questions = @(
        'Have you completed all forensics questions? (Yes/No)',
        'Have you noted down all current passwords and credential-related details? (Yes/No)',
        'Any suspicious recent activity to record? (briefly describe or type "None")'
    )
    foreach ($q in $questions) {
        $ans = Read-Host $q
        $forensicAnswers[$q] = $ans
        Add-Summary ("Forensic Q: {0} => {1}" -f $q, $ans)
    }

    # 3) USE GOOGLE (if needed)
    $useGoogle = Read-Host "Open Google in browser for research? (Yes/No)"
    if (@('yes','y') -contains $useGoogle.Trim().ToLower()) { Start-Process 'https://www.google.com'; Add-Summary 'Opened Google for user.' }

    # 4) Check for Valid Users + Control Panel user accounts
    Add-Summary 'Listing local users and properties...'
    $localUsers = Get-LocalUser | Select-Object Name, Enabled, PasswordNeverExpires, LastLogon
    $localUsers | Out-File (Join-Path $ReportDir "LocalUsers_$timestamp.txt") -Encoding UTF8
    foreach ($u in $localUsers) { Add-Summary ("User: {0}, Enabled: {1}, PasswordNeverExpires: {2}, LastLogon: {3}" -f $u.Name, $u.Enabled, $u.PasswordNeverExpires, $u.LastLogon) }

    # Open Control Panel -> User Accounts for manual review
    try { Start-Process 'control.exe' -ArgumentList '/name Microsoft.UserAccounts' -ErrorAction SilentlyContinue; Add-Summary 'Opened Control Panel User Accounts.' } catch { Add-Summary 'Failed to open Control Panel User Accounts.' }

    # 5) Open Group Policy Editor (gpedit.msc) and guide user to Account Policies
    try {
        Start-Process 'gpedit.msc' -ErrorAction SilentlyContinue
        Add-Summary 'Attempted to open gpedit.msc (may not be present on Home editions).'
    } catch {
        Add-Summary 'gpedit.msc open failed (likely not present on this edition).'
    }

    # 6) Account lockout & password policy (apply required values)
    try {
        # Account Lockout Policy
        net accounts /lockoutthreshold:5 | Out-Null
        net accounts /lockoutduration:30 | Out-Null
        net accounts /lockoutwindow:30 | Out-Null

        # Password policy
        net accounts /minpwlen:10 /maxpwage:30 /minpwage:10 /uniquepw:24 | Out-Null

        # Enforce password complexity via registry
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "PasswordComplexity" -PropertyType DWord -Value 1 -Force | Out-Null
        # Store passwords using reversible encryption -> Disabled
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "ClearTextPassword" -PropertyType DWord -Value 0 -Force | Out-Null

        Add-Summary 'Applied account lockout and password policy settings: LockoutThreshold=5, Duration=30, Window=30, MinLen=10, MaxAge=30, MinAge=10, History=24, Complexity=Enabled.'
    } catch {
        Add-Summary ("Failed to apply account/password policy: {0}" -f $_.Exception.Message)
    }

    # 7) Audit Policy: set everything to success and failure
    try {
        $cats = auditpol /get /category:* | Select-String 'Category' | ForEach-Object { ($_ -split ':')[1].Trim() }
        foreach ($c in $cats) { auditpol /set /category:"$c" /success:enable /failure:enable | Out-Null }
        Add-Summary 'Audit policy: set all categories to Success and Failure.'
    } catch {
        Add-Summary ("Failed to set audit policy for all categories: {0}" -f $_.Exception.Message)
    }

    # 8) User Rights Assignment: export and ask about odd entries (manual removal option)
    try {
        $seceditCfg = Join-Path $env:TEMP "secedit_export_$timestamp.inf"
        secedit /export /cfg $seceditCfg | Out-Null
        $privLines = Select-String -Path $seceditCfg -Pattern '^[A-Za-z].*=.*' | ForEach-Object { $_.Line } | Where-Object { $_ -match '=' }
        Add-Summary "Exported user rights (secedit) to $seceditCfg"
        # Show a short sample to user
        Write-Host "User Rights Assignment (sample lines) saved to $seceditCfg" -ForegroundColor Cyan
        $show = Read-Host "Would you like to view the exported rights file now? (Yes/No)"
        if (@('yes','y') -contains $show.Trim().ToLower()) { notepad $seceditCfg }

        $resp = Read-Host 'Would you like to remove all accounts from any specific right? Type the exact right name (e.g., SeDenyInteractiveLogonRight) or press Enter to skip'
        if ($resp.Trim() -ne '') {
            $rightName = $resp.Trim()
            $inf = @"
[Unicode]
Unicode=yes
[Privilege Rights]
$rightName =
"@
            $tmpInf = Join-Path $env:TEMP "remove_right_$timestamp.inf"
            $inf | Set-Content -Path $tmpInf -Encoding Unicode
            secedit /configure /db $env:TEMP\secedit.sdb /cfg $tmpInf /areas USER_RIGHTS | Out-Null
            Add-Summary ("Attempted to clear privilege right: {0}" -f $rightName)
        }
    } catch {
        Add-Summary ("Failed to export/analyze user rights: {0}" -f $_.Exception.Message)
    }

    # 9) Security options: ensure Guest disabled and interactive logon settings
    try {
        Disable-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
        New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'DontDisplayLastUserName' -PropertyType DWord -Value 1 -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LimitBlankPasswordUse' -PropertyType DWord -Value 1 -Force | Out-Null
        Add-Summary 'Security options set: Guest disabled, DontDisplayLastUserName=1, LimitBlankPasswordUse=1.'
    } catch {
        Add-Summary ("Failed to adjust security options: {0}" -f $_.Exception.Message)
    }

    # 10) Firewalls: Domain off, Private on, Public on
    try {
        Set-NetFirewallProfile -Profile Domain -Enabled False -ErrorAction SilentlyContinue
        Set-NetFirewallProfile -Profile Private -Enabled True -ErrorAction SilentlyContinue
        Set-NetFirewallProfile -Profile Public -Enabled True -ErrorAction SilentlyContinue
        Add-Summary 'Firewall profiles set: Domain=Off, Private=On, Public=On.'
    } catch {
        Add-Summary ("Failed to set firewall profiles: {0}" -f $_.Exception.Message)
    }

    # 11) Turn off Autoplay (already applied earlier, but ensure for the current user)
    try {
        New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' -PropertyType DWord -Value 255 -Force | Out-Null
        New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoAutoPlay' -PropertyType DWord -Value 1 -Force | Out-Null
        Add-Summary 'Autoplay disabled for current user via registry.'
    } catch {
        Add-Summary ("Failed to disable Autoplay for current user: {0}" -f $_.Exception.Message)
    }

    # 12) Turn off Developer Mode
    try {
        if (!(Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock')) { New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock' -Force | Out-Null }
        New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock' -Name 'AllowDevelopmentWithoutDevLicense' -PropertyType DWord -Value 0 -Force | Out-Null
        Add-Summary 'Developer Mode disabled (registry setting updated).'
    } catch {
        Add-Summary ("Failed to disable Developer Mode: {0}" -f $_.Exception.Message)
    }

    # 13) Delete odd applications/files: prompt for removing CCleaner, AngryIP, Discord (if present)
    $targets = @('CCleaner','Angry IP Scanner','Discord')
    foreach ($t in $targets) {
        try {
            $found = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "*$t*" }
            if ($found) {
                foreach ($f in $found) {
                    Write-Host "Found $($f.DisplayName). Uninstall? (Yes/No)" -ForegroundColor Cyan
                    $r = Read-Host "Uninstall $($f.DisplayName)?"
                    if (@('yes','y') -contains $r.Trim().ToLower()) {
                        if ($f.UninstallString) {
                            # Try to run uninstall string silently if it contains typical MSI or NSIS switches
                            $u = $f.UninstallString
                            if ($u -match 'msiexec') {
                                Start-Process -FilePath 'msiexec.exe' -ArgumentList '/x',$u -Wait -NoNewWindow -ErrorAction SilentlyContinue
                            } else {
                                Start-Process -FilePath 'cmd.exe' -ArgumentList '/c',"$u" -Wait -NoNewWindow -ErrorAction SilentlyContinue
                            }
                            Add-Summary ("Attempted uninstall of $($f.DisplayName) using uninstall string.")
                        } else {
                            Add-Summary ("No uninstall string found for $($f.DisplayName); manual removal needed.")
                        }
                        # Also try to remove desktop shortcuts
                        $publicDesktop = Join-Path $env:PUBLIC 'Desktop'
                        Get-ChildItem -Path $publicDesktop -Filter "*$t*.*" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
                        Get-ChildItem -Path ([Environment]::GetFolderPath('Desktop')) -Filter "*$t*.*" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
                    }
                }
            }
        } catch {
            Add-Summary ("Failed checking/uninstalling ${t}: {0}" -f $_.Exception.Message)
        }
    }

    # 14) Windows Update: Check for Updates
    try {
        $usopath = "$env:SystemRoot\System32\UsoClient.exe"
        if (Test-Path $usopath) { & $usopath StartScan | Out-Null; Add-Summary 'Triggered Windows Update scan via UsoClient.' } else { & "$env:SystemRoot\System32\wuauclt.exe" /detectnow | Out-Null; Add-Summary 'Triggered Windows Update via wuauclt.' }
    } catch {
        Add-Summary ("Failed to trigger Windows Update: {0}" -f $_.Exception.Message)
    }

    # 15) Sharing drives: unshare non-admin shares that expose Local Disk paths (C:\)
    try {
    $netShares = net share | Select-String '^([^\s]+)\s+([^\s].*)' | ForEach-Object { $_.Line }
        # Use Get-SmbShare when available for more structured output
        if (Get-Command Get-SmbShare -ErrorAction SilentlyContinue) {
            Get-SmbShare | Where-Object { $_.Path -and ($_.Name -notlike '*$') -and ($_.Path -match '^[A-Za-z]:\\') } | ForEach-Object {
                if ($_.Path -match '^[A-Za-z]:\\') {
                    # If the share path is a root of a local disk, prompt then remove
                    if ($_.Path -match '^.:\\$') { return }
                    Write-Host "Share: $($_.Name) -> $($_.Path). Remove? (Yes/No)" -ForegroundColor Cyan
                    $r = Read-Host "Remove share $($_.Name)?"
                    if (@('yes','y') -contains $r.Trim().ToLower()) { Remove-SmbShare -Name $_.Name -Force; Add-Summary ("Removed share: {0} -> {1}" -f $_.Name, $_.Path) }
                }
            }
        } else {
            # Fallback parsing of net share output (very basic)
            $shares = net share | Select-String '^(\S+)\s+' | ForEach-Object { ($_ -split '\s+')[0] } | Where-Object { $_ -and $_ -ne 'Share' -and $_ -ne 'The' }
            foreach ($s in $shares) {
                $info = net share $s 2>$null
                if ($info -match 'Path\s+\:\s+([A-Za-z]:\\.*)') {
                    $path = $matches[1]
                    if ($s -notlike '*$' -and $path -match '^[A-Za-z]:\\') {
                        Write-Host "Share $s -> $path. Remove? (Yes/No)" -ForegroundColor Cyan
                        $r = Read-Host "Remove share $s?"
                        if (@('yes','y') -contains $r.Trim().ToLower()) { net share $s /delete | Out-Null; Add-Summary ("Removed share: {0} -> {1}" -f $s, $path) }
                    }
                }
            }
        }
    } catch {
        Add-Summary ("Failed to enumerate/remove shares: {0}" -f $_.Exception.Message)
    }

    # 16) Windows Defender Security Center checks: ensure services and policies are on
    try {
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
        Update-MpSignature -ErrorAction SilentlyContinue
        Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -ErrorAction SilentlyContinue
        Add-Summary 'Enabled Defender real-time protection and ensured firewall profiles are enabled (best-effort).'
    } catch {
        Add-Summary ("Failed to ensure Defender/Firewall settings: {0}" -f $_.Exception.Message)
    }

    # 17) Creating groups (open lusrmgr.msc)
    try { Start-Process 'lusrmgr.msc' -ErrorAction SilentlyContinue; Add-Summary 'Opened lusrmgr.msc for group creation (if available).' } catch { Add-Summary 'lusrmgr.msc open failed (may not be available on Home edition).' }

    # 17b) Open Task Manager and Network Diagnostics (netstat -ab)
    try {
        # Open Task Manager for process monitoring
        Start-Process 'taskmgr.exe'
        Add-Summary 'Opened Task Manager for process and network connection monitoring.'
    } catch {
        Add-Summary ("Failed to open Task Manager: {0}" -f $_.Exception.Message)
    }

    try {
        # Open Command Prompt with netstat -ab to show all connections with associated processes
        Start-Process 'cmd.exe' -ArgumentList '/k netstat -ab'
        Add-Summary 'Opened Command Prompt with netstat -ab to display all network connections and associated processes.'
    } catch {
        Add-Summary ("Failed to open Command Prompt with netstat: {0}" -f $_.Exception.Message)
    }

    # 18) Microsoft FTP Service: disable
    try {
        $svc = Get-Service -Name 'FTPSVC' -ErrorAction SilentlyContinue
        if ($svc) { Set-Service -Name $svc.Name -StartupType Disabled; Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue; Add-Summary 'Microsoft FTP Service disabled.' }
    } catch {
        Add-Summary ("Failed to disable Microsoft FTP Service: {0}" -f $_.Exception.Message)
    }

    # 18b) World Wide Web Publishing Service: disable
    try {
        $w3svc = Get-Service -Name 'W3SVC' -ErrorAction SilentlyContinue
        if ($w3svc) {
            Set-Service -Name $w3svc.Name -StartupType Disabled -ErrorAction Stop
            Stop-Service -Name $w3svc.Name -Force -ErrorAction SilentlyContinue
            Add-Summary 'World Wide Web Publishing Service (W3SVC) disabled and stopped.'
        } else {
            Add-Summary 'World Wide Web Publishing Service (W3SVC) not found on this system.'
        }
    } catch {
        Add-Summary ("Failed to disable World Wide Web Publishing Service: {0}" -f $_.Exception.Message)
    }

    # 19) Remote Desktop: ensure disabled
    try {
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -PropertyType DWord -Value 1 -Force | Out-Null
        Get-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue | Disable-NetFirewallRule -ErrorAction SilentlyContinue
        Set-Service -Name 'TermService' -StartupType Disabled -ErrorAction SilentlyContinue
        Add-Summary 'Remote Desktop set to disabled via registry, firewall rules disabled, service set to Disabled.'
    } catch {
        Add-Summary ("Failed to disable Remote Desktop: {0}" -f $_.Exception.Message)
    }

    # 20) Remote Assistance: disable
    try {
        New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name 'fAllowToGetHelp' -PropertyType DWord -Value 0 -Force | Out-Null
        Add-Summary 'Remote Assistance disabled.'
    } catch {
        Add-Summary ("Failed to disable Remote Assistance: {0}" -f $_.Exception.Message)
    }

    # 21) Firefox: if present, open Privacy & Security section for user to set 'Block dangerous downloads'
    try {
        $firefoxPath = "$env:ProgramFiles\Mozilla Firefox\firefox.exe"
        if (Test-Path $firefoxPath) { Start-Process -FilePath $firefoxPath -ArgumentList 'about:preferences#privacy'; Add-Summary 'Opened Firefox privacy settings for manual toggle.' }
    } catch {
        Add-Summary 'Failed to open Firefox privacy settings.'
    }

    # 22) DOWNLOAD: scan for PNGs/MP3s/etc under Users and write to report
    try {
        $exts = '*.png','*.jpg','*.jpeg','*.mp3','*.wav','*.flac','*.pdf'
        $match = @()
        foreach ($e in $exts) { $match += Get-ChildItem -Path "$env:SystemDrive\Users" -Recurse -Include $e -ErrorAction SilentlyContinue }
        $outFile = Join-Path $ReportDir "UserFilesScan_$timestamp.txt"
        $match | Select-Object FullName,Length,LastWriteTime | Out-File -FilePath $outFile -Encoding UTF8
        Add-Summary ("Scanned Users folder for common media/docs; results written to $outFile (count: {0})." -f $match.Count)
    } catch {
        Add-Summary ("Failed to scan Users folder for media files: {0}" -f $_.Exception.Message)
    }

    # 23) Ensure Malwarebytes is installed (use winget if available, otherwise open downloads)
    try {
        $mb = Get-Command winget -ErrorAction SilentlyContinue
        if ($mb) {
            winget install --id Malwarebytes.Malwarebytes -e --silent --accept-package-agreements --accept-source-agreements | Out-Null
            Add-Summary 'Attempted to install Malwarebytes via winget.'
        } else {
            Start-Process 'https://www.malwarebytes.com/mwb-download/thank-you/'
            Add-Summary 'Opened Malwarebytes download page for manual install.'
        }
    } catch {
        Add-Summary ("Failed Malwarebytes install attempt: {0}" -f $_.Exception.Message)
    }

    # 24) Using Local Security Policy / Registry: ensure 'Interactive logon: Don't display last user name' set (again)
    try {
        New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'DontDisplayLastUserName' -PropertyType DWord -Value 1 -Force | Out-Null
        Add-Summary "Ensured registry key DontDisplayLastUserName = 1"
    } catch {
        Add-Summary ("Failed to set DontDisplayLastUserName in registry: {0}" -f $_.Exception.Message)
    }

    Add-Summary 'Checklist compliance block completed.'
}

# ----------------------------- Update web browsers, PuTTY, GIMP, Thunderbird, FileZilla -----------------------------

Invoke-Safe -Task "Update web browsers, PuTTY, GIMP, Thunderbird, FileZilla (if installed)" -Script {
    $apps = @("Google Chrome", "Mozilla Firefox", "Microsoft Edge", "Opera", "PuTTY", "GIMP", "Thunderbird", "FileZilla")
    foreach ($app in $apps) {
        $pkg = winget list | Where-Object { $_ -match $app }
        if ($pkg) {
            try {
                winget upgrade --id $app --silent --accept-package-agreements --accept-source-agreements | Out-Null
                Add-Summary "$app updated via winget."
            } catch {
                Add-Summary "Failed to update '$app': $($_.Exception.Message)"
            }
        }
    }
    # Set minimum TLS to 1.3 in FileZilla config if present
    $fzConfigPaths = @(
        "$env:APPDATA\FileZilla\filezilla.xml",
        "$env:ProgramFiles\FileZilla FTP Client\filezilla.xml",
        "$env:ProgramFiles(x86)\FileZilla FTP Client\filezilla.xml"
    )
    foreach ($configPath in $fzConfigPaths) {
        if (Test-Path $configPath) {
            try {
                [xml]$fzConfig = Get-Content $configPath
                $tlsNode = $fzConfig.Settings.Setting | Where-Object { $_.name -eq "MinimumTLSVersion" }
                if ($tlsNode) {
                    $tlsNode.'#text' = "1.3"
                } else {
                    $newNode = $fzConfig.CreateElement("Setting")
                    $newNode.SetAttribute("name", "MinimumTLSVersion")
                    $newNode.InnerText = "1.3"
                    $fzConfig.Settings.AppendChild($newNode) | Out-Null
                }
                $fzConfig.Save($configPath)
                Add-Summary "FileZilla config at '$configPath' set to minimum TLS 1.3."
            } catch {
                Add-Summary "Failed to set minimum TLS for FileZilla at '$configPath': $($_.Exception.Message)"
            }
        }
    }
}

# ----------------------------- Set all browsers to auto-update if present -----------------------------

Invoke-Safe -Task "Set all browsers to auto-update (if installed)" -Script {
    # Google Chrome
    $chromePath = "$env:ProgramFiles\Google\Chrome\Application\chrome.exe"
    if (Test-Path $chromePath) {
        $chromeUpdatePath = "HKLM:\SOFTWARE\Policies\Google\Update"
        if (!(Test-Path $chromeUpdatePath)) { New-Item -Path $chromeUpdatePath -Force | Out-Null }
        New-ItemProperty -Path $chromeUpdatePath -Name "AutoUpdateCheckPeriodMinutes" -PropertyType DWord -Value 240 -Force | Out-Null
        New-ItemProperty -Path $chromeUpdatePath -Name "UpdateDefault" -PropertyType DWord -Value 1 -Force | Out-Null
        Add-Summary "Google Chrome set to auto-update."
    }

    # Microsoft Edge
    $edgePath = "$env:ProgramFiles (x86)\Microsoft\Edge\Application\msedge.exe"
    if (Test-Path $edgePath) {
        $edgeUpdatePath = "HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate"
        if (!(Test-Path $edgeUpdatePath)) { New-Item -Path $edgeUpdatePath -Force | Out-Null }
        New-ItemProperty -Path $edgeUpdatePath -Name "AutoUpdateCheckPeriodMinutes" -PropertyType DWord -Value 240 -Force | Out-Null
        New-ItemProperty -Path $edgeUpdatePath -Name "UpdateDefault" -PropertyType DWord -Value 1 -Force | Out-Null
        Add-Summary "Microsoft Edge set to auto-update."
    }

    # Mozilla Firefox
    $firefoxPath = "$env:ProgramFiles\Mozilla Firefox\firefox.exe"
    if (Test-Path $firefoxPath) {
        $firefoxUpdatePath = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox"
        if (!(Test-Path $firefoxUpdatePath)) { New-Item -Path $firefoxUpdatePath -Force | Out-Null }
        New-ItemProperty -Path $firefoxUpdatePath -Name "BackgroundAppUpdate" -PropertyType DWord -Value 1 -Force | Out-Null
        Add-Summary "Mozilla Firefox set to auto-update in background."
    }

    # Opera
    $operaPath = "$env:ProgramFiles\Opera\launcher.exe"
    if (Test-Path $operaPath) {
        $operaUpdatePath = "HKLM:\SOFTWARE\Policies\Opera Software"
        if (!(Test-Path $operaUpdatePath)) { New-Item -Path $operaUpdatePath -Force | Out-Null }
        New-ItemProperty -Path $operaUpdatePath -Name "AutoUpdate" -PropertyType DWord -Value 1 -Force | Out-Null
        Add-Summary "Opera set to auto-update."
    }
}

# ----------------------------- UAC configuration -----------------------------

Invoke-Safe -Task "Set UAC to enabled with prompt on secure desktop" -Script {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2 -PropertyType DWord -Force | Out-Null  # Prompt for consent
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 1 -PropertyType DWord -Force | Out-Null
    Add-Summary "UAC enabled. ConsentPromptBehaviorAdmin=2, PromptOnSecureDesktop=1"
}

# ----------------------------- Network configuration (adapters) -----------------------------

Invoke-Safe -Task "Disable unused (disconnected) physical network adapters" -Script {
    Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Disconnected' } |
        ForEach-Object { Disable-NetAdapter -Name $_.Name -Confirm:$false }
    Add-Summary "Disconnected physical adapters disabled (if any)."
}

# ----------------------------- Password policies -----------------------------

Invoke-Safe -Task "Set local password policies (length/age/history)" -Script {
    # min length 10, max age 30 days, min age 5 days, unique 5
    net accounts /minpwlen:10 /maxpwage:30 /minpwage:5 /uniquepw:5 | Out-Null
    Add-Summary "Password policy set: minlen=10, maxage=30, minage=5, history=5"
}

Invoke-Safe -Task "Enable password complexity requirement" -Script {
    # Complexity policy (Local Security Policy equivalent)
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "RequireStrongKey" -Value 1 -PropertyType DWord -Force | Out-Null
    # Primary switch for 'Password must meet complexity requirements'
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "PasswordComplexity" -Value 1 -PropertyType DWord -Force | Out-Null
    #
}
Invoke-Safe -Task "Change all local user passwords to Cyb3rP@tr!0T!!" -Script {
    $newPassword = "Cyb3rP@tr!0T!!"
    $users = Get-LocalUser | Where-Object { $_.Enabled -eq $true -and $_.Name -ne "Administrator" -and $_.Name -ne "Guest" }
    foreach ($user in $users) {
        try {
            Set-LocalUser -Name $user.Name -Password (ConvertTo-SecureString $newPassword -AsPlainText -Force)
            Add-Summary ("Password for user '{0}' changed." -f $user.Name)
        } catch {
            Add-Summary ("Failed to change password for user '{0}': {1}" -f $user.Name, $_.Exception.Message)
        }
    }
}

# ----------------------------- Account lockout & authentication hardening -----------------------------

Invoke-Safe -Task "Account lockout & auth hardening" -Script {
net accounts /lockoutthreshold:10    # Lock out accounts after 10 failed logon attempts
net accounts /lockoutduration:30    # Keep locked accounts locked for 30 minutes
net accounts /lockoutwindow:30      # Reset the failed-attempt counter after 30 minutes

New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -PropertyType DWord -Value 1 -Force | Out-Null  # Disallow network logons with blank passwords
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -PropertyType DWord -Value 5 -Force | Out-Null  # Use NTLMv2 only and refuse LM/NTLM
}

# ----------------------------- UAC: Admin Approval Mode for built-in Administrator -----------------------------

Invoke-Safe -Task "UAC Admin Approval Mode" -Script {
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "FilterAdministratorToken" -PropertyType DWord -Value 1 -Force | Out-Null  # Enable Admin Approval Mode for built-in Admin
}

# ----------------------------- Remote Desktop / Remote Assistance lockdown -----------------------------

Invoke-Safe -Task "Remote Desktop + Remote Assistance lockdown" -Script {
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -PropertyType DWord -Value 1 -Force | Out-Null  # Disable incoming RDP connections
Get-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue | Disable-NetFirewallRule | Out-Null  # Disable all RDP firewall rules if present
Get-Service -Name "TermService" -ErrorAction SilentlyContinue | ForEach-Object { Set-Service -Name $_.Name -StartupType Disabled }  # Disable RDP service startup if service exists
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Force | Out-Null  # Ensure Remote Assistance key exists
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -PropertyType DWord -Value 0 -Force | Out-Null  # Disable Remote Assistance
}

# ----------------------------- Printers: restrict driver installs to admins -----------------------------

Invoke-Safe -Task "Restrict driver installs to admin" -Script {
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Force | Out-Null  # Create Point and Print policy key
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "RestrictDriverInstallationToAdministrators" -PropertyType DWord -Value 1 -Force | Out-Null  # Allow printer driver installs only by admins
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "NoWarningNoElevationOnInstall" -PropertyType DWord -Value 0 -Force | Out-Null  # Show warnings and require elevation on driver install
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "UpdatePromptSettings" -PropertyType DWord -Value 0 -Force | Out-Null  # Prompt on driver updates
}

# ----------------------------- Logon privacy and AutoPlay/AutoRun -----------------------------

Invoke-Safe -Task "Logon privacy and AutoPlay/AutoRun" -Script {
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DontDisplayLastUserName" -PropertyType DWord -Value 1 -Force | Out-Null  # Hide last signed-in user at the logon screen

New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -PropertyType DWord -Value 255 -Force | Out-Null  # Disable AutoRun for all drive types (machine policy)
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutoRun" -PropertyType DWord -Value 1 -Force | Out-Null             # Disable AutoRun entirely (machine policy)
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutoPlay" -PropertyType DWord -Value 1 -Force | Out-Null            # Disable AutoPlay (machine policy)
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -PropertyType DWord -Value 255 -Force | Out-Null  # Disable AutoRun for all drive types (user policy)
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutoRun" -PropertyType DWord -Value 1 -Force | Out-Null             # Disable AutoRun entirely (user policy)
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutoPlay" -PropertyType DWord -Value 1 -Force | Out-Null            # Disable AutoPlay (user policy)
}

# ----------------------------- Windows Update: ensure automatic checks and service state -----------------------------

Invoke-Safe -Task "Windows Update checks and service state" -Script {
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null  # Ensure Windows Update AU policy key exists
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -PropertyType DWord -Value 4 -Force | Out-Null  # Auto download & schedule install
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -PropertyType DWord -Value 1 -Force | Out-Null  # Avoid auto reboot with active users

Get-Service -Name wuauserv -ErrorAction SilentlyContinue | ForEach-Object { Set-Service -Name $_.Name -StartupType Automatic }  # Ensure Windows Update service is set to Automatic
Get-Service -Name wuauserv -ErrorAction SilentlyContinue | Where-Object { $_.Status -ne 'Running' } | Start-Service  # Start Windows Update if not running
Get-Service -Name UsoSvc,BITS -ErrorAction SilentlyContinue | ForEach-Object { Set-Service -Name $_.Name -StartupType Automatic }  # Ensure Update Orchestrator and BITS are Automatic
}

# ----------------------------- SmartScreen (Explorer) -----------------------------

Invoke-Safe -Task "SmertScreen" -Script {
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Force | Out-Null  # Ensure Windows System policy key
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -PropertyType DWord -Value 1 -Force | Out-Null  # Enable SmartScreen
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "ShellSmartScreenLevel" -PropertyType String -Value "Block" -Force | Out-Null  # Set SmartScreen level to Block
}

# ----------------------------- Memory Integrity (HVCI) / Core Isolation -----------------------------

Invoke-Safe -Task "Memory Integrity (HVCI) / Core Isolation" -Script {
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Force | Out-Null  # Ensure DeviceGuard key exists
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -PropertyType DWord -Value 1 -Force | Out-Null  # Enable virtualization-based security
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "RequirePlatformSecurityFeatures" -PropertyType DWord -Value 1 -Force | Out-Null  # Require platform security features
}

# ----------------------------- Additional Security Hardening Section -----------------------------

Invoke-Safe -Task "Additional Security Hardening" -Script {
    # 1. Restrict PowerShell and Command Prompt usage (AppLocker audit mode, enforce if desired)
    # Note: AppLocker requires Windows Enterprise/Education
    $appLockerPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2"
    if ((Get-WmiObject -Class Win32_OperatingSystem).Caption -match "Enterprise|Education") {
        New-Item -Path $appLockerPath -Force | Out-Null
        # Example: Block PowerShell and cmd.exe for non-admins (audit mode)
        # For full enforcement, set EnforcementMode to 1
        New-ItemProperty -Path "$appLockerPath" -Name "EnforcementMode" -PropertyType DWord -Value 0 -Force | Out-Null
        Add-Summary "AppLocker audit mode enabled (manual configuration needed for rules)."
    }

    # 2. Disable SMBv1
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
    Add-Summary "SMBv1 disabled."

    # 3. Disable Remote Registry
    Set-Service -Name RemoteRegistry -StartupType Disabled
    Stop-Service -Name RemoteRegistry -Force
    Add-Summary "Remote Registry service disabled."

    # 4. Restrict RDP to Network Level Authentication
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -PropertyType DWord -Value 1 -Force | Out-Null
    Add-Summary "RDP set to require Network Level Authentication."

    # 5. Disable Guest Account
    Disable-LocalUser -Name "Guest"
    Add-Summary "Guest account disabled."

    # 6. Restrict Scheduled Tasks (disable suspicious tasks)
    $suspiciousTasks = Get-ScheduledTask | Where-Object { $_.TaskName -match "OneClick|Remote|Update|VNC|TFTP|IIS" }
    foreach ($task in $suspiciousTasks) {
        try {
            Disable-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath
            Add-Summary ("Disabled suspicious scheduled task: {0}" -f $task.TaskName)
        } catch {
            Add-Summary ("Failed to disable scheduled task '{0}': {1}" -f $task.TaskName, $_.Exception.Message)
        }
    }

    # 7. Enable Controlled Folder Access (Defender)
    Set-MpPreference -EnableControlledFolderAccess Enabled
    Add-Summary "Controlled Folder Access enabled."

    # 8. Disable Windows Script Host
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows Script Host\Settings" -Name "Enabled" -PropertyType DWord -Value 0 -Force | Out-Null
    Add-Summary "Windows Script Host disabled."

    # 9. Disable Autorun for Removable Media (already present, but ensure for all users)
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -PropertyType DWord -Value 255 -Force | Out-Null
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -PropertyType DWord -Value 255 -Force | Out-Null
    Add-Summary "Autorun disabled for all drive types (machine and user policy)."

    # 10. Configure Audit Policies for Object Access
    auditpol /set /subcategory:"File System" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"Registry" /success:enable /failure:enable | Out-Null
    Add-Summary "Audit policies for file system and registry object access enabled."

    # 11. Restrict USB Storage Devices
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" -Name "Start" -PropertyType DWord -Value 4 -Force | Out-Null
    Add-Summary "USB storage devices disabled."

    # 12. Remove Everyone and Guest permissions from Users folder only
    $usersPath = "$env:SystemDrive\Users"
    icacls $usersPath /remove:g Everyone /remove:g Guest /T /C | Out-Null
    Add-Summary ("Removed Everyone and Guest permissions from '$usersPath'.")

    # 13. Ensure Windows Defender is enabled and up to date
    Set-MpPreference -DisableRealtimeMonitoring $false
    Update-MpSignature | Out-Null
    Add-Summary "Windows Defender real-time protection enabled and signatures updated."
}

# ----------------------------- Interactive: Review all local groups -----------------------------

Invoke-Safe -Task "Review all local group members" -Script {
    $groups = Get-LocalGroup
    foreach ($group in $groups) {
        $groupObj = [ADSI]"WinNT://$env:COMPUTERNAME/$($group.Name),group"
        $members = @($groupObj.psbase.Invoke("Members")) | ForEach-Object {
            $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)
        }
        foreach ($member in $members) {
            Write-Host "`nGroup: $($group.Name) - Member: $member" -ForegroundColor Cyan
            $resp = Read-Host "Keep this account in $($group.Name)? (Yes/No)"
            if (@("no","n") -contains $resp.Trim().ToLower()) {
                try {
                    $groupObj.Remove("WinNT://$env:COMPUTERNAME/$member")
                    Add-Summary ("Removed '$member' from $($group.Name).")
                    Write-Host "Removed $member from $($group.Name)." -ForegroundColor Yellow
                } catch {
                    Add-Summary ("Failed to remove '$member' from $($group.Name): {0}" -f $_.Exception.Message)
                    Write-Host "Failed to remove '$member' from $($group.Name): $($_.Exception.Message)" -ForegroundColor Red
                }
            } else {
                Add-Summary ("Kept '$member' in $($group.Name).")
            }
        }
    }
}

# ----------------------------- Interactive: Review and optionally disable local accounts -----------------------------

Invoke-Safe -Task "Review and optionally disable local accounts" -Script {
    $accounts = Get-LocalUser
    foreach ($acct in $accounts) {
        Write-Host "`nLocal account: $($acct.Name) (Enabled: $($acct.Enabled))" -ForegroundColor Cyan
        $resp = Read-Host "Keep this account? (Yes/No)"
        if (@("no","n") -contains $resp.Trim().ToLower()) {
            try {
                Disable-LocalUser -Name $acct.Name
                Add-Summary ("Disabled account '$($acct.Name)'.")
                Write-Host "Disabled $($acct.Name)." -ForegroundColor Yellow
            } catch {
                Add-Summary ("Failed to disable '$($acct.Name)': {0}" -f $_.Exception.Message)
                Write-Host "Failed to disable $($acct.Name): $($_.Exception.Message)" -ForegroundColor Red
            }
        } else {
            Add-Summary ("Kept account '$($acct.Name)' enabled.")
        }
    }
}

# ----------------------------- Interactive: Review and optionally remove installed applications -----------------------------

Invoke-Safe -Task "Review and optionally remove installed applications" -Script {
    $apps = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*,
                            HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
            Where-Object { $_.DisplayName } | Sort-Object DisplayName
    foreach ($app in $apps) {
        Write-Host "`nApplication: $($app.DisplayName)" -ForegroundColor Cyan
        $resp = Read-Host "Keep this application? (Yes/No)"
        if (@("no","n") -contains $resp.Trim().ToLower()) {
            try {
                if ($app.UninstallString) {
                    Start-Process -FilePath "cmd.exe" -ArgumentList "/c $($app.UninstallString)" -Wait
                    Add-Summary ("Uninstalled '$($app.DisplayName)'.")
                    Write-Host "Uninstalled $($app.DisplayName)." -ForegroundColor Yellow
                } else {
                    Add-Summary ("No uninstall string for '$($app.DisplayName)'.")
                    Write-Host "No uninstall string for $($app.DisplayName)." -ForegroundColor Red
                }
            } catch {
                Add-Summary ("Failed to uninstall '$($app.DisplayName)': {0}" -f $_.Exception.Message)
                Write-Host "Failed to uninstall $($app.DisplayName): $($_.Exception.Message)" -ForegroundColor Red
            }
        } else {
            Add-Summary ("Kept '$($app.DisplayName)' installed.")
        }
    }
}

# ----------------------------- Interactive: Review and optionally remove music, image, zip, and PDF files (Users folder only) -----------------------------

Invoke-Safe -Task "Review and optionally remove music, image, zip, and PDF files in Users folder" -Script {
    $fileTypes = @("*.mp3", "*.wav", "*.flac", "*.jpg", "*.jpeg", "*.png", "*.gif", "*.bmp", "*.zip", "*.rar", "*.7z", "*.pdf")
    $files = @()
    foreach ($type in $fileTypes) {
        $files += Get-ChildItem -Path "$env:SystemDrive\Users" -Recurse -Include $type -ErrorAction SilentlyContinue
    }
    foreach ($file in $files) {
        Write-Host "`nFile: $($file.FullName)" -ForegroundColor Cyan
        $resp = Read-Host "Keep this file? (Yes/No)"
        if (@("no","n") -contains $resp.Trim().ToLower()) {
            try {
                Remove-Item -Path $file.FullName -Force
                Add-Summary ("Deleted file '$($file.FullName)'.")
                Write-Host "Deleted $($file.FullName)." -ForegroundColor Yellow
            } catch {
                Add-Summary ("Failed to delete '$($file.FullName)': {0}" -f $_.Exception.Message)
                Write-Host "Failed to delete $($file.FullName): $($_.Exception.Message)" -ForegroundColor Red
            }
        } else {
            Add-Summary ("Kept file '$($file.FullName)'.")
        }
    }
}

# ----------------------------- PDF-Based Remediations (CyberPatriot specific) -----------------------------

Invoke-Safe -Task "PDF-Based Remediations: Unauthorized apps, security policies, backdoors, and tampering checks" -Script {
    Write-Host "=== Starting PDF-Based Remediations ===" -ForegroundColor Cyan

    # --- 1. Unauthorized Application Removal ---
    # Sources: Server Training Round, CP-XVII Exhibition, Cincinnati Zoo
    # The base script removes VNC, IIS, TFTP, and McAfee. We add: TeamViewer, Nmap, Web Companion, npcap
    
    $appsToRemove = @(
        "TeamViewer",
        "Nmap",
        "Web Companion",
        "npcap"
    )
    
    foreach ($appName in $appsToRemove) {
        try {
            $app = Get-CimInstance -ClassName Win32_Product -Filter "Name LIKE '%$($appName)%'" -ErrorAction SilentlyContinue
            if ($app) {
                Write-Host "Attempting to uninstall '$($app.Name)'..." -ForegroundColor Yellow
                $app.Uninstall() | Out-Null
                Add-Summary "Uninstalled application: $($app.Name)"
            } else {
                Add-Summary "Confirmed application not found: $appName"
            }
        } catch {
            Add-Summary ("Failed to uninstall '$appName': {0}" -f $_.Exception.Message)
        }
    }

    # --- 2. Additional Security Policy Hardening (Registry) ---
    # Sources: My Little Pony, Santas Workshop, Cincinnati Zoo

    # Restrict blank password usage at console logon (distinct from LimitBlankPasswordUse)
    try {
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "LimitLocalAccountBlankPassword" -Value 1 -Type DWord -Force
        Add-Summary "Policy: Set LimitLocalAccountBlankPassword = 1"
    } catch {
        Add-Summary ("Failed to set LimitLocalAccountBlankPassword: {0}" -f $_.Exception.Message)
    }

    # Do not require CTRL+ALT+DEL: disabled (i.e., Require it: 0)
    try {
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableCAD" -Value 0 -Type DWord -Force
        Add-Summary "Policy: Set DisableCAD = 0 (CTRL+ALT+DEL is required)"
    } catch {
        Add-Summary ("Failed to set DisableCAD: {0}" -f $_.Exception.Message)
    }

    # RestrictAnonymous: prevent anonymous enumeration and connections
    try {
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1 -Type DWord -Force
        Add-Summary "Policy: Set RestrictAnonymous = 1"
    } catch {
        Add-Summary ("Failed to set RestrictAnonymous: {0}" -f $_.Exception.Message)
    }

    # AllowInsecureGuestAuth via Lanmanworkstation Policy Path (defense-in-depth)
    try {
        $lanmanPath = "HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation"
        if (!(Test-Path $lanmanPath)) { New-Item -Path $lanmanPath -Force | Out-Null }
        Set-ItemProperty -Path $lanmanPath -Name "AllowInsecureGuestAuth" -Value 0 -Type DWord -Force
        Add-Summary "Policy: Set AllowInsecureGuestAuth = 0 (via Lanmanworkstation path)"
    } catch {
        Add-Summary ("Failed to set AllowInsecureGuestAuth via Lanmanworkstation: {0}" -f $_.Exception.Message)
    }

    # --- 3. Remove Sticky Keys (sethc.exe) IFEO Backdoor ---
    # Source: Among The Reindeer
    # Checks for an Image File Execution Options (IFEO) debugger hijack on sethc.exe
    
    try {
        $ifeoPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe"
        if (Test-Path $ifeoPath) {
            $debugger = Get-ItemProperty -Path $ifeoPath -Name "Debugger" -ErrorAction SilentlyContinue
            if ($debugger -and $debugger.Debugger) {
                Remove-ItemProperty -Path $ifeoPath -Name "Debugger" -Force
                Add-Summary "Removed Sticky Keys (sethc.exe) IFEO backdoor"
                Write-Host "Removed Sticky Keys (sethc.exe) IFEO backdoor" -ForegroundColor Yellow
            } else {
                Add-Summary "No Sticky Keys backdoor detected (Debugger property not set)"
            }
        } else {
            Add-Summary "No Sticky Keys backdoor detected (IFEO key not present)"
        }
    } catch {
        Add-Summary ("Failed to check/remove Sticky Keys backdoor: {0}" -f $_.Exception.Message)
    }

    # --- 4. Enable System-Wide DEP (already set earlier, but verify here) ---
    # Source: The Cincinnati Zoo
    # Sets Data Execution Prevention (DEP) to AlwaysOn
    
    try {
        bcdedit.exe /set "{current}" nx AlwaysOn | Out-Null
        Add-Summary "Verified/Enabled system-wide DEP (nx AlwaysOn)"
    } catch {
        Add-Summary ("Failed to set DEP: {0}" -f $_.Exception.Message)
    }

    # --- 5. Detect and Report Windows Defender Tampering (PonyEng.exe) ---
    # Source: My Little Pony
    # Checks for a specific tamper where MsMpEng.exe is renamed to PonyEng.exe
    
    try {
        $platformPath = Get-ChildItem -Path "C:\ProgramData\Microsoft\Windows Defender\Platform" -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
        if ($platformPath) {
            $badFile = Join-Path $platformPath.FullName "PonyEng.exe"
            $goodFile = Join-Path $platformPath.FullName "MsMpEng.exe"
            
            if ((Test-Path $badFile) -and !(Test-Path $goodFile)) {
                Add-Summary "WARNING: Defender engine may be tampered - PonyEng.exe found at $badFile"
                Write-Host "WARNING: Defender tampering detected - PonyEng.exe found at $badFile" -ForegroundColor Red
                Add-Summary "Manual fix needed: Rename PonyEng.exe to MsMpEng.exe or reinstall Windows Defender"
            } else {
                Add-Summary "Defender engine check: No tampering detected"
            }
        } else {
            Add-Summary "Defender platform directory not found or empty"
        }
    } catch {
        Add-Summary ("Failed to check Defender tampering: {0}" -f $_.Exception.Message)
    }

    # --- 6. Fix Secpol Registry Key Permissions ---
    # Source: My Little Pony
    # The PDF notes that permissions on this key are broken, preventing secpol GUI from functioning.
    # We apply FullControl for Administrators.
    
    try {
        $secpolKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit"
        if (Test-Path $secpolKey) {
            $acl = Get-Acl $secpolKey
            $adminRule = New-Object System.Security.AccessControl.RegistryAccessRule(
                "Administrators",
                "FullControl",
                "ContainerInherit,ObjectInherit",
                "None",
                "Allow"
            )
            $acl.SetAccessRule($adminRule)
            Set-Acl -Path $secpolKey -AclObject $acl
            Add-Summary "Applied FullControl for Administrators to Secpol registry key"
            Write-Host "Fixed Secpol registry key permissions (Administrators now have FullControl)" -ForegroundColor Yellow
        } else {
            Add-Summary "Secpol registry key not found - cannot fix permissions"
        }
    } catch {
        Add-Summary ("Failed to set Secpol registry key permissions: {0}" -f $_.Exception.Message)
    }

    Write-Host "=== PDF-Based Remediations Complete ===" -ForegroundColor Green
    Add-Summary "PDF-based remediations completed."
}

# ----------------------------- Princeton-Plainsboro Teaching Hospital Hardening -----------------------------
Invoke-Safe -Task "PPTH Windows 11 Education Security Hardening" -Script {
    Write-Host "=== Starting PPTH System Hardening ===" -ForegroundColor Cyan

    # Local Policies & Passwords (using secedit for better error handling)
    try {
        $secpolPath = Join-Path $env:TEMP "secpol_$timestamp.cfg"
        $secpolDb = Join-Path $env:TEMP "secpol_$timestamp.sdb"
        
        # Export current policy
        secedit /export /cfg $secpolPath | Out-Null
        
        # Update password complexity in the exported file
        $content = Get-Content $secpolPath
        $content = $content -replace "PasswordComplexity = 0", "PasswordComplexity = 1"
        $content | Set-Content $secpolPath -Force
        
        # Import updated policy
        secedit /configure /db $secpolDb /cfg $secpolPath /areas SECURITYPOLICY | Out-Null
        Add-Summary "Password complexity enforced via secedit."
        
        # Clean up temp files
        Remove-Item $secpolPath, $secpolDb -Force -ErrorAction SilentlyContinue
    }
    catch {
        Add-Summary ("Failed to set password complexity: {0}" -f $_.Exception.Message)
    }

    # Audit Policy
    try {
        auditpol /set /subcategory:"Object Access" /success:enable /failure:enable | Out-Null
        Add-Summary "Object Access auditing enabled."
    }
    catch {
        Add-Summary ("Failed to set audit policy: {0}" -f $_.Exception.Message)
    }

    # UAC and RDP Security
    try {
        # Ensure registry paths exist
        $paths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
        )
        foreach ($path in $paths) {
            if (!(Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
        }

        # Set UAC and RDP security
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 1 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "SecurityLayer" -Value 2 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1 -PropertyType DWord -Force | Out-Null
        Add-Summary "UAC secure desktop and RDP security settings applied."
    }
    catch {
        Add-Summary ("Failed to set UAC/RDP security: {0}" -f $_.Exception.Message)
    }

    # Windows Defender & Firewall (using existing profile settings)
    try {
        Set-NetFirewallProfile -Profile Public -DefaultInboundAction Block -ErrorAction Stop
        Set-MpPreference -EnableScriptScanning $true -ErrorAction Stop
        Set-MpPreference -SevereThreatDefaultAction Quarantine -ErrorAction Stop
        Add-Summary "Defender and Firewall hardening applied."
    }
    catch {
        Add-Summary ("Failed to configure Defender/Firewall: {0}" -f $_.Exception.Message)
    }

    # Office Macro Security
    try {
        $officePath = "HKCU:\Software\Microsoft\Office\16.0\Word\Security"
        if (!(Test-Path $officePath)) { New-Item -Path $officePath -Force | Out-Null }
        New-ItemProperty -Path $officePath -Name "VBAWarnings" -Value 4 -PropertyType DWord -Force | Out-Null
        Add-Summary "Office macro security set to block Win32 API calls."
    }
    catch {
        Add-Summary ("Failed to set Office macro security: {0}" -f $_.Exception.Message)
    }

    # Windows Update (using modern UsoClient when available)
    try {
        $usoClient = "$env:SystemRoot\System32\UsoClient.exe"
        if (Test-Path $usoClient) {
            & $usoClient StartScan | Out-Null
            Start-Sleep -Seconds 5
            & $usoClient StartDownload | Out-Null
            Start-Sleep -Seconds 5
            & $usoClient StartInstall | Out-Null
            Add-Summary "Windows Update scan/install triggered via UsoClient."
        }
        else {
            Add-Summary "UsoClient not found for Windows Update."
        }
    }
    catch {
        Add-Summary ("Failed to trigger Windows Update: {0}" -f $_.Exception.Message)
    }

    # BitLocker (only if TPM is available)
    try {
        $tpm = Get-WmiObject -Namespace "root\cimv2\security\microsofttpm" -Class Win32_Tpm -ErrorAction Stop
        if ($tpm.IsEnabled().IsEnabled) {
            Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -UsedSpaceOnly -RecoveryPasswordProtector -ErrorAction Stop
            Add-Summary "BitLocker enabled on C: drive."
        }
        else {
            Add-Summary "TPM not enabled - BitLocker not configured."
        }
    }
    catch {
        Add-Summary ("BitLocker setup failed or TPM not available: {0}" -f $_.Exception.Message)
    }

    # Account Management
    try {
        Disable-LocalUser -Name "Guest" -ErrorAction Stop
        Set-LocalUser -Name "Cpark" -PasswordNeverExpires $false -ErrorAction Stop
        Add-Summary "Guest account disabled, Cpark password expiration enforced."
    }
    catch {
        Add-Summary ("Account management failed: {0}" -f $_.Exception.Message)
    }

    # PPTH-Specific Remediation
    try {
        # AnyDesk removal
        $anydeskPaths = @(
            "$env:ProgramFiles\AnyDesk",
            "${env:ProgramFiles(x86)}\AnyDesk"
        )
        foreach ($path in $anydeskPaths) {
            if (Test-Path $path) {
                Stop-Process -Name "AnyDesk" -Force -ErrorAction SilentlyContinue
                Remove-Item -Path $path -Recurse -Force
                Add-Summary "Removed AnyDesk from $path"
            }
        }

        # Mimikatz driver removal
        $mimikatzPaths = @(
            "$env:SystemRoot\System32\mimidrv.sys",
            "$env:SystemRoot\System32\drivers\mimidrv.sys"
        )
        foreach ($path in $mimikatzPaths) {
            if (Test-Path $path) {
                Remove-Item $path -Force
                Add-Summary "Removed Mimikatz driver from $path"
            }
        }

        # Sensitive file cleanup
        $sensitiveExt = @("*.doc", "*.txt", "*.pdf", "*.xls", "*.xlsx", "*.csv")
        $sensitiveLocations = @(
            "$env:PUBLIC\Documents",
            "$env:PUBLIC\Downloads",
            "$env:SystemDrive\Temp"
        )
        foreach ($loc in $sensitiveLocations) {
            if (Test-Path $loc) {
                foreach ($ext in $sensitiveExt) {
                    $files = Get-ChildItem -Path $loc -Filter $ext -Recurse -ErrorAction SilentlyContinue
                    if ($files) {
                        $files | Remove-Item -Force
                        Add-Summary "Removed sensitive $ext files from $loc"
                    }
                }
            }
        }

        # McAfee removal using proper product codes
        Get-WmiObject -Class Win32_Product | 
            Where-Object { $_.Name -like "*McAfee*" } | 
            ForEach-Object {
                $_ | Invoke-WmiMethod -Name Uninstall | Out-Null
                Add-Summary "Uninstalled McAfee product: $($_.Name)"
            }

        # FTP Service and persistence cleanup
        if ($ftpService = Get-Service -Name "FTPSVC" -ErrorAction SilentlyContinue) {
            Stop-Service -Name "FTPSVC" -Force -ErrorAction Stop
            Set-Service -Name "FTPSVC" -StartupType Disabled -ErrorAction Stop
            Add-Summary "FTP service disabled"
        }

        # Run key cleanup with better error handling
        $runKeyPaths = @(
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
        )
        foreach ($keyPath in $runKeyPaths) {
            if (Test-Path $keyPath) {
                $entries = Get-ItemProperty -Path $keyPath -ErrorAction Stop
                foreach ($prop in $entries.PSObject.Properties) {
                    if ($prop.Value -like "*powershell*" -or $prop.Value -like "*cmd.exe*") {
                        Remove-ItemProperty -Path $keyPath -Name $prop.Name -Force -ErrorAction Stop
                        Add-Summary "Removed suspicious Run key entry: $($prop.Name)"
                    }
                }
            }
        }
    }
    catch {
        Add-Summary ("Remediation step failed: {0}" -f $_.Exception.Message)
    }
    
    # ============================================================================
    # SECTION: DISA STIG & CIS BENCHMARK COMPLIANCE (WINDOWS 11)
    # Documents Referenced:
    #   1. CIS Microsoft Windows 11 Stand-alone Benchmark v4.0.0
    #   2. DISA Windows 11 STIG Overview V2R4
    # ============================================================================

    # ----------------------------------------------------------------------------
    # DISA STIG - Section 3.7: Cortana
    # ----------------------------------------------------------------------------
    Invoke-Safe -Task "DISA STIG 3.7: Disable Cortana (Allow Cortana)" -Script {
        # Reference: U_MS_Windows_11_V2R4_Overview.pdf, Page 12, Section 3.7
        # Requirement: "If an organization chooses not to allow Cortana, it can be disabled..."
        # Logic: Sets the 'AllowCortana' registry key to 0 (Disabled).
        
        $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
        if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
        
        New-ItemProperty -Path $path -Name "AllowCortana" -Value 0 -PropertyType DWord -Force | Out-Null
        Add-Summary "Compliance enforced: Cortana disabled per DISA STIG Sec 3.7"
    }

    # ----------------------------------------------------------------------------
    # CIS Benchmark - Section 18.10.59 (L2): Search Highlights
    # ----------------------------------------------------------------------------
    Invoke-Safe -Task "CIS 18.10.59: Disable Search Highlights" -Script {
        # Reference: CIS_Microsoft_Windows_11_Stand-alone_Benchmark_v4.0.0.pdf, Ticket #17591
        # Requirement: Ensure 'Allow search highlights' is set to 'Disabled'.
        # Logic: Disables dynamic content (highlights) in the Windows Search Box.
        
        $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
        if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
        
        New-ItemProperty -Path $path -Name "EnableDynamicContentInWSB" -Value 0 -PropertyType DWord -Force | Out-Null
        Add-Summary "Compliance enforced: Search highlights disabled per CIS 18.10.59"
    }

    # ----------------------------------------------------------------------------
    # CIS Benchmark - Section 18.10.29 (L2): Office.com in Quick Access
    # ----------------------------------------------------------------------------
    Invoke-Safe -Task "CIS 18.10.29: Disable Office.com Files in Quick Access" -Script {
        # Reference: CIS_Microsoft_Windows_11_Stand-alone_Benchmark_v4.0.0.pdf, Ticket #17587
        # Requirement: Ensure 'Turn off files from Office.com in Quick access view' is set to 'Enabled'.
        # Note: 'Enabled' policy means we act to TURN OFF the feature.
        
        $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
        if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
        
        New-ItemProperty -Path $path -Name "ShowCloudFilesInQuickAccess" -Value 0 -PropertyType DWord -Force | Out-Null
        Add-Summary "Compliance enforced: Office.com files removed from Quick Access per CIS 18.10.29"
    }

    # ----------------------------------------------------------------------------
    # CIS Benchmark - Section 18.10.43.6.1 (L1): Attack Surface Reduction (ASR)
    # ----------------------------------------------------------------------------
    Invoke-Safe -Task "CIS 18.10.43.6.1: Block Abuse of Exploited Vulnerable Signed Drivers" -Script {
        # Reference: CIS_Microsoft_Windows_11_Stand-alone_Benchmark_v4.0.0.pdf, Ticket #17588
        # Requirement: Configure ASR rule for "Block abuse of exploited vulnerable signed drivers".
        # GUID: 56a863a9-875e-4185-98a7-b882c64b5ce5
        # Action: 1 (Block)
        
        # Check if the rule is already active to avoid unnecessary output/error
        $asrRuleId = "56a863a9-875e-4185-98a7-b882c64b5ce5"
        $currentPref = Get-MpPreference
        
        if ($currentPref.AttackSurfaceReductionRules_Ids -notcontains $asrRuleId) {
            Add-MpPreference -AttackSurfaceReductionRules_Ids $asrRuleId -AttackSurfaceReductionRules_Actions 1 -ErrorAction Stop
            Add-Summary "Compliance enforced: ASR Rule 'Block Vulnerable Signed Drivers' enabled per CIS 18.10.43.6.1"
        } else {
            Add-Summary "Compliance check: ASR Rule 'Block Vulnerable Signed Drivers' already active."
        }
    }

    # ----------------------------------------------------------------------------
    # CIS Benchmark - Section 18.10.57.2 (L2): Cloud Clipboard Integration
    # ----------------------------------------------------------------------------
    Invoke-Safe -Task "CIS 18.10.57.2: Disable Cloud Clipboard Server-to-Client" -Script {
        # Reference: CIS_Microsoft_Windows_11_Stand-alone_Benchmark_v4.0.0.pdf, Ticket #17589
        # Requirement: Ensure 'Disable Cloud Clipboard integration for server-to-client data transfer' is set to 'Enabled'.
        # Logic: Prevents clipboard history from syncing across devices via the cloud.
        
        $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
        if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
        
        # "AllowCrossDeviceClipboard" = 0 disables the feature
        New-ItemProperty -Path $path -Name "AllowCrossDeviceClipboard" -Value 0 -PropertyType DWord -Force | Out-Null
        Add-Summary "Compliance enforced: Cloud Clipboard integration disabled per CIS 18.10.57.2"
    }

    # ----------------------------------------------------------------------------
    # CIS Benchmark - Section 18.10.76.1 (L1): Phishing Protection Notifications
    # ----------------------------------------------------------------------------
    Invoke-Safe -Task "CIS 18.10.76.1: Enable Enhanced Phishing Protection Notifications" -Script {
        # Reference: CIS_Microsoft_Windows_11_Stand-alone_Benchmark_v4.0.0.pdf, Ticket #17592, #17593, #17594
        # Requirement: Ensure 'Notify Malicious', 'Notify Password Reuse', and 'Notify Unsafe App' are 'Enabled'.
        # Target: Windows 11 22H2+ Enhanced Phishing Protection
        
        $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender SmartScreen"
        if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
        
        # Note: These keys may vary slightly by specific ADMX version, but standard implementation for 
        # Enhanced Phishing Protection involves these policy toggles.
        
        # Enable the feature service first if needed (ServiceEnabled)
        New-ItemProperty -Path $path -Name "ServiceEnabled" -Value 1 -PropertyType DWord -Force | Out-Null
        
        # Specific Notifications
        New-ItemProperty -Path $path -Name "NotifyMalicious" -Value 1 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path $path -Name "NotifyPasswordReuse" -Value 1 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path $path -Name "NotifyUnsafeApp" -Value 1 -PropertyType DWord -Force | Out-Null
        
        Add-Summary "Compliance enforced: Phishing protection notifications enabled per CIS 18.10.76.1"
    }

    # Final summary and completion message
    Write-Host "=== PPTH Hardening Complete ===" -ForegroundColor Green
    Add-Summary "PPTH hardening sequence completed."
    Write-Host "Script completed." -ForegroundColor Green
    Add-Summary "Please review the summary for details on actions taken."
}
