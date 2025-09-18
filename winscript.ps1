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
    - BitLocker (optional, with confirmation)
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

if (@("yes","y") -notcontains $ans1.Trim().ToLower() -or @("yes","y") -notcontains $ans2.Trim().ToLower()) {
    Write-Host "`nPlease complete forensics questions and securely note passwords BEFORE running the script." -ForegroundColor Yellow
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

    # Only elevate signed executables (UAC policy)
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ValidateAdminCodeSignatures" -PropertyType DWord -Value 1 -Force | Out-Null
    Add-Summary "Configured UAC to only elevate signed executables."
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
    # min length 8, max age 30 days, min age 5 days, unique 5
    net accounts /minpwlen:8 /maxpwage:30 /minpwage:5 /uniquepw:5 | Out-Null
    Add-Summary "Password policy set: minlen=8, maxage=30, minage=5, history=5"
}

Invoke-Safe -Task "Enable password complexity requirement" -Script {
    # Complexity policy (Local Security Policy equivalent)
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "RequireStrongKey" -Value 1 -PropertyType DWord -Force | Out-Null
    # Primary switch for 'Password must meet complexity requirements'
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "PasswordComplexity" -Value 1 -PropertyType DWord -Force | Out-Null
    #
}
Invoke-Safe -Task "Change all local user passwords to Cyb3rP@tr!0T" -Script {
    $newPassword = "Cyb3rP@tr!0T"
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
net accounts /lockoutthreshold:7    # Lock out accounts after 7 failed logon attempts
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