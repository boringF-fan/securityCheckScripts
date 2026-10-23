# =============================================================================
# Windows_Baseline_Check.ps1
# -----------------------------------------------------------------------------
# Windows Incident Response - Baseline Check (Phase 1)
# Purpose : Collect a comprehensive baseline snapshot of a Windows host before
#           any specialized malware hunting / forensic triage. The collected
#           evidence serves as the judgement basis for the follow-up phases.
# Output  : One timestamped folder with structured .txt evidence files.
#           All output is ENGLISH (ASCII) to avoid code-page issues on any
#           locale. Comments are English as well.
# Usage   : powershell -ExecutionPolicy Bypass -File .\Windows_Baseline_Check.ps1
#           powershell -ExecutionPolicy Bypass -File .\Windows_Baseline_Check.ps1 -OutputDir D:\IR\baseline
# Notes   : Some sections require an elevated (Administrator) shell, e.g.
#           Security event log (wevtutil), net session, some registry hives.
#           The script keeps running and reports what it could not collect.
# =============================================================================

param(
    [string]$OutputDir = ""
)

# -----------------------------------------------------------------------------
# Global settings
# -----------------------------------------------------------------------------
$ErrorActionPreference = 'Continue'
$OutputEncoding = [System.Text.Encoding]::ASCII

if ([string]::IsNullOrEmpty($OutputDir)) {
    $OutputDir = Join-Path $PSScriptRoot ("Baseline_Results_" + (Get-Date -Format 'yyyyMMdd_HHmmss'))
}
if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }

$hostname = [System.Net.Dns]::GetHostName()
$timeStamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

# Small helper: write a section header into an output file
function Write-Header {
    param([string]$File, [string]$Title)
    $line = '=' * 100
    Add-Content -Path $File -Encoding ASCII -Value $line
    Add-Content -Path $File -Encoding ASCII -Value ("[SECTION] " + $Title)
    Add-Content -Path $File -Encoding ASCII -Value ("[HOST]   " + $hostname)
    Add-Content -Path $File -Encoding ASCII -Value ("[TIME]   " + $timeStamp)
    Add-Content -Path $File -Encoding ASCII -Value $line
}

# Small helper: dump an object/command output with error tolerance
function Invoke-ToFile {
    param([string]$File, [scriptblock]$Block, [string]$FailMsg = '')
    try {
        & $Block | Out-File -FilePath $File -Encoding ascii -Append
    } catch {
        $msg = $FailMsg
        if ([string]::IsNullOrEmpty($msg)) { $msg = $_.Exception.Message }
        $warn = '[-] Collection failed: ' + $msg
        Add-Content -Path $File -Encoding ASCII -Value $warn
    }
}

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Summary file
$summaryFile = Join-Path $OutputDir '00_SUMMARY.txt'
Add-Content -Path $summaryFile -Encoding ASCII -Value ('=' * 100)
Add-Content -Path $summaryFile -Encoding ASCII -Value 'WINDOWS BASELINE CHECK - EXECUTION SUMMARY'
Add-Content -Path $summaryFile -Encoding ASCII -Value ("Host     : " + $hostname)
Add-Content -Path $summaryFile -Encoding ASCII -Value ("Time     : " + $timeStamp)
Add-Content -Path $summaryFile -Encoding ASCII -Value ("Admin    : " + $isAdmin)
Add-Content -Path $summaryFile -Encoding ASCII -Value ("OutputDir: " + $OutputDir)
Add-Content -Path $summaryFile -Encoding ASCII -Value ('=' * 100)
Add-Content -Path $summaryFile -Encoding ASCII -Value ''
Add-Content -Path $summaryFile -Encoding ASCII -Value 'NOTE: Run this script as Administrator for full coverage (Security log, net session, etc.).'

# =============================================================================
# 01 - SYSTEM INFORMATION
# =============================================================================
$f = Join-Path $OutputDir '01_System_Information.txt'
Write-Header -File $f -Title 'SYSTEM INFORMATION'
Invoke-ToFile -File $f -Block { Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture, InstallDate, LastBootUpTime, TotalVisibleMemorySize, FreePhysicalMemory | Format-List }
Invoke-ToFile -File $f -Block { Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer, Model, Domain, DomainRole, PartOfDomain, TotalPhysicalMemory | Format-List }
Invoke-ToFile -File $f -Block { Get-CimInstance Win32_BIOS | Select-Object Manufacturer, SMBIOSBIOSVersion, SerialNumber | Format-List }
Invoke-ToFile -File $f -Block { Get-CimInstance Win32_Processor | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed | Format-List }
Invoke-ToFile -File $f -Block { Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | Select-Object DeviceID, VolumeName, Size, FreeSpace | Format-List }
Invoke-ToFile -File $f -Block { Get-TimeZone | Select-Object Id, DisplayName | Format-List }
Add-Content -Path $f -Encoding ASCII -Value '[UPTIME]'
try { Add-Content -Path $f -Encoding ASCII -Value ((Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime).ToString() } catch { Add-Content -Path $f -Encoding ASCII -Value '[-] uptime unavailable' }

# =============================================================================
# 02 - INSTALLED HOTFIXES / PATCHES
# =============================================================================
$f = Join-Path $OutputDir '02_Installed_Hotfixes.txt'
Write-Header -File $f -Title 'INSTALLED HOTFIXES / PATCHES'
Invoke-ToFile -File $f -Block { Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object HotFixID, Description, InstalledOn, InstalledBy | Format-Table -AutoSize }
Add-Content -Path $f -Encoding ASCII -Value '[LAST PATCH DATE]'
try {
    $hf = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
    Add-Content -Path $f -Encoding ASCII -Value ("Last installed hotfix: " + $hf.HotFixID + " on " + $hf.InstalledOn)
} catch { Add-Content -Path $f -Encoding ASCII -Value '[-] no hotfix data' }

# =============================================================================
# 03 - LOCAL ACCOUNTS / GROUPS / PASSWORD POLICY
# =============================================================================
$f = Join-Path $OutputDir '03_Accounts_And_Groups.txt'
Write-Header -File $f -Title 'LOCAL ACCOUNTS, GROUPS, PASSWORD POLICY'
Add-Content -Path $f -Encoding ASCII -Value '[LOCAL USERS]'
Invoke-ToFile -File $f -Block { Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet, PasswordExpires, PasswordRequired, UserMayChangePassword, SID | Format-Table -AutoSize }
Add-Content -Path $f -Encoding ASCII -Value '[ADMINISTRATORS GROUP MEMBERS]'
Invoke-ToFile -File $f -Block { Get-LocalGroupMember -Group 'Administrators' | Select-Object Name, ObjectClass, PrincipalSource | Format-Table -AutoSize }
Add-Content -Path $f -Encoding ASCII -Value '[PASSWORD POLICY]'
Invoke-ToFile -File $f -Block { net accounts }
Add-Content -Path $f -Encoding ASCII -Value '[HIDDEN / WELL-KNOWN ACCOUNT CHECK (registry SAM, admin may be required)]'
try {
    $sam = 'Registry::HKEY_LOCAL_MACHINE\SAM\SAM\Domains\Account\Users\Names'
    if (Test-Path $sam) {
        Get-ChildItem $sam | Select-Object -ExpandProperty PSChildName | Out-File -FilePath $f -Encoding ascii -Append
    } else {
        Add-Content -Path $f -Encoding ASCII -Value '[-] SAM not accessible without SYSTEM privileges; check via net user / registry dump separately'
    }
} catch { Add-Content -Path $f -Encoding ASCII -Value '[-] SAM enumeration failed (not elevated?)' }

# =============================================================================
# 04 - LOGON / LOGOFF / FAILED LOGON EVENTS (Security log)
# =============================================================================
$f = Join-Path $OutputDir '04_Logon_Events.txt'
Write-Header -File $f -Title 'LOGON / FAILED LOGON / ACCOUNT CHANGES (Security log, last 7 days)'
$logonIds = @(4624, 4625, 4634, 4647, 4672, 4720, 4722, 4725, 4732, 4740, 1102, 4728, 4738)
try {
    $since = (Get-Date).AddDays(-7)
    Add-Content -Path $f -Encoding ASCII -Value ("[EVENT IDS " + ($logonIds -join ',') + " - last 300 entries in 7 days]")
    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=$logonIds; StartTime=$since} -MaxEvents 300 -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, Id, @{N='Message';E={$_.Message -split "`r`n" | Select-Object -First 8}} |
        Format-List | Out-File -FilePath $f -Encoding ascii -Append
} catch {
    Add-Content -Path $f -Encoding ASCII -Value '[-] Security log not readable (run elevated) or no events in range'
}

# =============================================================================
# 05 - NETWORK CONFIGURATION / CONNECTIONS
# =============================================================================
$f = Join-Path $OutputDir '05_Network.txt'
Write-Header -File $f -Title 'NETWORK CONFIGURATION AND ACTIVE CONNECTIONS'
Add-Content -Path $f -Encoding ASCII -Value '[IP CONFIGURATION]'
Invoke-ToFile -File $f -Block { ipconfig /all }
Add-Content -Path $f -Encoding ASCII -Value '[ARP TABLE]'
Invoke-ToFile -File $f -Block { arp -a }
Add-Content -Path $f -Encoding ASCII -Value '[ROUTE TABLE]'
Invoke-ToFile -File $f -Block { route print }
Add-Content -Path $f -Encoding ASCII -Value '[DNS CACHE]'
Invoke-ToFile -File $f -Block { ipconfig /displaydns }
Add-Content -Path $f -Encoding ASCII -Value '[ACTIVE TCP/UDP CONNECTIONS (netstat -ano)]'
Invoke-ToFile -File $f -Block { netstat -ano }
Add-Content -Path $f -Encoding ASCII -Value '[ESTABLISHED / LISTENING SUMMARY (external endpoints)]'
try {
    netstat -ano | Select-String -Pattern 'ESTABLISHED|LISTENING' | Out-File -FilePath $f -Encoding ascii -Append
} catch { Add-Content -Path $f -Encoding ASCII -Value '[-] netstat failed' }

# =============================================================================
# 06 - PROCESSES (with command lines)
# =============================================================================
$f = Join-Path $OutputDir '06_Processes.txt'
Write-Header -File $f -Title 'RUNNING PROCESSES WITH COMMAND LINES'
Invoke-ToFile -File $f -Block { Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine | Format-Table -Wrap -AutoSize }
Add-Content -Path $f -Encoding ASCII -Value '[PROCESSES WITH HIGH MEMORY / CPU (top 30 by working set)]'
try {
    Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 30 Id, ProcessName, CPU, WorkingSet64, Path | Format-Table -AutoSize | Out-File -FilePath $f -Encoding ascii -Append
} catch { Add-Content -Path $f -Encoding ASCII -Value '[-] process detail failed' }
Add-Content -Path $f -Encoding ASCII -Value '[PROCESSES WITHOUT VALID EXECUTABLE PATH (suspicious)]'
try {
    Get-CimInstance Win32_Process | Where-Object { [string]::IsNullOrEmpty($_.ExecutablePath) -and $_.Name -notmatch '^(System|Registry|Idle|csrss|smss|wininit|winlogon|services|lsass|fontdrvhost|dwm|explorer)$' } |
        Select-Object ProcessId, ParentProcessId, Name, CommandLine | Format-List | Out-File -FilePath $f -Encoding ascii -Append
} catch { Add-Content -Path $f -Encoding ASCII -Value '[-] no path check data' }

# =============================================================================
# 07 - AUTO-START ENTRIES (registry Run keys + startup folders)
# =============================================================================
$f = Join-Path $OutputDir '07_Autostart.txt'
Write-Header -File $f -Title 'AUTO-START ENTRIES (RUN KEYS + STARTUP FOLDERS)'
$runKeys = @(
    'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
    'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices',
    'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce',
    'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices',
    'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce'
)
foreach ($k in $runKeys) {
    Add-Content -Path $f -Encoding ASCII -Value ("[KEY] " + $k)
    try {
        if (Test-Path $k) {
            (Get-ItemProperty $k).PSObject.Properties | Where-Object { $_.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)' } |
                ForEach-Object { Add-Content -Path $f -Encoding ASCII -Value ($_.Name + " = " + $_.Value) }
        } else { Add-Content -Path $f -Encoding ASCII -Value '(not present)' }
    } catch { Add-Content -Path $f -Encoding ASCII -Value '[-] cannot read key' }
}
Add-Content -Path $f -Encoding ASCII -Value '[STARTUP FOLDERS]'
$startupDirs = @(
    (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup'),
    (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup')
)
foreach ($d in $startupDirs) {
    Add-Content -Path $f -Encoding ASCII -Value ("[DIR] " + $d)
    try {
        if (Test-Path $d) { Get-ChildItem $d -Force | Select-Object Name, Length, LastWriteTime | Format-Table -AutoSize | Out-File -FilePath $f -Encoding ascii -Append }
        else { Add-Content -Path $f -Encoding ASCII -Value '(not present)' }
    } catch { Add-Content -Path $f -Encoding ASCII -Value '[-] cannot read dir' }
}

# =============================================================================
# 08 - SCHEDULED TASKS
# =============================================================================
$f = Join-Path $OutputDir '08_Scheduled_Tasks.txt'
Write-Header -File $f -Title 'SCHEDULED TASKS (schtasks verbose)'
Invoke-ToFile -File $f -Block { schtasks /query /fo csv /v }
Add-Content -Path $f -Encoding ASCII -Value '[TASKS WITH ACTION COMMANDS (PowerShell view)]'
try {
    Get-ScheduledTask | ForEach-Object {
        $task = $_
        $actions = ($task.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }) -join ' | '
        Add-Content -Path $f -Encoding ASCII -Value ($task.TaskPath + $task.TaskName + ' | ' + $task.State + ' | ' + $actions)
    }
} catch { Add-Content -Path $f -Encoding ASCII -Value '[-] Get-ScheduledTask failed' }

# =============================================================================
# 09 - SERVICES (suspicious paths highlighted)
# =============================================================================
$f = Join-Path $OutputDir '09_Services.txt'
Write-Header -File $f -Title 'SERVICES (name / binary path / start mode / account)'
Invoke-ToFile -File $f -Block { Get-CimInstance Win32_Service | Select-Object Name, DisplayName, State, StartMode, StartName, PathName | Format-Table -Wrap -AutoSize }
Add-Content -Path $f -Encoding ASCII -Value '[SERVICES WITH BINARY OUTSIDE SYSTEM DIRS (suspicious candidates)]'
try {
    Get-CimInstance Win32_Service | Where-Object {
        $p = $_.PathName
        $p -notmatch '^"?(C:\\Windows\\(System32|SysWOW64|servicing|Microsoft\.NET)' -and
        $p -notmatch 'C:\\Program Files' -and
        $p -notmatch 'C:\\Program Files \(x86\)'
    } | Select-Object Name, DisplayName, State, StartMode, PathName | Format-List | Out-File -FilePath $f -Encoding ascii -Append
} catch { Add-Content -Path $f -Encoding ASCII -Value '[-] service path analysis failed' }

# =============================================================================
# 10 - SHARES / OPEN FILES
# =============================================================================
$f = Join-Path $OutputDir '10_Shares.txt'
Write-Header -File $f -Title 'SHARES AND OPEN FILES'
Add-Content -Path $f -Encoding ASCII -Value '[NET SHARE]'
Invoke-ToFile -File $f -Block { net share }
Add-Content -Path $f -Encoding ASCII -Value '[SHARE LIST (WMI)]'
Invoke-ToFile -File $f -Block { Get-CimInstance Win32_Share | Select-Object Name, Path, Type, Description | Format-Table -AutoSize }
Add-Content -Path $f -Encoding ASCII -Value '[SESSIONS / OPEN FILES (requires admin)]'
try { Invoke-ToFile -File $f -Block { net session } } catch { Add-Content -Path $f -Encoding ASCII -Value '[-] net session failed (elevation required)' }
try { Invoke-ToFile -File $f -Block { net file } } catch { Add-Content -Path $f -Encoding ASCII -Value '[-] net file failed (elevation required)' }

# =============================================================================
# 11 - ENVIRONMENT VARIABLES (incl. .NET CLR profiling hijack)
# =============================================================================
$f = Join-Path $OutputDir '11_Environment.txt'
Write-Header -File $f -Title 'ENVIRONMENT VARIABLES / .NET CLR PROFILING HIJACK CHECK'
Invoke-ToFile -File $f -Block { Get-ChildItem Env: | Sort-Object Name | Format-Table -AutoSize }
Add-Content -Path $f -Encoding ASCII -Value '[MACHINE ENV (registry)]'
try {
    $envKeys = @(
        'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
        'Registry::HKEY_CURRENT_USER\Environment'
    )
    foreach ($k in $envKeys) {
        Add-Content -Path $f -Encoding ASCII -Value ("[KEY] " + $k)
        if (Test-Path $k) {
            (Get-ItemProperty $k).PSObject.Properties | Where-Object { $_.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)' } |
                ForEach-Object { Add-Content -Path $f -Encoding ASCII -Value ($_.Name + " = " + $_.Value) }
        }
    }
} catch { Add-Content -Path $f -Encoding ASCII -Value '[-] env registry read failed' }
Add-Content -Path $f -Encoding ASCII -Value '[.NET COR PROFILING (COR_ENABLE_PROFILING / COR_PROFILER / COR_PROFILER_PATH)]'
Add-Content -Path $f -Encoding ASCII -Value ('COR_ENABLE_PROFILING = ' + $env:COR_ENABLE_PROFILING)
Add-Content -Path $f -Encoding ASCII -Value ('COR_PROFILER        = ' + $env:COR_PROFILER)
Add-Content -Path $f -Encoding ASCII -Value ('COR_PROFILER_PATH   = ' + $env:COR_PROFILER_PATH)

# =============================================================================
# 12 - PERSISTENCE / HIJACK REGISTRY KEYS (backdoor oriented)
# =============================================================================
$f = Join-Path $OutputDir '12_Persistence_Registry.txt'
Write-Header -File $f -Title 'PERSISTENCE / INJECTION REGISTRY KEYS'
$pKeys = @(
    @{k='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows';            d='AppInit_DLLs / LoadAppInit_DLLs / AppInit path (AppInit_DLLs must be empty by default)'},
    @{k='HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows';d='AppInit_DLLs (WOW64) - must be empty'},
    @{k='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'; d='IFEO - any "debugger" value is suspicious'},
    @{k='HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls';    d='AppCert DLLs - should not exist by default'},
    @{k='HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs';      d='KnownDLLs list - compare with default'},
    @{k='HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager';               d='SafeDllSearchMode / BootExecute'},
    @{k='HKCU:\Control Panel\Desktop';                                          d='ScreenSaver backdoor (SCRNSAVE.exe / ScreenSaveActive)'},
    @{k='HKLM:\SOFTWARE\Microsoft\NetSh';                                       d='NetSh helper DLLs'},
    @{k='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa';                           d='Notification Packages (Password Filter backdoor)'},
    @{k='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages';         d='Security Packages list'},
    @{k='HKLM:\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order';         d='Network Provider order'},
    @{k='HKLM:\SYSTEM\CurrentControlSet\Control\NetworkProvider\HwOrder';       d='HW Network Provider order'},
    @{k='HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers';               d='Print provider DLLs (potential persistence)'},
    @{k='HKLM:\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\NameSpace_Catalog5\Catalog_Entries';  d='Winsock NSP entries (LibraryPath)'},
    @{k='HKLM:\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\NameSpace_Catalog5\Catalog_Entries64';d='Winsock NSP entries x64 (LibraryPath)'},
    @{k='HKLM:\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries';  d='Winsock protocol entries'},
    @{k='HKLM:\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries64';d='Winsock protocol entries x64'},
    @{k='HKCU:\Software\Microsoft\Terminal Server Client\Default';               d='RDP client history (default connections)'},
    @{k='HKCU:\Software\Microsoft\Terminal Server Client\Servers';               d='RDP client history (servers)'},
    @{k='HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations';    d='RDP listener settings / fDenyTSConnections'},
    @{k='HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatFlags';d='Application shimming entries'}
)
foreach ($p in $pKeys) {
    Add-Content -Path $f -Encoding ASCII -Value ''
    Add-Content -Path $f -Encoding ASCII -Value ("[KEY] " + $p.k)
    Add-Content -Path $f -Encoding ASCII -Value ("      # " + $p.d)
    try {
        if (Test-Path $p.k) {
            Get-ChildItem -Path $p.k -ErrorAction SilentlyContinue | Select-Object -First 200 -ExpandProperty PSChildName |
                ForEach-Object { Add-Content -Path $f -Encoding ASCII -Value ("  subkey: " + $_) }
            $props = (Get-ItemProperty $p.k -ErrorAction SilentlyContinue).PSObject.Properties |
                Where-Object { $_.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)' }
            foreach ($pr in $props) {
                Add-Content -Path $f -Encoding ASCII -Value ("  " + $pr.Name + " = " + $pr.Value)
            }
        } else {
            Add-Content -Path $f -Encoding ASCII -Value '  (key not present - default is fine for most)'
        }
    } catch { Add-Content -Path $f -Encoding ASCII -Value '  [-] cannot read key' }
}
Add-Content -Path $f -Encoding ASCII -Value ''
Add-Content -Path $f -Encoding ASCII -Value '[IFEO debugger values - deep scan]'
try {
    $ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    $found = 0
    if (Test-Path $ifeo) {
        Get-ChildItem $ifeo | ForEach-Object {
            $dbg = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).debugger
            if ($dbg) {
                $found++
                Add-Content -Path $f -Encoding ASCII -Value ("  " + $_.PSChildName + " -> debugger = " + $dbg)
            }
        }
    }
    if ($found -eq 0) { Add-Content -Path $f -Encoding ASCII -Value '  No IFEO debugger values found (good).' }
} catch { Add-Content -Path $f -Encoding ASCII -Value '  [-] IFEO scan failed' }

# =============================================================================
# 13 - WMI EVENT SUBSCRIPTIONS (persistence)
# =============================================================================
$f = Join-Path $OutputDir '13_WMI_Subscriptions.txt'
Write-Header -File $f -Title 'WMI EVENT SUBSCRIPTIONS (EventFilter / EventConsumer / Binding)'
foreach ($ns in @('root\subscription', 'root\DEFAULT')) {
    Add-Content -Path $f -Encoding ASCII -Value ("[NAMESPACE] " + $ns)
    Add-Content -Path $f -Encoding ASCII -Value '  -- Event Filters --'
    try {
        Get-CimInstance -Namespace $ns -ClassName __EventFilter -ErrorAction Stop |
            Select-Object Name, Query | Format-List | Out-File -FilePath $f -Encoding ascii -Append
    } catch { Add-Content -Path $f -Encoding ASCII -Value '  [-] no/error filters' }
    Add-Content -Path $f -Encoding ASCII -Value '  -- Event Consumers --'
    try {
        Get-CimInstance -Namespace $ns -ClassName __EventConsumer -ErrorAction Stop |
            Select-Object Name, @{N='ExecutablePath';E={$_.ExecutablePath}}, @{N='CommandLineTemplate';E={$_.CommandLineTemplate}}, ScriptText |
            Format-List | Out-File -FilePath $f -Encoding ascii -Append
    } catch { Add-Content -Path $f -Encoding ASCII -Value '  [-] no/error consumers' }
    Add-Content -Path $f -Encoding ASCII -Value '  -- FilterToConsumer Bindings --'
    try {
        Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding -ErrorAction Stop |
            Select-Object Filter, Consumer | Format-List | Out-File -FilePath $f -Encoding ascii -Append
    } catch { Add-Content -Path $f -Encoding ASCII -Value '  [-] no/error bindings' }
}

# =============================================================================
# 14 - POWERSHELL HISTORY / PROFILE / TRANSCRIPT / BLOCK LOG
# =============================================================================
$f = Join-Path $OutputDir '14_PowerShell_History.txt'
Write-Header -File $f -Title 'POWERSHELL HISTORY, PROFILES, SCRIPT BLOCK LOG'
Add-Content -Path $f -Encoding ASCII -Value '[POWERSHELL CONSOLE HISTORY (user)]'
$psReadline = Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
if (Test-Path $psReadline) { Get-Content $psReadline | Out-File -FilePath $f -Encoding ascii -Append } else { Add-Content -Path $f -Encoding ASCII -Value '(no history file)' }
Add-Content -Path $f -Encoding ASCII -Value '[POWERSHELL PROFILES]'
try {
    $profileFiles = @($PROFILE.AllUsersAllHosts, $PROFILE.AllUsersCurrentHost, $PROFILE.CurrentUserAllHosts, $PROFILE.CurrentUserCurrentHost)
    foreach ($pf in $profileFiles) {
        Add-Content -Path $f -Encoding ASCII -Value ("[PROFILE] " + $pf + "  exists=" + (Test-Path $pf))
        if (Test-Path $pf) { Get-Content $pf | Out-File -FilePath $f -Encoding ascii -Append }
    }
} catch { Add-Content -Path $f -Encoding ASCII -Value '[-] profile enumeration failed' }
Add-Content -Path $f -Encoding ASCII -Value '[POWERSHELL SCRIPT BLOCK LOG (4104/4103, last 7 days, max 200)]'
try {
    $since = (Get-Date).AddDays(-7)
    Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=@(4104,4103); StartTime=$since} -MaxEvents 200 -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, Id, @{N='Msg';E={($_.Message -split "`r`n")[0..10] -join ' | '}} |
        Format-List | Out-File -FilePath $f -Encoding ascii -Append
} catch { Add-Content -Path $f -Encoding ASCII -Value '[-] PS operational log unavailable' }

# =============================================================================
# 15 - CMD HISTORY / RECENT FILES / PRE-FETCH
# =============================================================================
$f = Join-Path $OutputDir '15_Command_And_Recent_Artifacts.txt'
Write-Header -File $f -Title 'CMD HISTORY, RECENT FILES, PREFETCH'
Add-Content -Path $f -Encoding ASCII -Value '[RECENT DOCUMENTS (HKCU RecentDocs)]'
try {
    $r = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs'
    if (Test-Path $r) {
        Get-ChildItem $r | ForEach-Object {
            $vals = (Get-ItemProperty $_.PSPath).PSObject.Properties | Where-Object { $_.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)' }
            foreach ($v in $vals) { Add-Content -Path $f -Encoding ASCII -Value ($_.PSChildName + ' : ' + $v.Name) }
        }
    } else { Add-Content -Path $f -Encoding ASCII -Value '(no RecentDocs)' }
} catch { Add-Content -Path $f -Encoding ASCII -Value '[-] recent docs failed' }
Add-Content -Path $f -Encoding ASCII -Value '[PREFETCH FILES (most recent 100)]'
try {
    $pfDir = Join-Path $env:SystemRoot 'Prefetch'
    if (Test-Path $pfDir) {
        Get-ChildItem $pfDir -Filter '*.pf' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 100 Name, LastWriteTime | Format-Table -AutoSize | Out-File -FilePath $f -Encoding ascii -Append
    } else { Add-Content -Path $f -Encoding ASCII -Value '(no Prefetch - maybe disabled)' }
} catch { Add-Content -Path $f -Encoding ASCII -Value '[-] prefetch failed' }

# =============================================================================
# 16 - SENSITIVE FOLDERS (temp / public / recycle bin / deleted user homes)
# =============================================================================
$f = Join-Path $OutputDir '16_Sensitive_Folders.txt'
Write-Header -File $f -Title 'SENSITIVE FOLDERS (temp / public / recycle bin / user homes)'
$dirs = @(
    (Join-Path $env:SystemRoot 'Temp'),
    $env:TEMP,
    $env:TMP,
    (Join-Path $env:SystemDrive '\Users\Public'),
    (Join-Path $env:SystemDrive '\$Recycle.Bin'),
    (Join-Path $env:SystemDrive '\Users')
)
foreach ($d in $dirs) {
    Add-Content -Path $f -Encoding ASCII -Value ("[DIR] " + $d + "  exists=" + (Test-Path $d))
    try {
        if (Test-Path $d) {
            Get-ChildItem $d -Force -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending |
                Select-Object -First 50 Name, Length, LastWriteTime |
                Format-Table -AutoSize | Out-File -FilePath $f -Encoding ascii -Append
        }
    } catch { Add-Content -Path $f -Encoding ASCII -Value '  [-] cannot list' }
    Add-Content -Path $f -Encoding ASCII -Value ''
}

# =============================================================================
# 17 - INTEGRITY / SIGNATURE CHECK OF EASE-OF-ACCESS & SYSTEM BINARIES
# =============================================================================
$f = Join-Path $OutputDir '17_Integrity_Check.txt'
Write-Header -File $f -Title 'SIGNATURE CHECK OF EASE-OF-ACCESS / SYSTEM BINARIES (sticky keys backdoor etc.)'
$critical = @(
    (Join-Path $env:SystemRoot 'System32\sethc.exe'),
    (Join-Path $env:SystemRoot 'System32\utilman.exe'),
    (Join-Path $env:SystemRoot 'System32\osk.exe'),
    (Join-Path $env:SystemRoot 'System32\Magnify.exe'),
    (Join-Path $env:SystemRoot 'System32\Narrator.exe'),
    (Join-Path $env:SystemRoot 'System32\DisplaySwitch.exe'),
    (Join-Path $env:SystemRoot 'System32\AtBroker.exe'),
    (Join-Path $env:SystemRoot 'System32\cmd.exe'),
    (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe')
)
foreach ($bin in $critical) {
    if (Test-Path $bin) {
        $sig = Get-AuthenticodeSignature $bin
        $hash = (Get-FileHash $bin -Algorithm SHA256).Hash
        Add-Content -Path $f -Encoding ASCII -Value ("FILE : " + $bin)
        Add-Content -Path $f -Encoding ASCII -Value ("  Signature : " + $sig.Status + " | " + $sig.SignerCertificate.Subject)
        Add-Content -Path $f -Encoding ASCII -Value ("  SHA256    : " + $hash)
    } else {
        Add-Content -Path $f -Encoding ASCII -Value ("FILE : " + $bin + "  (NOT FOUND)")
    }
    Add-Content -Path $f -Encoding ASCII -Value ''
}

# =============================================================================
# 18 - WINDOWS FIREWALL STATUS & RULES
# =============================================================================
$f = Join-Path $OutputDir '18_Firewall.txt'
Write-Header -File $f -Title 'WINDOWS FIREWALL STATUS AND RULES'
try {
    Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction | Format-Table -AutoSize | Out-File -FilePath $f -Encoding ascii -Append
} catch { Add-Content -Path $f -Encoding ASCII -Value '[-] Get-NetFirewallProfile failed' }
Add-Content -Path $f -Encoding ASCII -Value '[ENABLED INBOUND RULES (non-default)]'
try {
    Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow -ErrorAction SilentlyContinue |
        Select-Object DisplayName, Profile, Action | Format-Table -AutoSize | Out-File -FilePath $f -Encoding ascii -Append
} catch { Add-Content -Path $f -Encoding ASCII -Value '[-] inbound rules enumeration failed' }

# =============================================================================
# 19 - DEFENDER / AV STATUS & DETECTION EVENTS
# =============================================================================
$f = Join-Path $OutputDir '19_Antivirus.txt'
Write-Header -File $f -Title 'WINDOWS DEFENDER / AV STATUS AND DETECTION EVENTS'
Add-Content -Path $f -Encoding ASCII -Value '[AV PRODUCTS (root\SecurityCenter2)]'
try {
    Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop |
        Select-Object displayName, productState, pathToSignedProductExe | Format-List | Out-File -FilePath $f -Encoding ascii -Append
} catch { Add-Content -Path $f -Encoding ASCII -Value '[-] SecurityCenter2 query failed (may not exist on Server Core)' }
Add-Content -Path $f -Encoding ASCII -Value '[DEFENDER STATUS (if available)]'
try {
    Get-MpComputerStatus -ErrorAction Stop | Select-Object AntivirusEnabled, AntivirusSignatureAge, AntivirusSignatureLastUpdated, RealTimeProtectionEnabled, DefenderSignaturesOutOfDate, AMServiceEnabled | Format-List | Out-File -FilePath $f -Encoding ascii -Append
} catch { Add-Content -Path $f -Encoding ASCII -Value '[-] Get-MpComputerStatus failed / module not present' }
Add-Content -Path $f -Encoding ASCII -Value '[DEFENDER DETECTION EVENTS (last 30 days, max 200)]'
try {
    $since = (Get-Date).AddDays(-30)
    Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; StartTime=$since} -MaxEvents 200 -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, Id, LevelDisplayName, @{N='Msg';E={($_.Message -split "`r`n")[0..6] -join ' | '}} |
        Format-List | Out-File -FilePath $f -Encoding ascii -Append
} catch { Add-Content -Path $f -Encoding ASCII -Value '[-] Defender log unavailable' }

# =============================================================================
# 20 - BITS JOBS / OTHER SYSTEM JOBS
# =============================================================================
$f = Join-Path $OutputDir '20_BITS_Jobs.txt'
Write-Header -File $f -Title 'BITS TRANSFER JOBS'
try {
    Get-BitsTransfer -AllUsers -ErrorAction Stop | Format-List | Out-File -FilePath $f -Encoding ascii -Append
} catch { Add-Content -Path $f -Encoding ASCII -Value '[-] Get-BitsTransfer failed (no permission / no jobs)' }

# =============================================================================
# Final: write index into summary
# =============================================================================
Add-Content -Path $summaryFile -Encoding ASCII -Value ''
Add-Content -Path $summaryFile -Encoding ASCII -Value 'GENERATED EVIDENCE FILES:'
Get-ChildItem $OutputDir -Filter '*.txt' | Sort-Object Name | ForEach-Object {
    Add-Content -Path $summaryFile -Encoding ASCII -Value ("  - " + $_.Name + "  (" + $_.Length + " bytes)")
}
Add-Content -Path $summaryFile -Encoding ASCII -Value ''
Add-Content -Path $summaryFile -Encoding ASCII -Value 'BASELINE CHECK COMPLETED.'

Write-Host "[+] Baseline check finished. Evidence saved to: $OutputDir" -ForegroundColor Green
Write-Host "[+] Open 00_SUMMARY.txt for the index of collected artifacts." -ForegroundColor Green
