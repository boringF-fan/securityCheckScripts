@echo off
setlocal EnableExtensions
REM =============================================================================
REM Windows_Baseline_Check.cmd
REM -----------------------------------------------------------------------------
REM Windows Incident Response - Baseline Check (Phase 1) - CMD/Batch edition
REM Purpose : Collect a comprehensive baseline snapshot of a Windows host before
REM           any specialized malware hunting / forensic triage. The collected
REM           evidence serves as the judgement basis for the follow-up phases.
REM Output  : One timestamped folder with structured .txt evidence files.
REM           All output is ENGLISH (ASCII) to avoid code-page issues on any
REM           locale. Comments are English as well.
REM Usage   : Windows_Baseline_Check.cmd
REM           Windows_Baseline_Check.cmd D:\IR\baseline
REM Notes   : Some sections require an elevated (Administrator) shell, e.g.
REM           Security event log (wevtutil), net session, some registry hives.
REM           The script keeps running and reports what it could not collect.
REM =============================================================================

REM --- avoid Chinese/UTF8 mojibake: switch console to UTF-8 (best effort) ------
chcp 65001 >nul 2>nul

REM --- output directory (parameter 1 or default inside script folder) ----------
set "SCRIPT_DIR=%~dp0"
set "OUTDIR=%~1"
if "%OUTDIR%"=="" set "OUTDIR=%SCRIPT_DIR%Baseline_Results_%RANDOM%"
if not exist "%OUTDIR%" mkdir "%OUTDIR%"

REM --- timestamp via powershell (locale independent) ---------------------------
for /f "usebackq delims=" %%i in (`powershell -NoProfile -Command "Get-Date -Format yyyyMMdd_HHmmss"`) do set "TS=%%i"
set "HOST=%COMPUTERNAME%"

echo ================================================================
echo WINDOWS BASELINE CHECK (CMD EDITION) - Started at %TS%
echo Host: %HOST%
echo Output: %OUTDIR%
echo NOTE: Run as Administrator for full coverage (Security log, net session, etc.)
echo ================================================================

REM =============================================================================
REM 01 - SYSTEM INFORMATION (includes patch level summary)
REM =============================================================================
set "F=%OUTDIR%\01_System_Information.txt"
echo [SECTION] SYSTEM INFORMATION > "%F%"
echo [HOST] %HOST% >> "%F%"
echo [TIME] %TS% >> "%F%"
echo ----------------------------------------------------------------- >> "%F%"
systeminfo >> "%F%" 2>nul
if errorlevel 1 echo [-] systeminfo failed >> "%F%"

REM =============================================================================
REM 02 - INSTALLED HOTFIXES / PATCHES
REM =============================================================================
set "F=%OUTDIR%\02_Installed_Hotfixes.txt"
echo [SECTION] INSTALLED HOTFIXES / PATCHES > "%F%"
echo [HOST] %HOST% >> "%F%"
echo [TIME] %TS% >> "%F%"
echo ----------------------------------------------------------------- >> "%F%"
wmic qfe get HotFixID,Description,InstalledOn,InstalledBy /format:table >> "%F%" 2>nul
if errorlevel 1 (
  echo [-] wmic unavailable, trying powershell fallback >> "%F%"
  powershell -NoProfile -Command "Get-HotFix | Sort-Object InstalledOn -Descending | Format-Table -AutoSize" >> "%F%" 2>nul
)

REM =============================================================================
REM 03 - LOCAL ACCOUNTS / GROUPS / PASSWORD POLICY
REM =============================================================================
set "F=%OUTDIR%\03_Accounts_And_Groups.txt"
echo [SECTION] LOCAL ACCOUNTS, GROUPS, PASSWORD POLICY > "%F%"
echo [HOST] %HOST% >> "%F%"
echo [TIME] %TS% >> "%F%"
echo ----------------------------------------------------------------- >> "%F%"
echo [LOCAL USERS] >> "%F%"
net user >> "%F%" 2>nul
echo. >> "%F%"
echo [ADMINISTRATORS GROUP MEMBERS] >> "%F%"
net localgroup administrators >> "%F%" 2>nul
echo. >> "%F%"
echo [PASSWORD POLICY] >> "%F%"
net accounts >> "%F%" 2>nul
echo. >> "%F%"
echo [USER DETAIL - whoami] >> "%F%"
whoami /all >> "%F%" 2>nul

REM =============================================================================
REM 04 - NETWORK CONFIGURATION AND ACTIVE CONNECTIONS
REM =============================================================================
set "F=%OUTDIR%\04_Network.txt"
echo [SECTION] NETWORK CONFIGURATION AND ACTIVE CONNECTIONS > "%F%"
echo [HOST] %HOST% >> "%F%"
echo [TIME] %TS% >> "%F%"
echo ----------------------------------------------------------------- >> "%F%"
echo [IP CONFIGURATION] >> "%F%"
ipconfig /all >> "%F%" 2>nul
echo. >> "%F%"
echo [ARP TABLE] >> "%F%"
arp -a >> "%F%" 2>nul
echo. >> "%F%"
echo [ROUTE TABLE] >> "%F%"
route print >> "%F%" 2>nul
echo. >> "%F%"
echo [DNS CACHE] >> "%F%"
ipconfig /displaydns >> "%F%" 2>nul
echo. >> "%F%"
echo [ACTIVE TCP/UDP CONNECTIONS - netstat -ano] >> "%F%"
netstat -ano >> "%F%" 2>nul
echo. >> "%F%"
echo [ESTABLISHED AND LISTENING ENDPOINTS] >> "%F%"
netstat -ano | findstr /I "ESTABLISHED LISTENING" >> "%F%" 2>nul

REM =============================================================================
REM 05 - PROCESSES (with command lines)
REM =============================================================================
set "F=%OUTDIR%\05_Processes.txt"
echo [SECTION] RUNNING PROCESSES WITH COMMAND LINES > "%F%"
echo [HOST] %HOST% >> "%F%"
echo [TIME] %TS% >> "%F%"
echo ----------------------------------------------------------------- >> "%F%"
echo [TASKLIST VERBOSE] >> "%F%"
tasklist /v >> "%F%" 2>nul
echo. >> "%F%"
echo [PROCESS COMMAND LINES (wmic)] >> "%F%"
wmic process get ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine /format:list >> "%F%" 2>nul
if errorlevel 1 (
  echo [-] wmic unavailable, trying powershell fallback >> "%F%"
  powershell -NoProfile -Command "Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine | Format-Table -Wrap -AutoSize" >> "%F%" 2>nul
)

REM =============================================================================
REM 06 - AUTO-START ENTRIES (registry Run keys + startup folders)
REM =============================================================================
set "F=%OUTDIR%\06_Autostart.txt"
echo [SECTION] AUTO-START ENTRIES (RUN KEYS + STARTUP FOLDERS) > "%F%"
echo [HOST] %HOST% >> "%F%"
echo [TIME] %TS% >> "%F%"
echo ----------------------------------------------------------------- >> "%F%"
set "RUNKEY1=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
set "RUNKEY2=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
set "RUNKEY3=HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
set "RUNKEY4=HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
set "RUNKEY5=HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
echo [RUN KEYS] >> "%F%"
reg query "%RUNKEY1%" >> "%F%" 2>nul
reg query "%RUNKEY2%" >> "%F%" 2>nul
reg query "%RUNKEY3%" >> "%F%" 2>nul
reg query "%RUNKEY4%" >> "%F%" 2>nul
reg query "%RUNKEY5%" >> "%F%" 2>nul
echo. >> "%F%"
echo [STARTUP FOLDERS] >> "%F%"
if exist "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup" (
  echo --- User Startup --- >> "%F%"
  dir /a "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup" >> "%F%" 2>nul
)
if exist "%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup" (
  echo --- All Users Startup --- >> "%F%"
  dir /a "%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup" >> "%F%" 2>nul
)

REM =============================================================================
REM 07 - SCHEDULED TASKS
REM =============================================================================
set "F=%OUTDIR%\07_Scheduled_Tasks.txt"
echo [SECTION] SCHEDULED TASKS (schtasks verbose) > "%F%"
echo [HOST] %HOST% >> "%F%"
echo [TIME] %TS% >> "%F%"
echo ----------------------------------------------------------------- >> "%F%"
schtasks /query /fo csv /v >> "%F%" 2>nul

REM =============================================================================
REM 08 - SERVICES (name / binary path / start mode / account)
REM =============================================================================
set "F=%OUTDIR%\08_Services.txt"
echo [SECTION] SERVICES > "%F%"
echo [HOST] %HOST% >> "%F%"
echo [TIME] %TS% >> "%F%"
echo ----------------------------------------------------------------- >> "%F%"
echo [SERVICE LIST (wmic)] >> "%F%"
wmic service get Name,DisplayName,State,StartMode,StartName,PathName /format:list >> "%F%" 2>nul
if errorlevel 1 (
  echo [-] wmic unavailable, trying powershell fallback >> "%F%"
  powershell -NoProfile -Command "Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,StartName,PathName | Format-Table -Wrap -AutoSize" >> "%F%" 2>nul
)
echo. >> "%F%"
echo [RUNNING SERVICES SUMMARY - sc query] >> "%F%"
sc query >> "%F%" 2>nul

REM =============================================================================
REM 09 - SHARES / OPEN FILES
REM =============================================================================
set "F=%OUTDIR%\09_Shares.txt"
echo [SECTION] SHARES AND OPEN FILES > "%F%"
echo [HOST] %HOST% >> "%F%"
echo [TIME] %TS% >> "%F%"
echo ----------------------------------------------------------------- >> "%F%"
echo [NET SHARE] >> "%F%"
net share >> "%F%" 2>nul
echo. >> "%F%"
echo [SESSIONS - requires admin] >> "%F%"
net session >> "%F%" 2>nul
echo. >> "%F%"
echo [OPEN FILES - requires admin] >> "%F%"
net file >> "%F%" 2>nul

REM =============================================================================
REM 10 - ENVIRONMENT VARIABLES (incl. .NET CLR profiling hijack)
REM =============================================================================
set "F=%OUTDIR%\10_Environment.txt"
echo [SECTION] ENVIRONMENT VARIABLES / .NET CLR PROFILING > "%F%"
echo [HOST] %HOST% >> "%F%"
echo [TIME] %TS% >> "%F%"
echo ----------------------------------------------------------------- >> "%F%"
echo [PROCESS ENVIRONMENT] >> "%F%"
set >> "%F%" 2>nul
echo. >> "%F%"
echo [MACHINE ENVIRONMENT (registry)] >> "%F%"
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" >> "%F%" 2>nul
reg query "HKCU\Environment" >> "%F%" 2>nul
echo. >> "%F%"
echo [.NET COR PROFILING HIJACK CHECK] >> "%F%"
echo COR_ENABLE_PROFILING=%COR_ENABLE_PROFILING% >> "%F%"
echo COR_PROFILER=%COR_PROFILER% >> "%F%"
echo COR_PROFILER_PATH=%COR_PROFILER_PATH% >> "%F%"

REM =============================================================================
REM 11 - PERSISTENCE / HIJACK REGISTRY KEYS (backdoor oriented)
REM =============================================================================
set "F=%OUTDIR%\11_Persistence_Registry.txt"
echo [SECTION] PERSISTENCE / INJECTION REGISTRY KEYS > "%F%"
echo [HOST] %HOST% >> "%F%"
echo [TIME] %TS% >> "%F%"
echo ----------------------------------------------------------------- >> "%F%"
echo [AppInit_DLLs - must be empty by default] >> "%F%"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs >> "%F%" 2>nul
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs >> "%F%" 2>nul
echo. >> "%F%"
echo [IFEO - any "debugger" value is suspicious] >> "%F%"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" /s /v debugger >> "%F%" 2>nul
echo. >> "%F%"
echo [AppCertDlls - should not exist by default] >> "%F%"
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls" /s >> "%F%" 2>nul
echo. >> "%F%"
echo [KnownDLLs - compare with default] >> "%F%"
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs" >> "%F%" 2>nul
echo. >> "%F%"
echo [Session Manager misc - SafeDllSearchMode / BootExecute] >> "%F%"
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v SafeDllSearchMode >> "%F%" 2>nul
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v BootExecute >> "%F%" 2>nul
echo. >> "%F%"
echo [ScreenSaver backdoor] >> "%F%"
reg query "HKCU\Control Panel\Desktop" /v SCRNSAVE.exe >> "%F%" 2>nul
reg query "HKCU\Control Panel\Desktop" /v ScreenSaveActive >> "%F%" 2>nul
reg query "HKCU\Control Panel\Desktop" /v ScreenSaverIsSecure >> "%F%" 2>nul
echo. >> "%F%"
echo [NetSh helper DLLs] >> "%F%"
reg query "HKLM\SOFTWARE\Microsoft\NetSh" >> "%F%" 2>nul
echo. >> "%F%"
echo [Password Filter / LSA Notification Packages] >> "%F%"
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "Notification Packages" >> "%F%" 2>nul
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages" >> "%F%" 2>nul
echo. >> "%F%"
echo [Network Provider order] >> "%F%"
reg query "HKLM\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order" >> "%F%" 2>nul
reg query "HKLM\SYSTEM\CurrentControlSet\Control\NetworkProvider\HwOrder" >> "%F%" 2>nul
echo. >> "%F%"
echo [Winsock NSP / Protocol catalog entries] >> "%F%"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\NameSpace_Catalog5\Catalog_Entries" /s >> "%F%" 2>nul
reg query "HKLM\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\NameSpace_Catalog5\Catalog_Entries64" /s >> "%F%" 2>nul
echo. >> "%F%"
echo [RDP client history] >> "%F%"
reg query "HKCU\Software\Microsoft\Terminal Server Client\Default" >> "%F%" 2>nul
reg query "HKCU\Software\Microsoft\Terminal Server Client\Servers" >> "%F%" 2>nul
echo. >> "%F%"
echo [RDP server deny flag - 0 means RDP enabled] >> "%F%"
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections >> "%F%" 2>nul

REM =============================================================================
REM 12 - LOG EVENTS (Security log key IDs, System errors, PowerShell, Defender)
REM =============================================================================
set "F=%OUTDIR%\12_Log_Events.txt"
echo [SECTION] LOG EVENTS (last 200 relevant entries each) > "%F%"
echo [HOST] %HOST% >> "%F%"
echo [TIME] %TS% >> "%F%"
echo ----------------------------------------------------------------- >> "%F%"
echo [SECURITY LOG - logon/account events 4624,4625,4672,4720,4732,4740,1102] >> "%F%"
wevtutil qe Security "/q:*[System[(EventID=4624 or EventID=4625 or EventID=4672 or EventID=4720 or EventID=4732 or EventID=4740 or EventID=1102)]]" /rd:true /c:200 /f:text >> "%F%" 2>nul
echo. >> "%F%"
echo [SYSTEM LOG - error/critical events] >> "%F%"
wevtutil qe System "/q:*[System[(Level=1 or Level=2)]]" /rd:true /c:100 /f:text >> "%F%" 2>nul
echo. >> "%F%"
echo [POWERSHELL SCRIPT BLOCK LOG 4104/4103] >> "%F%"
wevtutil qe "Microsoft-Windows-PowerShell/Operational" "/q:*[System[(EventID=4104 or EventID=4103)]]" /rd:true /c:100 /f:text >> "%F%" 2>nul
echo. >> "%F%"
echo [DEFENDER OPERATIONAL LOG] >> "%F%"
wevtutil qe "Microsoft-Windows-Windows Defender/Operational" /rd:true /c:100 /f:text >> "%F%" 2>nul

REM =============================================================================
REM 13 - SENSITIVE FOLDERS (temp / public / recycle bin)
REM =============================================================================
set "F=%OUTDIR%\13_Sensitive_Folders.txt"
echo [SECTION] SENSITIVE FOLDERS (temp / public / recycle bin) > "%F%"
echo [HOST] %HOST% >> "%F%"
echo [TIME] %TS% >> "%F%"
echo ----------------------------------------------------------------- >> "%F%"
echo [SYSTEM TEMP] >> "%F%"
dir /a /-c "%SystemRoot%\Temp" >> "%F%" 2>nul
echo. >> "%F%"
echo [USER TEMP] >> "%F%"
dir /a /-c "%TEMP%" >> "%F%" 2>nul
echo. >> "%F%"
echo [PUBLIC FOLDER] >> "%F%"
dir /a /-c "%SystemDrive%\Users\Public" >> "%F%" 2>nul
echo. >> "%F%"
echo [RECYCLE BIN - usually needs admin/system privileges] >> "%F%"
dir /a /-c "%SystemDrive%\$Recycle.Bin" >> "%F%" 2>nul

REM =============================================================================
REM 14 - INTEGRITY CHECK (Ease-of-Access binaries signature - sticky keys backdoor)
REM =============================================================================
set "F=%OUTDIR%\14_Integrity_Check.txt"
echo [SECTION] SIGNATURE CHECK OF EASE-OF-ACCESS / SYSTEM BINARIES > "%F%"
echo [HOST] %HOST% >> "%F%"
echo [TIME] %TS% >> "%F%"
echo ----------------------------------------------------------------- >> "%F%"
powershell -NoProfile -Command "$bins=@('C:\Windows\System32\sethc.exe','C:\Windows\System32\utilman.exe','C:\Windows\System32\osk.exe','C:\Windows\System32\Magnify.exe','C:\Windows\System32\Narrator.exe','C:\Windows\System32\DisplaySwitch.exe','C:\Windows\System32\AtBroker.exe','C:\Windows\System32\cmd.exe','C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'); foreach($b in $bins){ if(Test-Path $b){ $s=Get-AuthenticodeSignature $b; $h=(Get-FileHash $b -Algorithm SHA256).Hash; Write-Output ('FILE : '+$b); Write-Output ('  Signature : '+$s.Status+' | '+$s.SignerCertificate.Subject); Write-Output ('  SHA256    : '+$h); Write-Output '' } else { Write-Output ('FILE : '+$b+'  (NOT FOUND)') } }" >> "%F%" 2>nul

REM =============================================================================
REM 15 - FIREWALL STATUS AND RULES
REM =============================================================================
set "F=%OUTDIR%\15_Firewall.txt"
echo [SECTION] WINDOWS FIREWALL STATUS AND RULES > "%F%"
echo [HOST] %HOST% >> "%F%"
echo [TIME] %TS% >> "%F%"
echo ----------------------------------------------------------------- >> "%F%"
netsh advfirewall show allprofiles >> "%F%" 2>nul
echo. >> "%F%"
echo [ENABLED INBOUND ALLOW RULES] >> "%F%"
netsh advfirewall firewall show rule name=all dir=in action=allow status=enabled >> "%F%" 2>nul

REM =============================================================================
REM 16 - BITS JOBS / ANTIVIRUS STATUS
REM =============================================================================
set "F=%OUTDIR%\16_Bits_And_AV.txt"
echo [SECTION] BITS JOBS AND ANTIVIRUS STATUS > "%F%"
echo [HOST] %HOST% >> "%F%"
echo [TIME] %TS% >> "%F%"
echo ----------------------------------------------------------------- >> "%F%"
echo [BITS JOBS - all users] >> "%F%"
bitsadmin /list /allusers /verbose >> "%F%" 2>nul
echo. >> "%F%"
echo [ANTIVIRUS PRODUCTS] >> "%F%"
powershell -NoProfile -Command "Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue | Select-Object displayName,productState,pathToSignedProductExe | Format-List" >> "%F%" 2>nul

REM =============================================================================
REM Final: index
REM =============================================================================
set "F=%OUTDIR%\00_SUMMARY.txt"
echo WINDOWS BASELINE CHECK (CMD EDITION) - SUMMARY > "%F%"
echo Host    : %HOST% >> "%F%"
echo Time    : %TS% >> "%F%"
echo Output  : %OUTDIR% >> "%F%"
echo ---------------------------------------------------------------- >> "%F%"
echo GENERATED EVIDENCE FILES: >> "%F%"
for %%g in ("%OUTDIR%\*.txt") do echo   - %%~nxg (%%~zg bytes) >> "%F%"
echo ---------------------------------------------------------------- >> "%F%"
echo BASELINE CHECK COMPLETED. >> "%F%"

echo.
echo [=] Baseline check completed. Evidence saved to: %OUTDIR%
echo [=] Open 00_SUMMARY.txt for the index of collected artifacts.
endlocal
