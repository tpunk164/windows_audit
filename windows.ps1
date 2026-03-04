<#
COMPLETE Windows Security Audit v8.0
Covers system baseline, patching, identity, policy, logging, network, endpoint, hardening, and services.
#>

[CmdletBinding()]
param(
    [string]$OutputRoot = "$env:USERPROFILE\Desktop"
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = "Stop"

$ScriptVersion = "v8.0"
$BannerText = "by Green Tick Nepal Pvt. Ltd."
$ExpectedCheckCount = 106
$RunStart = Get-Date
$RunStamp = $RunStart.ToString("yyyyMMdd_HHmmss")
$AuditFolder = Join-Path $OutputRoot "Windows_Audit_$RunStamp"
$EvidenceFolder = Join-Path $AuditFolder "Evidence"
$CsvPath = Join-Path $AuditFolder "Windows_Audit.csv"
$TxtPath = Join-Path $AuditFolder "Windows_Audit.txt"
$JsonPath = Join-Path $AuditFolder "Windows_Audit.json"
$HtmlPath = Join-Path $AuditFolder "Windows_Audit.html"
$MetaPath = Join-Path $AuditFolder "Run_Metadata.txt"
$EvidenceIndexPath = Join-Path $AuditFolder "Evidence_Index.csv"

# Require elevation. If not elevated, try to relaunch the same script as Administrator.
$isAdmin = $false
try {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch { $isAdmin = $false }

if (-not $isAdmin) {
    Write-Host "Administrator privileges are required. Attempting elevated relaunch..." -ForegroundColor Yellow
    Write-Host $BannerText -ForegroundColor Green

    if (-not [string]::IsNullOrWhiteSpace([string]$PSCommandPath) -and (Test-Path -Path $PSCommandPath)) {
        $shellExe = (Get-Process -Id $PID).Path
        if ([string]::IsNullOrWhiteSpace([string]$shellExe) -or -not (Test-Path -Path $shellExe)) {
            $shellExe = 'powershell.exe'
        }

        $args = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $PSCommandPath))
        if ($PSBoundParameters.ContainsKey('OutputRoot')) {
            $args += @('-OutputRoot', ('"{0}"' -f $OutputRoot))
        }

        try {
            Start-Process -FilePath $shellExe -Verb RunAs -ArgumentList ($args -join ' ') | Out-Null
            exit 0
        } catch {
            throw "Administrator privileges are required. Relaunch failed or was cancelled."
        }
    }

    throw "Administrator privileges are required. Run this script in an elevated PowerShell terminal."
}

New-Item -ItemType Directory -Path $AuditFolder, $EvidenceFolder -Force | Out-Null
$Results = New-Object System.Collections.Generic.List[object]
$Checks = New-Object System.Collections.Generic.List[object]
$BaselineEvidencePaths = New-Object System.Collections.Generic.List[string]

Clear-Host
$bannerLine = ('=' * 90)
Write-Host $bannerLine -ForegroundColor DarkGreen
Write-Host ("WINDOWS SECURITY AUDIT {0} | {1}" -f $ScriptVersion, $env:COMPUTERNAME) -ForegroundColor Cyan
Write-Host $BannerText -ForegroundColor Green
Write-Host ("Started: {0} | User: {1} | Elevated: {2}" -f $RunStart.ToString('yyyy-MM-dd HH:mm:ss'), $env:USERNAME, $isAdmin) -ForegroundColor Gray
Write-Host $bannerLine -ForegroundColor DarkGreen
"=== WINDOWS SECURITY AUDIT | $($RunStart.ToString('yyyy-MM-dd HH:mm:ss')) | $env:COMPUTERNAME ===" | Set-Content -Path $TxtPath -Encoding UTF8
Add-Content -Path $TxtPath -Value ("BANNER: {0}" -f $BannerText)
Add-Content -Path $TxtPath -Value ("RUN CONTEXT: User={0} | IsAdmin={1}" -f $env:USERNAME, $isAdmin)

function Cmd {
    param([string]$Name)
    [bool](Get-Command -Name $Name -ErrorAction SilentlyContinue)
}

function Safe {
    param([scriptblock]$Script, $Default = $null)
    try { & $Script } catch { $Default }
}

function ToInt {
    param($Value)
    $n = 0
    if ([int]::TryParse([string]$Value, [ref]$n)) { return $n }
    return $null
}

function EV {
    param([string]$Status, [string]$Note)
    [pscustomobject]@{ Status = $Status.ToUpperInvariant(); Note = $Note }
}

function Add-CheckDef {
    param(
        [string]$Category,
        [string]$Name,
        [string]$Expected,
        [string]$Command,
        [scriptblock]$Get,
        [scriptblock]$Test
    )

    $script:Checks.Add([pscustomobject]@{
            Category = $Category
            Name = $Name
            Expected = $Expected
            Command = $Command
            Get = $Get.GetNewClosure()
            Test = $Test.GetNewClosure()
        }) | Out-Null
}

function SafeFileName {
    param([string]$Name)
    $x = ($Name -replace '[^A-Za-z0-9._-]', '_').Trim('_')
    if ([string]::IsNullOrWhiteSpace($x)) { return "check" }
    $x
}

function ShortText {
    param($InputObject, [int]$Max = 180)
    if ($null -eq $InputObject) { return "<null>" }
    if ($InputObject -is [string]) {
        $t = $InputObject.Trim()
    } elseif ($InputObject -is [System.Collections.IDictionary]) {
        $t = ($InputObject.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '; '
    } elseif ($InputObject -is [System.Collections.IEnumerable] -and -not ($InputObject -is [string])) {
        $arr = @($InputObject)
        if ($arr.Count -eq 0) { $t = "0 item(s)" }
        elseif ($arr.Count -le 3) { $t = ($arr | ForEach-Object { ($_ | Out-String).Trim() }) -join '; ' }
        else { $t = "$($arr.Count) item(s): " + (($arr[0..2] | ForEach-Object { ($_ | Out-String).Trim() }) -join '; ') + '; ...' }
    } else {
        $t = ($InputObject | Out-String).Trim()
    }
    if ([string]::IsNullOrWhiteSpace($t)) { $t = "<empty>" }
    if ($t.Length -gt $Max) { $t = $t.Substring(0, $Max) + '...' }
    $t
}

function RawText {
    param($InputObject)
    if ($null -eq $InputObject) { return "<null>" }
    if ($InputObject -is [string]) { return $InputObject }
    if ($InputObject -is [ValueType]) { return [string]$InputObject }
    try { return ($InputObject | ConvertTo-Json -Depth 8) } catch { return ($InputObject | Out-String) }
}

function RegVal {
    param([string]$Path, [string]$Name)
    try { (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch { $null }
}

function Prop {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($null -eq $p) { return $null }
    return $p.Value
}

function ServiceMode {
    param([string]$Name)
    $svc = Safe { Get-CimInstance -ClassName Win32_Service -Filter "Name='$Name'" }
    if ($svc) { $svc.StartMode } else { $null }
}

function Get-SecPolicy {
    $cfg = Join-Path $env:TEMP ("secpol_{0}.cfg" -f ([guid]::NewGuid().ToString('N')))
    $map = @{}
    try {
        secedit /export /cfg $cfg /quiet | Out-Null
        if (Test-Path $cfg) {
            foreach ($line in Get-Content $cfg -ErrorAction SilentlyContinue) {
                if ($line -match '^\s*([^;][^=]+?)\s*=\s*(.*)\s*$') {
                    $map[$matches[1].Trim()] = $matches[2].Trim()
                }
            }
        }
    } catch {
    } finally {
        Remove-Item $cfg -Force -ErrorAction SilentlyContinue
    }
    $map
}

function SecVal {
    param([hashtable]$Policy, [string]$Key)
    if ($Policy.ContainsKey($Key)) { $Policy[$Key] } else { $null }
}

function AuditSub {
    param([string]$Text, [string]$Subcategory)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $pattern = '^\s*' + [regex]::Escape($Subcategory) + '\s{2,}(?<setting>.+?)\s*$'
    foreach ($line in ($Text -split "`r?`n")) {
        if ($line -match $pattern) { return $matches['setting'].Trim() }
    }
    return $null
}

function PendingReboot {
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    )
    foreach ($k in $keys) { if (Test-Path $k) { return $true } }
    $rename = RegVal 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' 'PendingFileRenameOperations'
    if ($null -ne $rename) { return $true }
    return $false
}

function GroupMembers {
    param([string]$Group)
    if (-not (Cmd 'Get-LocalGroupMember')) { return @() }
    @(Safe { Get-LocalGroupMember -Group $Group -ErrorAction Stop } @())
}

function RunEntryCount {
    $count = 0
    foreach ($key in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run')) {
        try {
            $props = (Get-ItemProperty -Path $key -ErrorAction Stop).PSObject.Properties |
                Where-Object { $_.Name -notin @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider') }
            $count += $props.Count
        } catch {
        }
    }
    $count
}

function Resolve-ExecutablePath {
    param([string]$CommandLine)

    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $null }

    $cmd = [Environment]::ExpandEnvironmentVariables($CommandLine.Trim())
    $candidate = $null

    if ($cmd -match '^\s*"([^"]+)"') {
        $candidate = $matches[1]
    } elseif ($cmd -match "^\s*([^\s]+)") {
        $candidate = $matches[1]
    }

    if ([string]::IsNullOrWhiteSpace($candidate)) { return $null }

    $candidate = $candidate.Trim()
    $candidate = $candidate.Trim('"', "'")
    $candidate = $candidate.TrimEnd(',')
    if ([string]::IsNullOrWhiteSpace($candidate)) { return $null }

    if (Test-Path -LiteralPath $candidate -PathType Leaf) {
        try { return (Resolve-Path -LiteralPath $candidate -ErrorAction Stop).Path } catch { return $candidate }
    }

    $cmdObj = Safe { Get-Command -Name $candidate -ErrorAction Stop }
    if ($cmdObj) {
        $source = [string](Prop $cmdObj 'Source')
        if (-not [string]::IsNullOrWhiteSpace($source) -and (Test-Path -LiteralPath $source -PathType Leaf)) { return $source }
    }

    return $null
}

function Write-BaselineEvidence {
    $created = New-Object System.Collections.Generic.List[string]

    $runtimeFile = 'Baseline_Runtime_Context.txt'
    $networkFile = 'Baseline_Network_Snapshot.txt'
    $securityFile = 'Baseline_Security_Snapshot.txt'

    $runtimePath = Join-Path $EvidenceFolder $runtimeFile
    $networkPath = Join-Path $EvidenceFolder $networkFile
    $securityPath = Join-Path $EvidenceFolder $securityFile

    $runtimeBody = @"
BANNER        : $BannerText
RUN ID        : $RunStamp
SCRIPT VERSION: $ScriptVersion
GENERATED     : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
COMPUTER      : $env:COMPUTERNAME
USER          : $env:USERNAME
IS ADMIN      : $isAdmin
POWERSHELL    : $($PSVersionTable.PSVersion.ToString())
OS CAPTION    : $(if ($os) { $os.Caption } else { '<unknown>' })
OS VERSION    : $(if ($os) { $os.Version } else { '<unknown>' })
OS BUILD      : $(if ($os) { $os.BuildNumber } else { '<unknown>' })
DOMAIN        : $(if ($cs) { $cs.Domain } else { '<unknown>' })
MODEL         : $(if ($cs) { $cs.Model } else { '<unknown>' })
BIOS VERSION  : $(if ($bios) { [string](Prop $bios 'SMBIOSBIOSVersion') } else { '<unknown>' })
"@
    Set-Content -Path $runtimePath -Value $runtimeBody -Encoding UTF8
    $created.Add((Join-Path 'Evidence' $runtimeFile)) | Out-Null

    $ipconfigText = [string](Safe { (& ipconfig /all 2>&1 | Out-String) } 'ipconfig output unavailable.')
    $routeText = [string](Safe { (& route print 2>&1 | Out-String) } 'route output unavailable.')
    $arpText = [string](Safe { (& arp -a 2>&1 | Out-String) } 'arp output unavailable.')
    $networkBody = @"
BANNER: $BannerText
RUN ID: $RunStamp
TIME  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

=== IPCONFIG /ALL ===
$ipconfigText

=== ROUTE PRINT ===
$routeText

=== ARP -A ===
$arpText
"@
    Set-Content -Path $networkPath -Value $networkBody -Encoding UTF8
    $created.Add((Join-Path 'Evidence' $networkFile)) | Out-Null

    $adminMembers = if ($admins.Count -gt 0) {
        ($admins | ForEach-Object { [string](Prop $_ 'Name') } | Sort-Object -Unique) -join "`r`n"
    } else { '<none/unknown>' }
    $hotfixSample = if ($hotfixes.Count -gt 0) {
        ($hotfixes | Select-Object -First 40 | ForEach-Object { '{0} | {1}' -f [string](Prop $_ 'HotFixID'), [string](Prop $_ 'InstalledOn') }) -join "`r`n"
    } else { '<none/unknown>' }
    $listenSample = if ($listenTcp.Count -gt 0) {
        ($listenTcp | Select-Object -First 150 | ForEach-Object { '{0}:{1} | PID {2}' -f [string](Prop $_ 'LocalAddress'), [string](Prop $_ 'LocalPort'), [string](Prop $_ 'OwningProcess') }) -join "`r`n"
    } else { '<none/unknown>' }

    $securityBody = @"
BANNER: $BannerText
RUN ID: $RunStamp
TIME  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

=== LOCAL ADMINISTRATORS GROUP ===
$adminMembers

=== HOTFIX SAMPLE (TOP 40 RECENT) ===
$hotfixSample

=== LISTENING TCP PORTS (TOP 150) ===
$listenSample

=== DEFENDER RAW STATUS ===
$(RawText $mpStatus)
"@
    Set-Content -Path $securityPath -Value $securityBody -Encoding UTF8
    $created.Add((Join-Path 'Evidence' $securityFile)) | Out-Null

    return @($created.ToArray())
}

function Invoke-Check {
    param([int]$Id, $Check)

    $checkStart = Get-Date
    $actual = $null
    $status = 'ERROR'
    $note = ''
    $err = $null

    try {
        $actual = & $Check.Get
        $eval = & $Check.Test $actual
        if ($null -eq $eval) { $eval = EV 'INFO' 'Evaluator returned no result.' }
        $status = [string]$eval.Status
        if ([string]::IsNullOrWhiteSpace($status)) { $status = 'INFO' }
        $status = $status.ToUpperInvariant()
        $note = [string]$eval.Note
    } catch {
        $err = ($_ | Out-String).Trim()
        $actual = $err
        $status = 'ERROR'
        $note = 'Check execution failed.'
    }
    $checkEnd = Get-Date
    $durationMs = [math]::Round((New-TimeSpan -Start $checkStart -End $checkEnd).TotalMilliseconds, 2)
    $actualType = if ($null -eq $actual) { '<null>' } else { $actual.GetType().FullName }
    $actualShort = ShortText $actual

    $safeName = SafeFileName $Check.Name
    $fileName = 'Check_{0:D3}_{1}.txt' -f $Id, $safeName
    $relative = Join-Path 'Evidence' $fileName
    $path = Join-Path $EvidenceFolder $fileName

$evidence = @"
CHECK ID   : $Id
RUN ID     : $RunStamp
BANNER     : $BannerText
CATEGORY   : $($Check.Category)
HOST       : $env:COMPUTERNAME
USER       : $env:USERNAME
CHECK START: $($checkStart.ToString('yyyy-MM-dd HH:mm:ss.fff'))
CHECK END  : $($checkEnd.ToString('yyyy-MM-dd HH:mm:ss.fff'))
DURATIONMS : $durationMs
CHECK NAME : $($Check.Name)
EXPECTED   : $($Check.Expected)
COMMAND    : $($Check.Command)
STATUS     : $status
NOTE       : $note
ACTUALTYPE : $actualType
ACTUALSHORT: $actualShort

ACTUAL (RAW):
$(RawText $actual)
"@
    if ($err) { $evidence += "`r`nERROR:`r`n$err`r`n" }
    Set-Content -Path $path -Value $evidence -Encoding UTF8

    $obj = [pscustomobject]@{
        ID = '{0:D3}' -f $Id
        Category = $Check.Category
        Check = $Check.Name
        Expected = $Check.Expected
        Actual = ShortText $actual
        Status = $status
        Note = $note
        Command = $Check.Command
        Evidence = $relative
        DurationMs = $durationMs
        Computer = $env:COMPUTERNAME
        User = $env:USERNAME
        Time = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    }
    $script:Results.Add($obj) | Out-Null

    $colors = @{ PASS = 'Green'; FAIL = 'Red'; WARN = 'Yellow'; INFO = 'Cyan'; ERROR = 'Magenta' }
    $color = if ($colors.ContainsKey($status)) { $colors[$status] } else { 'White' }
    Write-Host ('[{0}] {1} [{2}] {3} ({4} ms)' -f $obj.ID, $obj.Check, $obj.Status, $obj.Actual, $durationMs) -ForegroundColor $color
    Add-Content -Path $TxtPath -Value ('[{0}] {1} | {2} | {3} | DurationMs={4}' -f $obj.ID, $obj.Check, $obj.Status, $obj.Actual, $durationMs)
}

# Runtime context / cache
$hasLocalUser = Cmd 'Get-LocalUser'
$hasLocalGroup = Cmd 'Get-LocalGroupMember'
$hasFirewall = Cmd 'Get-NetFirewallProfile'
$hasDefStatus = Cmd 'Get-MpComputerStatus'
$hasDefPref = Cmd 'Get-MpPreference'
$hasBitLocker = Cmd 'Get-BitLockerVolume'
$hasTasks = Cmd 'Get-ScheduledTask'

$os = Safe { Get-CimInstance Win32_OperatingSystem }
$cs = Safe { Get-CimInstance Win32_ComputerSystem }
$bios = Safe { Get-CimInstance Win32_BIOS }
$tpm = if (Cmd 'Get-Tpm') { Safe { Get-Tpm } } else { $null }
$secureBoot = if (Cmd 'Confirm-SecureBootUEFI') { Safe { Confirm-SecureBootUEFI } } else { $null }

$hotfixes = @(Safe { Get-HotFix | Sort-Object InstalledOn -Descending } @())
$localUsers = if ($hasLocalUser) { @(Safe { Get-LocalUser } @()) } else { @() }
$admins = GroupMembers 'Administrators'
$rdpUsers = GroupMembers 'Remote Desktop Users'
$rmUsers = GroupMembers 'Remote Management Users'
$powerUsers = GroupMembers 'Power Users'
$hyperVAdmins = GroupMembers 'Hyper-V Administrators'

$secpol = Get-SecPolicy
$auditText = [string](Safe { (& auditpol /get /category:* 2>$null | Out-String) } '')
$fwProfiles = if ($hasFirewall) { @(Safe { Get-NetFirewallProfile } @()) } else { @() }
$listenTcp = if (Cmd 'Get-NetTCPConnection') { @(Safe { Get-NetTCPConnection -State Listen } @()) } else { @() }

$mpStatus = if ($hasDefStatus) { Safe { Get-MpComputerStatus } } else { $null }
$mpPref = if ($hasDefPref) { Safe { Get-MpPreference } } else { $null }
$bitLocker = if ($hasBitLocker) { @(Safe { Get-BitLockerVolume } @()) } else { @() }
$deviceGuard = Safe { Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard }
$tasks = if ($hasTasks) { @(Safe { Get-ScheduledTask } @()) } else { @() }
$hiddenTasks = @($tasks | Where-Object { $_.Settings.Hidden -eq $true })

$currentUser = $env:USERNAME
$currentLocalUser = if ($hasLocalUser) { $localUsers | Where-Object { $_.Name -eq $currentUser } | Select-Object -First 1 } else { $null }
$currentUserIsAdmin = $false
try { $currentUserIsAdmin = (whoami /groups 2>$null | Select-String 'S-1-5-32-544').Count -gt 0 } catch { $currentUserIsAdmin = $false }

$enabledUsers = @($localUsers | Where-Object { (Prop $_ 'Enabled') -eq $true })
$noPwdReqUsers = @($localUsers | Where-Object { (Prop $_ 'PasswordRequired') -eq $false })
$pwdNeverExpireUsers = @($localUsers | Where-Object { (Prop $_ 'PasswordNeverExpires') -eq $true })
$inactiveEnabledUsers = @($localUsers | Where-Object { (Prop $_ 'Enabled') -eq $true -and (Prop $_ 'LastLogon') -and (Prop $_ 'LastLogon') -lt (Get-Date).AddDays(-90) })
$unknownAdminSids = @($admins | Where-Object { (Prop $_ 'Name') -match '^S-\d-\d+' -or (Prop $_ 'ObjectClass') -eq 'Unknown' })
$netbios = @(Safe { Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | Select-Object -ExpandProperty TcpipNetbiosOptions } @())

Write-Host 'Collecting baseline evidence snapshots...' -ForegroundColor DarkCyan
$baselineEvidence = @(Write-BaselineEvidence)
foreach ($path in $baselineEvidence) {
    $BaselineEvidencePaths.Add([string]$path) | Out-Null
    Add-Content -Path $TxtPath -Value ("[BASELINE] {0}" -f $path)
}

# -------------------------
# Check definitions
# -------------------------
# 1-10 System baseline
Add-CheckDef 'System' 'OS Caption' 'OS caption should be available.' '(Get-CimInstance Win32_OperatingSystem).Caption' {
    if ($os) { $os.Caption } else { $null }
} {
    param($v)
    if ([string]::IsNullOrWhiteSpace([string]$v)) { EV 'FAIL' 'OS caption unavailable.' } else { EV 'PASS' 'OS caption collected.' }
}

Add-CheckDef 'System' 'OS Version' 'OS version should be available.' '(Get-CimInstance Win32_OperatingSystem).Version' {
    if ($os) { $os.Version } else { $null }
} {
    param($v)
    if ([string]::IsNullOrWhiteSpace([string]$v)) { EV 'FAIL' 'OS version unavailable.' } else { EV 'PASS' 'OS version collected.' }
}

Add-CheckDef 'System' 'OS Build Number' 'Build should be >= 19041.' '(Get-CimInstance Win32_OperatingSystem).BuildNumber' {
    if ($os) { ToInt $os.BuildNumber } else { $null }
} {
    param($v)
    if ($null -eq $v) { EV 'WARN' 'Build number unavailable.' }
    elseif ($v -ge 19041) { EV 'PASS' 'Build baseline met.' }
    else { EV 'WARN' 'Build older than baseline.' }
}

Add-CheckDef 'System' 'OS Install Date' 'Install date should be available.' '(Get-CimInstance Win32_OperatingSystem).InstallDate' {
    if ($os) { $os.InstallDate } else { $null }
} {
    param($v)
    if ($null -eq $v) { EV 'WARN' 'Install date unavailable.' } else { EV 'PASS' 'Install date collected.' }
}

Add-CheckDef 'System' 'System Uptime Days' 'Uptime should ideally be <= 45 days.' '((Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime).TotalDays' {
    if ($os -and $os.LastBootUpTime) { [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays, 2) } else { $null }
} {
    param($v)
    if ($null -eq $v) { EV 'WARN' 'Uptime unavailable.' }
    elseif ($v -le 45) { EV 'PASS' 'Uptime in baseline.' }
    else { EV 'WARN' 'Long uptime detected.' }
}

Add-CheckDef 'System' 'OS Architecture' '64-bit OS expected.' '(Get-CimInstance Win32_OperatingSystem).OSArchitecture' {
    if ($os) { $os.OSArchitecture } else { $null }
} {
    param($v)
    if ([string]::IsNullOrWhiteSpace([string]$v)) { EV 'WARN' 'Architecture unavailable.' }
    elseif ([string]$v -match '64') { EV 'PASS' '64-bit architecture detected.' }
    else { EV 'WARN' 'Non 64-bit architecture detected.' }
}

Add-CheckDef 'System' 'Secure Boot' 'Secure Boot should be enabled.' 'Confirm-SecureBootUEFI' {
    $secureBoot
} {
    param($v)
    if ($null -eq $v) { EV 'WARN' 'Secure Boot state unavailable.' }
    elseif ($v -eq $true) { EV 'PASS' 'Secure Boot enabled.' }
    else { EV 'FAIL' 'Secure Boot disabled.' }
}

Add-CheckDef 'System' 'TPM Presence' 'TPM should be present.' '(Get-Tpm).TpmPresent' {
    if ($tpm) { Prop $tpm 'TpmPresent' } else { $null }
} {
    param($v)
    if ($null -eq $v) { EV 'WARN' 'TPM data unavailable.' }
    elseif ($v -eq $true) { EV 'PASS' 'TPM present.' }
    else { EV 'FAIL' 'TPM not present.' }
}

Add-CheckDef 'System' 'TPM Ready' 'TPM should be ready.' '(Get-Tpm).TpmReady' {
    if ($tpm) { Prop $tpm 'TpmReady' } else { $null }
} {
    param($v)
    if ($null -eq $v) { EV 'WARN' 'TPM readiness unavailable.' }
    elseif ($v -eq $true) { EV 'PASS' 'TPM ready.' }
    else { EV 'WARN' 'TPM not ready.' }
}

Add-CheckDef 'System' 'Domain or Workgroup Detection' 'Membership should be identified.' '(Get-CimInstance Win32_ComputerSystem).Domain / Workgroup' {
    if ($cs) {
        if ($cs.PartOfDomain) { "Domain: $($cs.Domain)" } else { "Workgroup: $($cs.Workgroup)" }
    } else {
        $null
    }
} {
    param($v)
    if ([string]::IsNullOrWhiteSpace([string]$v)) { EV 'WARN' 'Membership info unavailable.' }
    elseif ([string]$v -like 'Domain:*') { EV 'PASS' 'Domain membership identified.' }
    else { EV 'INFO' 'Workgroup mode detected.' }
}

# 11-20 Patch and update
Add-CheckDef 'Patch' 'Windows Update Startup Mode' 'wuauserv startup should not be Disabled.' '(Get-CimInstance Win32_Service -Filter "Name=''wuauserv''").StartMode' {
    ServiceMode 'wuauserv'
} {
    param($v)
    if ($null -eq $v) { EV 'WARN' 'wuauserv startup mode unavailable.' }
    elseif ($v -ne 'Disabled') { EV 'PASS' 'wuauserv startup mode acceptable.' }
    else { EV 'FAIL' 'wuauserv disabled.' }
}

Add-CheckDef 'Patch' 'Windows Update Service Status' 'wuauserv should be running.' '(Get-Service wuauserv).Status' {
    Safe { (Get-Service -Name 'wuauserv' -ErrorAction Stop).Status }
} {
    param($v)
    if ($null -eq $v) { EV 'WARN' 'wuauserv status unavailable.' }
    elseif ([string]$v -eq 'Running') { EV 'PASS' 'wuauserv running.' }
    else { EV 'WARN' 'wuauserv not running.' }
}

Add-CheckDef 'Patch' 'Update Orchestrator Startup Mode' 'UsoSvc startup should not be Disabled.' '(Get-CimInstance Win32_Service -Filter "Name=''UsoSvc''").StartMode' {
    ServiceMode 'UsoSvc'
} {
    param($v)
    if ($null -eq $v) { EV 'WARN' 'UsoSvc startup mode unavailable.' }
    elseif ($v -ne 'Disabled') { EV 'PASS' 'UsoSvc startup mode acceptable.' }
    else { EV 'WARN' 'UsoSvc disabled.' }
}

Add-CheckDef 'Patch' 'Installed Hotfix Count' 'Hotfix count should be >= 20.' '(Get-HotFix).Count' {
    $hotfixes.Count
} {
    param($v)
    if ($v -ge 20) { EV 'PASS' 'Hotfix count baseline met.' } else { EV 'WARN' 'Hotfix count below baseline.' }
}

Add-CheckDef 'Patch' 'Latest Hotfix Age (Days)' 'Latest hotfix should be <= 60 days old.' '((Get-Date)-((Get-HotFix|Sort InstalledOn -Desc)[0].InstalledOn)).Days' {
    $latest = $hotfixes | Where-Object { $_.InstalledOn } | Select-Object -First 1
    if ($latest) { [int]([math]::Round(((Get-Date) - $latest.InstalledOn).TotalDays, 0)) } else { $null }
} {
    param($v)
    if ($null -eq $v) { EV 'WARN' 'Latest hotfix age unavailable.' }
    elseif ($v -le 60) { EV 'PASS' 'Hotfix recency healthy.' }
    elseif ($v -le 120) { EV 'WARN' 'Hotfix recency aging.' }
    else { EV 'FAIL' 'Hotfix recency poor.' }
}

Add-CheckDef 'Patch' 'Pending Reboot State' 'No pending reboot should exist.' 'Pending reboot registry keys' {
    PendingReboot
} {
    param($v)
    if ($v -eq $false) { EV 'PASS' 'No pending reboot.' } else { EV 'FAIL' 'Pending reboot detected.' }
}

Add-CheckDef 'Patch' 'Automatic Update Mode (AUOptions)' 'AUOptions should be 3 or 4.' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\AUOptions' {
    $x = RegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' 'AUOptions'
    if ($null -eq $x) { $x = RegVal 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' 'AUOptions' }
    ToInt $x
} {
    param($v)
    if ($null -eq $v) { EV 'WARN' 'AUOptions not explicitly configured.' }
    elseif ($v -in 3, 4) { EV 'PASS' 'AUOptions baseline met.' }
    else { EV 'WARN' 'AUOptions outside preferred baseline.' }
}

Add-CheckDef 'Patch' 'NoAutoUpdate Policy' 'NoAutoUpdate should not be enabled.' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAutoUpdate' {
    ToInt (RegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' 'NoAutoUpdate')
} {
    param($v)
    if ($null -eq $v -or $v -eq 0) { EV 'PASS' 'NoAutoUpdate does not disable patching.' }
    else { EV 'FAIL' 'NoAutoUpdate disables patching.' }
}

Add-CheckDef 'Patch' 'WSUS Server Setting' 'WSUS configuration should be documented.' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\WUServer' {
    RegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'WUServer'
} {
    param($v)
    if ([string]::IsNullOrWhiteSpace([string]$v)) { EV 'INFO' 'WSUS not configured (likely direct Microsoft Update).' }
    else { EV 'PASS' 'WSUS configured.' }
}

Add-CheckDef 'Patch' 'Delivery Optimization Startup Mode' 'DoSvc startup should not be Disabled.' '(Get-CimInstance Win32_Service -Filter "Name=''DoSvc''").StartMode' {
    ServiceMode 'DoSvc'
} {
    param($v)
    if ($null -eq $v) { EV 'WARN' 'DoSvc startup mode unavailable.' }
    elseif ($v -ne 'Disabled') { EV 'PASS' 'DoSvc startup mode acceptable.' }
    else { EV 'WARN' 'DoSvc disabled.' }
}

# 21-35 Accounts and privilege
Add-CheckDef 'Account' 'Local User Count' 'Total local users should be <= 20.' '(Get-LocalUser).Count' {
    if ($hasLocalUser) { $localUsers.Count } else { $null }
} {
    param($v)
    if (-not $hasLocalUser) { EV 'WARN' 'Get-LocalUser not available.' }
    elseif ($v -le 20) { EV 'PASS' 'Local user count controlled.' }
    else { EV 'WARN' 'High local user count.' }
}

Add-CheckDef 'Account' 'Enabled Local User Count' 'Enabled local users should be <= 10.' '(Get-LocalUser | ? Enabled).Count' {
    if ($hasLocalUser) { $enabledUsers.Count } else { $null }
} {
    param($v)
    if (-not $hasLocalUser) { EV 'WARN' 'Get-LocalUser not available.' }
    elseif ($v -le 10) { EV 'PASS' 'Enabled user count controlled.' }
    else { EV 'WARN' 'Too many enabled local users.' }
}

Add-CheckDef 'Account' 'Guest Account Disabled' 'Guest account should be disabled.' '(Get-LocalUser Guest).Enabled' {
    if (-not $hasLocalUser) { $null }
    else {
        $g = $localUsers | Where-Object { $_.Name -eq 'Guest' } | Select-Object -First 1
        if ($g) { Prop $g 'Enabled' } else { 'NotPresent' }
    }
} {
    param($v)
    if (-not $hasLocalUser) { EV 'WARN' 'Get-LocalUser not available.' }
    elseif ($v -eq 'NotPresent' -or $v -eq $false) { EV 'PASS' 'Guest account not enabled.' }
    else { EV 'FAIL' 'Guest account enabled.' }
}

Add-CheckDef 'Account' 'Built-in Administrator Disabled' 'Administrator account should be disabled.' '(Get-LocalUser Administrator).Enabled' {
    if (-not $hasLocalUser) { $null }
    else {
        $a = $localUsers | Where-Object { $_.Name -eq 'Administrator' } | Select-Object -First 1
        if ($a) { Prop $a 'Enabled' } else { 'NotPresent' }
    }
} {
    param($v)
    if (-not $hasLocalUser) { EV 'WARN' 'Get-LocalUser not available.' }
    elseif ($v -eq 'NotPresent') { EV 'WARN' 'Built-in Administrator not found (possibly renamed).' }
    elseif ($v -eq $false) { EV 'PASS' 'Built-in Administrator disabled.' }
    else { EV 'FAIL' 'Built-in Administrator enabled.' }
}

Add-CheckDef 'Privilege' 'Administrators Group Member Count' 'Administrators group should have <= 5 members.' '(Get-LocalGroupMember Administrators).Count' {
    if ($hasLocalGroup) { $admins.Count } else { $null }
} {
    param($v)
    if (-not $hasLocalGroup) { EV 'WARN' 'Get-LocalGroupMember not available.' }
    elseif ($v -le 5) { EV 'PASS' 'Administrators group size controlled.' }
    else { EV 'FAIL' 'Too many administrators.' }
}

Add-CheckDef 'Account' 'Password Required Disabled Accounts' 'Accounts without password requirement should be 0.' '(Get-LocalUser | ? PasswordRequired -eq $false).Count' {
    if ($hasLocalUser) { $noPwdReqUsers.Count } else { $null }
} {
    param($v)
    if (-not $hasLocalUser) { EV 'WARN' 'Get-LocalUser not available.' }
    elseif ($v -eq 0) { EV 'PASS' 'All local accounts require passwords.' }
    else { EV 'FAIL' 'Accounts without password requirement found.' }
}

Add-CheckDef 'Account' 'Password Never Expires Accounts' 'PasswordNeverExpires should be <= 1 local account.' '(Get-LocalUser | ? PasswordNeverExpires).Count' {
    if ($hasLocalUser) { $pwdNeverExpireUsers.Count } else { $null }
} {
    param($v)
    if (-not $hasLocalUser) { EV 'WARN' 'Get-LocalUser not available.' }
    elseif ($v -le 1) { EV 'PASS' 'Password expiration policy mostly enforced.' }
    else { EV 'WARN' 'Multiple non-expiring local passwords.' }
}

Add-CheckDef 'Account' 'Inactive Enabled Local Accounts (>90 Days)' 'Inactive enabled local accounts should be 0.' '(Get-LocalUser | ? { $_.Enabled -and $_.LastLogon -lt (Get-Date).AddDays(-90) }).Count' {
    if ($hasLocalUser) { $inactiveEnabledUsers.Count } else { $null }
} {
    param($v)
    if (-not $hasLocalUser) { EV 'WARN' 'Get-LocalUser not available.' }
    elseif ($v -eq 0) { EV 'PASS' 'No stale enabled local users.' }
    else { EV 'WARN' 'Stale enabled local users detected.' }
}

Add-CheckDef 'Privilege' 'Remote Desktop Users Group Size' 'Remote Desktop Users should have <= 3 members.' '(Get-LocalGroupMember "Remote Desktop Users").Count' {
    if ($hasLocalGroup) { $rdpUsers.Count } else { $null }
} {
    param($v)
    if (-not $hasLocalGroup) { EV 'WARN' 'Get-LocalGroupMember not available.' }
    elseif ($v -le 3) { EV 'PASS' 'Remote Desktop Users group controlled.' }
    else { EV 'WARN' 'Too many Remote Desktop Users.' }
}

Add-CheckDef 'Privilege' 'Remote Management Users Group Size' 'Remote Management Users should be empty.' '(Get-LocalGroupMember "Remote Management Users").Count' {
    if ($hasLocalGroup) { $rmUsers.Count } else { $null }
} {
    param($v)
    if (-not $hasLocalGroup) { EV 'WARN' 'Get-LocalGroupMember not available.' }
    elseif ($v -eq 0) { EV 'PASS' 'Remote Management Users group empty.' }
    else { EV 'WARN' 'Remote Management Users has members.' }
}

Add-CheckDef 'Privilege' 'Power Users Group Size' 'Power Users should be empty.' '(Get-LocalGroupMember "Power Users").Count' {
    if ($hasLocalGroup) { $powerUsers.Count } else { $null }
} {
    param($v)
    if (-not $hasLocalGroup) { EV 'WARN' 'Get-LocalGroupMember not available.' }
    elseif ($v -eq 0) { EV 'PASS' 'Power Users group empty.' }
    else { EV 'WARN' 'Power Users has members.' }
}

Add-CheckDef 'Privilege' 'Hyper-V Administrators Group Size' 'Hyper-V Administrators should be empty unless needed.' '(Get-LocalGroupMember "Hyper-V Administrators").Count' {
    if ($hasLocalGroup) { $hyperVAdmins.Count } else { $null }
} {
    param($v)
    if (-not $hasLocalGroup) { EV 'WARN' 'Get-LocalGroupMember not available.' }
    elseif ($v -eq 0) { EV 'PASS' 'Hyper-V Administrators group empty.' }
    else { EV 'WARN' 'Hyper-V Administrators has members.' }
}

Add-CheckDef 'Privilege' 'Current User Local Administrator Rights' 'Daily account should ideally be non-admin.' 'whoami /groups | Select-String S-1-5-32-544' {
    $currentUserIsAdmin
} {
    param($v)
    if ($v -eq $false) { EV 'PASS' 'Current user not local admin.' } else { EV 'WARN' 'Current user is local admin.' }
}

Add-CheckDef 'Account' 'Current User Password Age (Days)' 'Password age should ideally be <= 365 days.' '(Get-LocalUser $env:USERNAME).PasswordLastSet' {
    $pwdSet = Prop $currentLocalUser 'PasswordLastSet'
    if ($currentLocalUser -and $pwdSet) {
        [int]([math]::Round(((Get-Date) - $pwdSet).TotalDays, 0))
    } else {
        $null
    }
} {
    param($v)
    if ($null -eq $v) { EV 'INFO' 'Password age unavailable for current user context.' }
    elseif ($v -le 365) { EV 'PASS' 'Current user password age acceptable.' }
    else { EV 'WARN' 'Current user password older than 365 days.' }
}

Add-CheckDef 'Privilege' 'Unknown SID Entries in Administrators Group' 'Unknown SID members should be 0.' '(Get-LocalGroupMember Administrators | ? Name -match "^S-").Count' {
    if ($hasLocalGroup) { $unknownAdminSids.Count } else { $null }
} {
    param($v)
    if (-not $hasLocalGroup) { EV 'WARN' 'Get-LocalGroupMember not available.' }
    elseif ($v -eq 0) { EV 'PASS' 'No unknown SID admin members.' }
    else { EV 'WARN' 'Unknown SID admin members found.' }
}
# 36-45 Password and lockout policy
Add-CheckDef 'Policy' 'Password Complexity Policy' 'PasswordComplexity should be 1.' 'secedit export -> PasswordComplexity' {
    ToInt (SecVal $secpol 'PasswordComplexity')
} {
    param($v)
    if ($null -eq $v) { EV 'WARN' 'PasswordComplexity unavailable.' }
    elseif ($v -eq 1) { EV 'PASS' 'Password complexity enabled.' }
    else { EV 'FAIL' 'Password complexity disabled.' }
}

Add-CheckDef 'Policy' 'Minimum Password Length Policy' 'MinimumPasswordLength should be >= 12.' 'secedit export -> MinimumPasswordLength' {
    ToInt (SecVal $secpol 'MinimumPasswordLength')
} {
    param($v)
    if ($null -eq $v) { EV 'WARN' 'MinimumPasswordLength unavailable.' }
    elseif ($v -ge 12) { EV 'PASS' 'Minimum password length meets baseline.' }
    else { EV 'FAIL' 'Minimum password length below baseline.' }
}

Add-CheckDef 'Policy' 'Password History Policy' 'PasswordHistorySize should be >= 12.' 'secedit export -> PasswordHistorySize' {
    ToInt (SecVal $secpol 'PasswordHistorySize')
} {
    param($v)
    if ($null -eq $v) { EV 'WARN' 'PasswordHistorySize unavailable.' }
    elseif ($v -ge 12) { EV 'PASS' 'Password history baseline met.' }
    else { EV 'FAIL' 'Password history baseline not met.' }
}

Add-CheckDef 'Policy' 'Maximum Password Age Policy' 'MaximumPasswordAge should be between 1 and 90.' 'secedit export -> MaximumPasswordAge' {
    ToInt (SecVal $secpol 'MaximumPasswordAge')
} {
    param($v)
    if ($null -eq $v) { EV 'WARN' 'MaximumPasswordAge unavailable.' }
    elseif ($v -ge 1 -and $v -le 90) { EV 'PASS' 'Maximum password age baseline met.' }
    else { EV 'FAIL' 'Maximum password age outside baseline.' }
}

Add-CheckDef 'Policy' 'Minimum Password Age Policy' 'MinimumPasswordAge should be >= 1.' 'secedit export -> MinimumPasswordAge' {
    ToInt (SecVal $secpol 'MinimumPasswordAge')
} {
    param($v)
    if ($null -eq $v) { EV 'WARN' 'MinimumPasswordAge unavailable.' }
    elseif ($v -ge 1) { EV 'PASS' 'Minimum password age baseline met.' }
    else { EV 'WARN' 'Minimum password age weak.' }
}

Add-CheckDef 'Policy' 'Account Lockout Threshold Policy' 'LockoutBadCount should be between 3 and 10.' 'secedit export -> LockoutBadCount' {
    ToInt (SecVal $secpol 'LockoutBadCount')
} {
    param($v)
    if ($null -eq $v) { EV 'WARN' 'LockoutBadCount unavailable.' }
    elseif ($v -ge 3 -and $v -le 10) { EV 'PASS' 'Lockout threshold baseline met.' }
    else { EV 'FAIL' 'Lockout threshold outside baseline.' }
}

Add-CheckDef 'Policy' 'Account Lockout Duration Policy' 'LockoutDuration should be >= 15 minutes (or -1).' 'secedit export -> LockoutDuration' {
    ToInt (SecVal $secpol 'LockoutDuration')
} {
    param($v)
    if ($null -eq $v) { EV 'WARN' 'LockoutDuration unavailable.' }
    elseif ($v -eq -1 -or $v -ge 15) { EV 'PASS' 'Lockout duration baseline met.' }
    else { EV 'WARN' 'Lockout duration below baseline.' }
}

Add-CheckDef 'Policy' 'Reset Lockout Counter Policy' 'ResetLockoutCount should be >= 15 minutes.' 'secedit export -> ResetLockoutCount' {
    ToInt (SecVal $secpol 'ResetLockoutCount')
} {
    param($v)
    if ($null -eq $v) { EV 'WARN' 'ResetLockoutCount unavailable.' }
    elseif ($v -ge 15) { EV 'PASS' 'Reset lockout counter baseline met.' }
    else { EV 'WARN' 'Reset lockout counter below baseline.' }
}

Add-CheckDef 'Policy' 'Store Passwords with Reversible Encryption' 'ClearTextPassword should be 0.' 'secedit export -> ClearTextPassword' {
    ToInt (SecVal $secpol 'ClearTextPassword')
} {
    param($v)
    if ($null -eq $v) { EV 'WARN' 'ClearTextPassword setting unavailable.' }
    elseif ($v -eq 0) { EV 'PASS' 'Reversible password storage disabled.' }
    else { EV 'FAIL' 'Reversible password storage enabled.' }
}

Add-CheckDef 'Policy' 'Limit Blank Password Use' 'LimitBlankPasswordUse should be 1.' 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse' {
    ToInt (RegVal 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LimitBlankPasswordUse')
} {
    param($v)
    if ($null -eq $v) { EV 'WARN' 'LimitBlankPasswordUse unavailable.' }
    elseif ($v -eq 1) { EV 'PASS' 'Blank password use is restricted.' }
    else { EV 'FAIL' 'Blank password use is not restricted.' }
}

# 46-55 Audit policy and logs
Add-CheckDef 'Audit' 'Audit Logon Policy' 'Logon should audit Success and Failure.' 'auditpol /get /subcategory:"Logon"' {
    AuditSub $auditText 'Logon'
} {
    param($v)
    if ([string]::IsNullOrWhiteSpace([string]$v)) { EV 'WARN' 'Logon audit setting unavailable.' }
    elseif ($v -match 'Success' -and $v -match 'Failure') { EV 'PASS' 'Logon auditing includes Success and Failure.' }
    else { EV 'WARN' 'Logon auditing not fully configured.' }
}

Add-CheckDef 'Audit' 'Audit Account Logon Policy' 'Credential Validation should audit Success and Failure.' 'auditpol /get /subcategory:"Credential Validation"' {
    AuditSub $auditText 'Credential Validation'
} {
    param($v)
    if ([string]::IsNullOrWhiteSpace([string]$v)) { EV 'WARN' 'Credential Validation setting unavailable.' }
    elseif ($v -match 'Success' -and $v -match 'Failure') { EV 'PASS' 'Credential Validation audits Success and Failure.' }
    else { EV 'WARN' 'Credential Validation not fully configured.' }
}

Add-CheckDef 'Audit' 'Audit Account Management Policy' 'User Account Management should audit Success and Failure.' 'auditpol /get /subcategory:"User Account Management"' {
    AuditSub $auditText 'User Account Management'
} {
    param($v)
    if ([string]::IsNullOrWhiteSpace([string]$v)) { EV 'WARN' 'User Account Management setting unavailable.' }
    elseif ($v -match 'Success' -and $v -match 'Failure') { EV 'PASS' 'User Account Management audits Success and Failure.' }
    else { EV 'WARN' 'User Account Management not fully configured.' }
}

Add-CheckDef 'Audit' 'Audit Policy Change Policy' 'Audit Policy Change should audit Success and Failure.' 'auditpol /get /subcategory:"Audit Policy Change"' {
    AuditSub $auditText 'Audit Policy Change'
} {
    param($v)
    if ([string]::IsNullOrWhiteSpace([string]$v)) { EV 'WARN' 'Audit Policy Change setting unavailable.' }
    elseif ($v -match 'Success' -and $v -match 'Failure') { EV 'PASS' 'Audit Policy Change audits Success and Failure.' }
    else { EV 'WARN' 'Audit Policy Change not fully configured.' }
}

Add-CheckDef 'Audit' 'Audit System Policy' 'Security System Extension should audit Success and Failure.' 'auditpol /get /subcategory:"Security System Extension"' {
    AuditSub $auditText 'Security System Extension'
} {
    param($v)
    if ([string]::IsNullOrWhiteSpace([string]$v)) { EV 'WARN' 'Security System Extension setting unavailable.' }
    elseif ($v -match 'Success' -and $v -match 'Failure') { EV 'PASS' 'Security System Extension audits Success and Failure.' }
    else { EV 'WARN' 'Security System Extension not fully configured.' }
}

Add-CheckDef 'Audit' 'Security Log Maximum Size (KB)' 'Security log max size should be >= 65536 KB.' '(Get-WinEvent -ListLog Security).MaximumSizeInBytes/1KB' {
    $log = Safe { Get-WinEvent -ListLog 'Security' }
    if ($log) { [int]([math]::Round($log.MaximumSizeInBytes / 1KB, 0)) } else { $null }
} {
    param($v)
    if ($null -eq $v) { EV 'WARN' 'Security log size unavailable.' }
    elseif ($v -ge 65536) { EV 'PASS' 'Security log size baseline met.' }
    else { EV 'WARN' 'Security log size below baseline.' }
}

Add-CheckDef 'Audit' 'Application Log Maximum Size (KB)' 'Application log max size should be >= 32768 KB.' '(Get-WinEvent -ListLog Application).MaximumSizeInBytes/1KB' {
    $log = Safe { Get-WinEvent -ListLog 'Application' }
    if ($log) { [int]([math]::Round($log.MaximumSizeInBytes / 1KB, 0)) } else { $null }
} {
    param($v)
    if ($null -eq $v) { EV 'WARN' 'Application log size unavailable.' }
    elseif ($v -ge 32768) { EV 'PASS' 'Application log size baseline met.' }
    else { EV 'WARN' 'Application log size below baseline.' }
}

Add-CheckDef 'Audit' 'System Log Maximum Size (KB)' 'System log max size should be >= 32768 KB.' '(Get-WinEvent -ListLog System).MaximumSizeInBytes/1KB' {
    $log = Safe { Get-WinEvent -ListLog 'System' }
    if ($log) { [int]([math]::Round($log.MaximumSizeInBytes / 1KB, 0)) } else { $null }
} {
    param($v)
    if ($null -eq $v) { EV 'WARN' 'System log size unavailable.' }
    elseif ($v -ge 32768) { EV 'PASS' 'System log size baseline met.' }
    else { EV 'WARN' 'System log size below baseline.' }
}

Add-CheckDef 'Audit' 'Event Log Service Status' 'EventLog service should be running.' '(Get-Service EventLog).Status' {
    Safe { (Get-Service -Name 'EventLog' -ErrorAction Stop).Status }
} {
    param($v)
    if ($null -eq $v) { EV 'WARN' 'EventLog service status unavailable.' }
    elseif ([string]$v -eq 'Running') { EV 'PASS' 'EventLog service running.' }
    else { EV 'FAIL' 'EventLog service not running.' }
}

Add-CheckDef 'Audit' 'Critical Events in Last 24 Hours' 'Critical event count should be 0.' 'Get-WinEvent -FilterHashtable @{LogName="System|Application";Level=1;StartTime=(Get-Date).AddHours(-24)}' {
    $start = (Get-Date).AddHours(-24)
    $sys = @(Safe { Get-WinEvent -FilterHashtable @{ LogName = 'System'; Level = 1; StartTime = $start } } @())
    $app = @(Safe { Get-WinEvent -FilterHashtable @{ LogName = 'Application'; Level = 1; StartTime = $start } } @())
    $sys.Count + $app.Count
} {
    param($v)
    if ($null -eq $v) { EV 'WARN' 'Critical event count unavailable.' }
    elseif ($v -eq 0) { EV 'PASS' 'No critical events in last 24h.' }
    else { EV 'WARN' 'Critical events found in last 24h.' }
}

# 56-70 Network and firewall
Add-CheckDef 'Firewall' 'Domain Firewall Profile Enabled' 'Domain firewall profile should be enabled.' '(Get-NetFirewallProfile -Name Domain).Enabled' {
    if (-not $hasFirewall) { $null } else { ($fwProfiles | Where-Object { $_.Name -eq 'Domain' } | Select-Object -First 1).Enabled }
} {
    param($v)
    if (-not $hasFirewall) { EV 'WARN' 'Get-NetFirewallProfile not available.' }
    elseif ($null -eq $v) { EV 'INFO' 'Domain profile unavailable.' }
    elseif ($v -eq $true) { EV 'PASS' 'Domain firewall enabled.' }
    else { EV 'FAIL' 'Domain firewall disabled.' }
}

Add-CheckDef 'Firewall' 'Private Firewall Profile Enabled' 'Private firewall profile should be enabled.' '(Get-NetFirewallProfile -Name Private).Enabled' {
    if (-not $hasFirewall) { $null } else { ($fwProfiles | Where-Object { $_.Name -eq 'Private' } | Select-Object -First 1).Enabled }
} {
    param($v)
    if (-not $hasFirewall) { EV 'WARN' 'Get-NetFirewallProfile not available.' }
    elseif ($null -eq $v) { EV 'WARN' 'Private profile unavailable.' }
    elseif ($v -eq $true) { EV 'PASS' 'Private firewall enabled.' }
    else { EV 'FAIL' 'Private firewall disabled.' }
}

Add-CheckDef 'Firewall' 'Public Firewall Profile Enabled' 'Public firewall profile should be enabled.' '(Get-NetFirewallProfile -Name Public).Enabled' {
    if (-not $hasFirewall) { $null } else { ($fwProfiles | Where-Object { $_.Name -eq 'Public' } | Select-Object -First 1).Enabled }
} {
    param($v)
    if (-not $hasFirewall) { EV 'WARN' 'Get-NetFirewallProfile not available.' }
    elseif ($null -eq $v) { EV 'WARN' 'Public profile unavailable.' }
    elseif ($v -eq $true) { EV 'PASS' 'Public firewall enabled.' }
    else { EV 'FAIL' 'Public firewall disabled.' }
}

Add-CheckDef 'Firewall' 'Default Inbound Firewall Action' 'All profiles should block inbound by default.' '(Get-NetFirewallProfile).DefaultInboundAction' {
    if (-not $hasFirewall) { $null } else { @($fwProfiles | Select-Object -ExpandProperty DefaultInboundAction) }
} {
    param($v)
    if (-not $hasFirewall) { EV 'WARN' 'Get-NetFirewallProfile not available.' }
    elseif ($null -eq $v -or @($v).Count -eq 0) { EV 'WARN' 'Inbound default action unavailable.' }
    elseif (@($v | Where-Object { $_ -eq 'Allow' }).Count -eq 0) { EV 'PASS' 'Inbound default action is block.' }
    else { EV 'FAIL' 'One or more profiles allow inbound by default.' }
}

Add-CheckDef 'Firewall' 'Public Firewall Log Dropped Packets' 'Public profile should log dropped packets.' '(Get-NetFirewallProfile -Name Public).LogBlocked' {
    if (-not $hasFirewall) { $null } else { ($fwProfiles | Where-Object { $_.Name -eq 'Public' } | Select-Object -First 1).LogBlocked }
} {
    param($v)
    if (-not $hasFirewall) { EV 'WARN' 'Get-NetFirewallProfile not available.' }
    elseif ($null -eq $v) { EV 'WARN' 'Public log blocked setting unavailable.' }
    elseif ($v -eq $true) { EV 'PASS' 'Dropped packet logging enabled.' }
    else { EV 'WARN' 'Dropped packet logging disabled.' }
}

Add-CheckDef 'Network' 'Listening TCP Ports Count' 'Listening TCP ports should be <= 30.' '(Get-NetTCPConnection -State Listen).Count' {
    if ($listenTcp.Count -gt 0) { $listenTcp.Count } else { (Safe { (netstat -ano 2>$null | Select-String 'LISTENING').Count } 0) }
} {
    param($v)
    if ($v -le 30) { EV 'PASS' 'Listening port count baseline met.' }
    elseif ($v -le 60) { EV 'WARN' 'Listening port count above baseline.' }
    else { EV 'FAIL' 'Listening port count high.' }
}

Add-CheckDef 'Network' 'RDP Disabled Policy' 'fDenyTSConnections should be 1.' 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\fDenyTSConnections' {
    ToInt (RegVal 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections')
} {
    param($v)
    if ($null -eq $v) { EV 'WARN' 'RDP policy value unavailable.' }
    elseif ($v -eq 1) { EV 'PASS' 'RDP disabled.' }
    else { EV 'WARN' 'RDP enabled.' }
}

Add-CheckDef 'Network' 'RDP NLA Requirement' 'If RDP enabled, NLA should be required.' 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\UserAuthentication' {
    @{ RdpDisabled = ToInt (RegVal 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'); Nla = ToInt (RegVal 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication') }
} {
    param($v)
    if ($null -eq $v) { EV 'WARN' 'RDP/NLA values unavailable.' }
    elseif ($v.RdpDisabled -eq 1) { EV 'PASS' 'RDP disabled; NLA condition satisfied.' }
    elseif ($v.Nla -eq 1) { EV 'PASS' 'RDP enabled with NLA.' }
    else { EV 'FAIL' 'RDP enabled without NLA.' }
}

Add-CheckDef 'Network' 'SMBv1 Disabled' 'SMB1 protocol should be disabled.' 'Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol' {
    if (Cmd 'Get-WindowsOptionalFeature') {
        [string](Safe { (Get-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -ErrorAction Stop).State })
    } else {
        ToInt (RegVal 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1')
    }
} {
    param($v)
    if ($null -eq $v) { EV 'WARN' 'SMB1 state unavailable.' }
    elseif ([string]$v -eq 'Disabled' -or $v -eq 0) { EV 'PASS' 'SMB1 disabled.' }
    else { EV 'FAIL' 'SMB1 enabled.' }
}

Add-CheckDef 'Network' 'SMB Server Signing Required' 'RequireSecuritySignature should be 1 for LanmanServer.' 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\RequireSecuritySignature' {
    ToInt (RegVal 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RequireSecuritySignature')
} {
    param($v)
    if ($null -eq $v) { EV 'WARN' 'SMB server signing setting unavailable.' }
    elseif ($v -eq 1) { EV 'PASS' 'SMB server signing required.' }
    else { EV 'FAIL' 'SMB server signing not required.' }
}

Add-CheckDef 'Network' 'SMB Client Signing Required' 'RequireSecuritySignature should be 1 for LanmanWorkstation.' 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature' {
    ToInt (RegVal 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'RequireSecuritySignature')
} {
    param($v)
    if ($null -eq $v) { EV 'WARN' 'SMB client signing setting unavailable.' }
    elseif ($v -eq 1) { EV 'PASS' 'SMB client signing required.' }
    else { EV 'WARN' 'SMB client signing not required.' }
}

Add-CheckDef 'Network' 'LLMNR Disabled' 'EnableMulticast should be 0.' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast' {
    ToInt (RegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast')
} {
    param($v)
    if ($null -eq $v) { EV 'WARN' 'LLMNR policy not configured.' }
    elseif ($v -eq 0) { EV 'PASS' 'LLMNR disabled.' }
    else { EV 'WARN' 'LLMNR enabled.' }
}

Add-CheckDef 'Network' 'NetBIOS Disabled on Active NICs' 'All active adapters should use TcpipNetbiosOptions=2.' 'Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" | Select TcpipNetbiosOptions' {
    if ($netbios.Count -eq 0) { $null } else { $netbios }
} {
    param($v)
    if ($null -eq $v) { EV 'WARN' 'NetBIOS values unavailable.' }
    else {
        $items = @($v)
        if ($items.Count -eq 0) { EV 'WARN' 'No active adapters for NetBIOS check.' }
        elseif (@($items | Where-Object { $_ -ne 2 }).Count -eq 0) { EV 'PASS' 'NetBIOS disabled on active adapters.' }
        else { EV 'WARN' 'One or more adapters do not disable NetBIOS explicitly.' }
    }
}

Add-CheckDef 'Network' 'WinRM Service Status' 'WinRM should not be running unless required.' '(Get-Service WinRM).Status' {
    Safe { (Get-Service -Name 'WinRM' -ErrorAction Stop).Status }
} {
    param($v)
    if ($null -eq $v) { EV 'INFO' 'WinRM service not found.' }
    elseif ([string]$v -ne 'Running') { EV 'PASS' 'WinRM not running.' }
    else { EV 'WARN' 'WinRM running.' }
}

Add-CheckDef 'Network' 'WPAD Disabled' 'DisableWpad should be 1.' 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp\DisableWpad' {
    ToInt (RegVal 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' 'DisableWpad')
} {
    param($v)
    if ($null -eq $v) { EV 'WARN' 'WPAD setting unavailable.' }
    elseif ($v -eq 1) { EV 'PASS' 'WPAD disabled.' }
    else { EV 'WARN' 'WPAD enabled.' }
}
# 71-85 Defender and endpoint
Add-CheckDef 'Defender' 'Defender Service Status' 'WinDefend service should be running.' '(Get-Service WinDefend).Status' {
    Safe { (Get-Service -Name 'WinDefend' -ErrorAction Stop).Status }
} {
    param($v)
    if ($null -eq $v) { EV 'WARN' 'Defender service not found.' }
    elseif ([string]$v -eq 'Running') { EV 'PASS' 'Defender service running.' }
    else { EV 'FAIL' 'Defender service not running.' }
}

Add-CheckDef 'Defender' 'Defender AM Service Enabled' 'AMServiceEnabled should be True.' '(Get-MpComputerStatus).AMServiceEnabled' {
    if ($mpStatus) { Prop $mpStatus 'AMServiceEnabled' } else { $null }
} {
    param($v)
    if (-not $hasDefStatus) { EV 'WARN' 'Get-MpComputerStatus not available.' }
    elseif ($null -eq $v) { EV 'WARN' 'AMServiceEnabled unavailable.' }
    elseif ($v -eq $true) { EV 'PASS' 'AM service enabled.' }
    else { EV 'FAIL' 'AM service disabled.' }
}

Add-CheckDef 'Defender' 'Antivirus Enabled' 'AntivirusEnabled should be True.' '(Get-MpComputerStatus).AntivirusEnabled' {
    if ($mpStatus) { Prop $mpStatus 'AntivirusEnabled' } else { $null }
} {
    param($v)
    if (-not $hasDefStatus) { EV 'WARN' 'Get-MpComputerStatus not available.' }
    elseif ($null -eq $v) { EV 'WARN' 'AntivirusEnabled unavailable.' }
    elseif ($v -eq $true) { EV 'PASS' 'Antivirus enabled.' }
    else { EV 'FAIL' 'Antivirus disabled.' }
}

Add-CheckDef 'Defender' 'Real-Time Protection Enabled' 'RealTimeProtectionEnabled should be True.' '(Get-MpComputerStatus).RealTimeProtectionEnabled' {
    if ($mpStatus) { Prop $mpStatus 'RealTimeProtectionEnabled' } else { $null }
} {
    param($v)
    if (-not $hasDefStatus) { EV 'WARN' 'Get-MpComputerStatus not available.' }
    elseif ($null -eq $v) { EV 'WARN' 'RealTimeProtectionEnabled unavailable.' }
    elseif ($v -eq $true) { EV 'PASS' 'Real-time protection enabled.' }
    else { EV 'FAIL' 'Real-time protection disabled.' }
}

Add-CheckDef 'Defender' 'Behavior Monitoring Enabled' 'BehaviorMonitorEnabled should be True.' '(Get-MpComputerStatus).BehaviorMonitorEnabled' {
    if ($mpStatus) { Prop $mpStatus 'BehaviorMonitorEnabled' } else { $null }
} {
    param($v)
    if (-not $hasDefStatus) { EV 'WARN' 'Get-MpComputerStatus not available.' }
    elseif ($null -eq $v) { EV 'WARN' 'BehaviorMonitorEnabled unavailable.' }
    elseif ($v -eq $true) { EV 'PASS' 'Behavior monitoring enabled.' }
    else { EV 'WARN' 'Behavior monitoring disabled.' }
}

Add-CheckDef 'Defender' 'On-Access Protection Enabled' 'OnAccessProtectionEnabled should be True.' '(Get-MpComputerStatus).OnAccessProtectionEnabled' {
    if ($mpStatus) { Prop $mpStatus 'OnAccessProtectionEnabled' } else { $null }
} {
    param($v)
    if (-not $hasDefStatus) { EV 'WARN' 'Get-MpComputerStatus not available.' }
    elseif ($null -eq $v) { EV 'WARN' 'OnAccessProtectionEnabled unavailable.' }
    elseif ($v -eq $true) { EV 'PASS' 'On-access protection enabled.' }
    else { EV 'WARN' 'On-access protection disabled.' }
}

Add-CheckDef 'Defender' 'IOAV Protection Enabled' 'IoavProtectionEnabled should be True.' '(Get-MpComputerStatus).IoavProtectionEnabled' {
    if ($mpStatus) { Prop $mpStatus 'IoavProtectionEnabled' } else { $null }
} {
    param($v)
    if (-not $hasDefStatus) { EV 'WARN' 'Get-MpComputerStatus not available.' }
    elseif ($null -eq $v) { EV 'WARN' 'IoavProtectionEnabled unavailable.' }
    elseif ($v -eq $true) { EV 'PASS' 'IOAV protection enabled.' }
    else { EV 'WARN' 'IOAV protection disabled.' }
}

Add-CheckDef 'Defender' 'Network Inspection Service Enabled' 'NISEnabled should be True.' '(Get-MpComputerStatus).NISEnabled' {
    if ($mpStatus) { Prop $mpStatus 'NISEnabled' } else { $null }
} {
    param($v)
    if (-not $hasDefStatus) { EV 'WARN' 'Get-MpComputerStatus not available.' }
    elseif ($null -eq $v) { EV 'WARN' 'NISEnabled unavailable.' }
    elseif ($v -eq $true) { EV 'PASS' 'Network inspection enabled.' }
    else { EV 'WARN' 'Network inspection disabled.' }
}

Add-CheckDef 'Defender' 'Tamper Protection Enabled' 'IsTamperProtected should be True.' '(Get-MpComputerStatus).IsTamperProtected' {
    if ($mpStatus) { Prop $mpStatus 'IsTamperProtected' } else { $null }
} {
    param($v)
    if (-not $hasDefStatus) { EV 'WARN' 'Get-MpComputerStatus not available.' }
    elseif ($null -eq $v) { EV 'WARN' 'IsTamperProtected unavailable.' }
    elseif ($v -eq $true) { EV 'PASS' 'Tamper protection enabled.' }
    else { EV 'FAIL' 'Tamper protection disabled.' }
}

Add-CheckDef 'Defender' 'Antivirus Signature Age (Days)' 'AntivirusSignatureAge should be <= 7.' '(Get-MpComputerStatus).AntivirusSignatureAge' {
    if ($mpStatus) { ToInt $mpStatus.AntivirusSignatureAge } else { $null }
} {
    param($v)
    if (-not $hasDefStatus) { EV 'WARN' 'Get-MpComputerStatus not available.' }
    elseif ($null -eq $v) { EV 'WARN' 'Signature age unavailable.' }
    elseif ($v -le 7) { EV 'PASS' 'Signature age baseline met.' }
    elseif ($v -le 14) { EV 'WARN' 'Signatures aging.' }
    else { EV 'FAIL' 'Signatures outdated.' }
}

Add-CheckDef 'Defender' 'Quick Scan Age (Days)' 'QuickScanAge should be <= 30.' '(Get-MpComputerStatus).QuickScanAge' {
    if ($mpStatus) { ToInt $mpStatus.QuickScanAge } else { $null }
} {
    param($v)
    if (-not $hasDefStatus) { EV 'WARN' 'Get-MpComputerStatus not available.' }
    elseif ($null -eq $v -or $v -lt 0) { EV 'WARN' 'Quick scan age unavailable.' }
    elseif ($v -le 30) { EV 'PASS' 'Quick scan recency baseline met.' }
    else { EV 'WARN' 'Quick scan stale.' }
}

Add-CheckDef 'Defender' 'Full Scan Age (Days)' 'FullScanAge should be <= 45.' '(Get-MpComputerStatus).FullScanAge' {
    if ($mpStatus) { ToInt $mpStatus.FullScanAge } else { $null }
} {
    param($v)
    if (-not $hasDefStatus) { EV 'WARN' 'Get-MpComputerStatus not available.' }
    elseif ($null -eq $v -or $v -lt 0) { EV 'WARN' 'Full scan age unavailable.' }
    elseif ($v -le 45) { EV 'PASS' 'Full scan recency baseline met.' }
    else { EV 'WARN' 'Full scan stale.' }
}

Add-CheckDef 'Defender' 'Cloud-Delivered Protection' 'MAPSReporting should be >= 1.' '(Get-MpPreference).MAPSReporting' {
    if ($mpPref) { ToInt $mpPref.MAPSReporting } else { $null }
} {
    param($v)
    if (-not $hasDefPref) { EV 'WARN' 'Get-MpPreference not available.' }
    elseif ($null -eq $v) { EV 'WARN' 'Cloud protection setting unavailable.' }
    elseif ($v -ge 1) { EV 'PASS' 'Cloud-delivered protection enabled.' }
    else { EV 'WARN' 'Cloud-delivered protection disabled.' }
}

Add-CheckDef 'Defender' 'PUA Protection Setting' 'PUAProtection should be 1 or 2.' '(Get-MpPreference).PUAProtection' {
    if ($mpPref) { ToInt $mpPref.PUAProtection } else { $null }
} {
    param($v)
    if (-not $hasDefPref) { EV 'WARN' 'Get-MpPreference not available.' }
    elseif ($null -eq $v) { EV 'WARN' 'PUA protection unavailable.' }
    elseif ($v -in 1, 2) { EV 'PASS' 'PUA protection enabled.' }
    else { EV 'WARN' 'PUA protection disabled.' }
}

Add-CheckDef 'Defender' 'ASR Rules Configured Count' 'ASR rule count should be >= 5.' '(Get-MpPreference).AttackSurfaceReductionRules_Ids.Count' {
    if ($mpPref -and $null -ne $mpPref.AttackSurfaceReductionRules_Ids) { @($mpPref.AttackSurfaceReductionRules_Ids).Count } else { $null }
} {
    param($v)
    if (-not $hasDefPref) { EV 'WARN' 'Get-MpPreference not available.' }
    elseif ($null -eq $v) { EV 'WARN' 'ASR configuration unavailable.' }
    elseif ($v -ge 5) { EV 'PASS' 'ASR rule coverage good.' }
    elseif ($v -gt 0) { EV 'WARN' 'ASR partially configured.' }
    else { EV 'WARN' 'ASR not configured.' }
}

Add-CheckDef 'Defender' 'Defender Exclusions Review' 'Exclusion paths/processes/extensions should be minimal and avoid risky patterns.' '(Get-MpPreference).ExclusionPath/ExclusionProcess/ExclusionExtension' {
    if (-not $mpPref) { $null } else {
        $paths = @($mpPref.ExclusionPath | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
        $procs = @($mpPref.ExclusionProcess | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
        $exts = @($mpPref.ExclusionExtension | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })

        $riskyPathEntries = @()
        foreach ($p in $paths) {
            $raw = [string]$p
            $norm = [Environment]::ExpandEnvironmentVariables($raw).ToLowerInvariant()
            $isRisky = $false
            if ($norm -match '^[a-z]:\\$') { $isRisky = $true }
            elseif ($norm -match '^[a-z]:\\\*$') { $isRisky = $true }
            elseif ($norm -match '[*?]') { $isRisky = $true }
            elseif ($norm -match '(\\windows\\temp\\|\\temp\\|\\appdata\\|\\users\\|\\programdata\\)') { $isRisky = $true }
            if ($isRisky) { $riskyPathEntries += $raw }
        }

        $riskyProcessNames = @('powershell.exe', 'pwsh.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'wmic.exe', 'bitsadmin.exe')
        $riskyProcessEntries = @()
        foreach ($pr in $procs) {
            $raw = [string]$pr
            $name = [System.IO.Path]::GetFileName($raw).ToLowerInvariant()
            if ($raw -match '[*?]' -or $riskyProcessNames -contains $name) { $riskyProcessEntries += $raw }
        }

        $riskyExtensions = @('exe', 'dll', 'sys', 'ps1', 'psm1', 'vbs', 'vbe', 'js', 'jse', 'cmd', 'bat', 'com', 'scr', 'msi')
        $riskyExtensionEntries = @()
        foreach ($ex in $exts) {
            $raw = [string]$ex
            $normalized = $raw.Trim().TrimStart('.').ToLowerInvariant()
            if ($normalized -eq '*' -or $riskyExtensions -contains $normalized) { $riskyExtensionEntries += $raw }
        }

        @{
            PathCount = $paths.Count
            ProcessCount = $procs.Count
            ExtensionCount = $exts.Count
            Total = ($paths.Count + $procs.Count + $exts.Count)
            RiskyPathCount = $riskyPathEntries.Count
            RiskyProcessCount = $riskyProcessEntries.Count
            RiskyExtensionCount = $riskyExtensionEntries.Count
            RiskyItems = @(($riskyPathEntries + $riskyProcessEntries + $riskyExtensionEntries) | Select-Object -First 20)
            PathSample = @($paths | Select-Object -First 10)
            ProcessSample = @($procs | Select-Object -First 10)
            ExtensionSample = @($exts | Select-Object -First 10)
        }
    }
} {
    param($v)
    if (-not $hasDefPref) { EV 'WARN' 'Get-MpPreference not available.' }
    elseif ($null -eq $v) { EV 'WARN' 'Defender exclusion data unavailable.' }
    else {
        $riskyTotal = ($v.RiskyPathCount + $v.RiskyProcessCount + $v.RiskyExtensionCount)
        if ($v.Total -eq 0) { EV 'PASS' 'No Defender exclusions configured.' }
        elseif ($riskyTotal -gt 0) { EV 'FAIL' 'Risky Defender exclusion patterns detected.' }
        elseif ($v.Total -le 5) { EV 'WARN' 'Defender exclusions present; review necessity.' }
        else { EV 'FAIL' 'High number of Defender exclusions detected.' }
    }
}

# 86-95 Encryption and hardening
Add-CheckDef 'Hardening' 'BitLocker OS Drive Protection' 'OS drive BitLocker protection should be On.' 'Get-BitLockerVolume -MountPoint $env:SystemDrive' {
    if (-not $hasBitLocker) { $null }
    else {
        $vol = $bitLocker | Where-Object { $_.MountPoint -eq $env:SystemDrive } | Select-Object -First 1
        if ($vol) { $vol.ProtectionStatus } else { $null }
    }
} {
    param($v)
    if (-not $hasBitLocker) { EV 'WARN' 'Get-BitLockerVolume not available.' }
    elseif ($null -eq $v) { EV 'WARN' 'OS drive BitLocker state unavailable.' }
    elseif ($v -eq 1 -or [string]$v -eq 'On') { EV 'PASS' 'OS drive protected by BitLocker.' }
    else { EV 'FAIL' 'OS drive not protected by BitLocker.' }
}

Add-CheckDef 'Hardening' 'BitLocker Fixed Data Drive Coverage' 'All fixed data drives should be encrypted or none should exist.' 'Get-BitLockerVolume | ? VolumeType -eq FixedData' {
    if (-not $hasBitLocker) { $null }
    else {
        $fixed = @($bitLocker | Where-Object { $_.VolumeType -eq 'FixedData' })
        if ($fixed.Count -eq 0) {
            @{ FixedDataDrives = 0; Unprotected = 0 }
        } else {
            $unp = @($fixed | Where-Object { $_.ProtectionStatus -ne 1 -and $_.ProtectionStatus -ne 'On' })
            @{ FixedDataDrives = $fixed.Count; Unprotected = $unp.Count; UnprotectedList = @($unp | Select-Object -ExpandProperty MountPoint) }
        }
    }
} {
    param($v)
    if (-not $hasBitLocker) { EV 'WARN' 'Get-BitLockerVolume not available.' }
    elseif ($null -eq $v) { EV 'WARN' 'Fixed drive BitLocker state unavailable.' }
    elseif ($v.Unprotected -eq 0) { EV 'PASS' 'Fixed drives covered by BitLocker (or none).' }
    else { EV 'WARN' 'Unprotected fixed data drives detected.' }
}

Add-CheckDef 'Hardening' 'UAC Enabled' 'EnableLUA should be 1.' 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA' {
    ToInt (RegVal 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA')
} {
    param($v)
    if ($null -eq $v) { EV 'WARN' 'EnableLUA unavailable.' }
    elseif ($v -eq 1) { EV 'PASS' 'UAC enabled.' }
    else { EV 'FAIL' 'UAC disabled.' }
}

Add-CheckDef 'Hardening' 'UAC Admin Prompt Behavior' 'ConsentPromptBehaviorAdmin should be >= 2.' 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin' {
    ToInt (RegVal 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin')
} {
    param($v)
    if ($null -eq $v) { EV 'WARN' 'ConsentPromptBehaviorAdmin unavailable.' }
    elseif ($v -ge 2) { EV 'PASS' 'UAC admin prompt baseline met.' }
    else { EV 'WARN' 'UAC admin prompt may be weak.' }
}

Add-CheckDef 'Hardening' 'LSA Protection (RunAsPPL)' 'RunAsPPL should be 1.' 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL' {
    ToInt (RegVal 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL')
} {
    param($v)
    if ($null -eq $v) { EV 'WARN' 'RunAsPPL not configured.' }
    elseif ($v -eq 1) { EV 'PASS' 'LSA protection enabled.' }
    else { EV 'WARN' 'LSA protection not enabled.' }
}

Add-CheckDef 'Hardening' 'Credential Guard Configuration' 'Credential Guard should be configured or running.' 'Get-CimInstance root\Microsoft\Windows\DeviceGuard Win32_DeviceGuard' {
    if ($null -eq $deviceGuard) { $null } else { @{ Configured = @($deviceGuard.SecurityServicesConfigured); Running = @($deviceGuard.SecurityServicesRunning) } }
} {
    param($v)
    if ($null -eq $v) { EV 'WARN' 'Device Guard data unavailable.' }
    elseif (@($v.Configured + $v.Running) -contains 1) { EV 'PASS' 'Credential Guard appears configured/running.' }
    else { EV 'WARN' 'Credential Guard not detected.' }
}

Add-CheckDef 'Hardening' 'SmartScreen Setting' 'SmartScreen should be enabled.' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\EnableSmartScreen' {
    @{ PolicyEnable = ToInt (RegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen'); ShellValue = [string](RegVal 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' 'SmartScreenEnabled') }
} {
    param($v)
    if ($null -eq $v) { EV 'WARN' 'SmartScreen setting unavailable.' }
    elseif ($v.PolicyEnable -eq 1) { EV 'PASS' 'SmartScreen enabled by policy.' }
    elseif (-not [string]::IsNullOrWhiteSpace($v.ShellValue) -and $v.ShellValue -notin @('Off', '0')) { EV 'PASS' 'SmartScreen shell setting enabled.' }
    else { EV 'WARN' 'SmartScreen appears disabled.' }
}

Add-CheckDef 'Hardening' 'PowerShell Script Block Logging' 'EnableScriptBlockLogging should be 1.' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging' {
    ToInt (RegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging')
} {
    param($v)
    if ($null -eq $v) { EV 'WARN' 'Script block logging policy not configured.' }
    elseif ($v -eq 1) { EV 'PASS' 'Script block logging enabled.' }
    else { EV 'WARN' 'Script block logging disabled.' }
}

Add-CheckDef 'Hardening' 'PowerShell Transcription' 'EnableTranscripting should be 1.' 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription\EnableTranscripting' {
    ToInt (RegVal 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' 'EnableTranscripting')
} {
    param($v)
    if ($null -eq $v) { EV 'WARN' 'Transcription policy not configured.' }
    elseif ($v -eq 1) { EV 'PASS' 'PowerShell transcription enabled.' }
    else { EV 'WARN' 'PowerShell transcription disabled.' }
}

Add-CheckDef 'Hardening' 'TLS 1.0 Server Disabled' 'TLS 1.0 Server Enabled=0 and DisabledByDefault=1.' 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' {
    @{ Enabled = ToInt (RegVal 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' 'Enabled'); DisabledByDefault = ToInt (RegVal 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' 'DisabledByDefault') }
} {
    param($v)
    if ($null -eq $v) { EV 'WARN' 'TLS 1.0 registry values unavailable.' }
    elseif ($v.Enabled -eq 0 -and $v.DisabledByDefault -eq 1) { EV 'PASS' 'TLS 1.0 server disabled.' }
    elseif ($null -eq $v.Enabled -and $null -eq $v.DisabledByDefault) { EV 'WARN' 'TLS 1.0 keys not set; relying on OS defaults.' }
    else { EV 'WARN' 'TLS 1.0 server may be enabled.' }
}

# 96-105 Services and attack surface
Add-CheckDef 'Service' 'Remote Registry Service Startup Mode' 'RemoteRegistry startup should be Disabled.' '(Get-CimInstance Win32_Service -Filter "Name=''RemoteRegistry''").StartMode' {
    ServiceMode 'RemoteRegistry'
} {
    param($v)
    if ($null -eq $v) { EV 'INFO' 'RemoteRegistry service not found.' }
    elseif ($v -eq 'Disabled') { EV 'PASS' 'RemoteRegistry disabled.' }
    else { EV 'WARN' 'RemoteRegistry not disabled.' }
}

Add-CheckDef 'Service' 'Telnet Service Disabled or Absent' 'Telnet service should be absent or disabled.' 'Get-Service TlntSvr' {
    $svc = Safe { Get-Service -Name 'TlntSvr' -ErrorAction Stop }
    if ($null -eq $svc) {
        @{ Exists = $false; Status = 'NotInstalled'; StartMode = 'NotInstalled' }
    } else {
        @{ Exists = $true; Status = [string]$svc.Status; StartMode = ServiceMode 'TlntSvr' }
    }
} {
    param($v)
    if ($null -eq $v) { EV 'INFO' 'Telnet service info unavailable.' }
    elseif ($v.Exists -eq $false) { EV 'PASS' 'Telnet not installed.' }
    elseif ($v.StartMode -eq 'Disabled' -or $v.Status -eq 'Stopped') { EV 'PASS' 'Telnet not active.' }
    else { EV 'FAIL' 'Telnet active or enabled.' }
}

Add-CheckDef 'Service' 'SNMP Services Disabled or Absent' 'SNMP services should be absent or disabled.' 'Get-Service SNMP,SNMPTRAP' {
    $svcs = @(Safe { Get-Service -Name 'SNMP', 'SNMPTRAP' -ErrorAction Stop } @())
    if ($svcs.Count -eq 0) {
        @{ Found = 0; Running = 0; AutoStart = 0 }
    } else {
        $running = @($svcs | Where-Object { $_.Status -eq 'Running' }).Count
        $auto = 0
        foreach ($s in $svcs) { if ((ServiceMode $s.Name) -eq 'Auto') { $auto++ } }
        @{ Found = $svcs.Count; Running = $running; AutoStart = $auto; Names = @($svcs | Select-Object -ExpandProperty Name) }
    }
} {
    param($v)
    if ($null -eq $v) { EV 'INFO' 'SNMP service info unavailable.' }
    elseif ($v.Found -eq 0) { EV 'PASS' 'SNMP services not installed.' }
    elseif ($v.Running -eq 0 -and $v.AutoStart -eq 0) { EV 'PASS' 'SNMP services installed but inactive.' }
    else { EV 'WARN' 'SNMP services active or auto-starting.' }
}

Add-CheckDef 'Hardening' 'AutoRun Disabled for All Drives' 'NoDriveTypeAutoRun should be 255.' 'HKLM/HKCU Policies Explorer NoDriveTypeAutoRun' {
    @{ HKLM = ToInt (RegVal 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun'); HKCU = ToInt (RegVal 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun') }
} {
    param($v)
    if ($null -eq $v) { EV 'WARN' 'AutoRun policy values unavailable.' }
    elseif ($v.HKLM -eq 255 -or $v.HKCU -eq 255) { EV 'PASS' 'AutoRun disabled.' }
    else { EV 'WARN' 'AutoRun may not be fully disabled.' }
}

Add-CheckDef 'Service' 'Hidden Scheduled Tasks Count' 'Hidden scheduled tasks should be <= 10 and reviewed.' '(Get-ScheduledTask | ? { $_.Settings.Hidden }).Count' {
    if (-not $hasTasks) { $null } else { @{ Count = $hiddenTasks.Count; Names = @($hiddenTasks | Select-Object -ExpandProperty TaskName | Select-Object -First 20) } }
} {
    param($v)
    if (-not $hasTasks) { EV 'WARN' 'Get-ScheduledTask not available.' }
    elseif ($null -eq $v) { EV 'WARN' 'Scheduled task data unavailable.' }
    elseif ($v.Count -le 10) { EV 'PASS' 'Hidden scheduled task count within baseline.' }
    else { EV 'WARN' 'High hidden scheduled task count detected.' }
}

Add-CheckDef 'Hardening' 'Unsigned Startup Binary Entries' 'Startup executable signatures should be valid or explicitly trusted.' 'Get-CimInstance Win32_StartupCommand + Get-AuthenticodeSignature' {
    $startup = @(Safe { Get-CimInstance Win32_StartupCommand } @())
    if ($startup.Count -eq 0) {
        @{ Total = 0; Unsigned = 0; Unresolved = 0; Findings = @() }
    } else {
        $unsigned = @()
        $unresolved = 0
        foreach ($s in $startup) {
            $name = [string](Prop $s 'Name')
            $cmdLine = [string](Prop $s 'Command')
            $path = Resolve-ExecutablePath $cmdLine
            if ([string]::IsNullOrWhiteSpace($path) -or -not (Test-Path -LiteralPath $path -PathType Leaf)) {
                $unresolved++
                continue
            }

            $sig = Safe { Get-AuthenticodeSignature -FilePath $path -ErrorAction Stop }
            $status = [string](Prop $sig 'Status')
            if ([string]::IsNullOrWhiteSpace($status)) { $status = 'UnknownError' }
            if ($status -ne 'Valid') {
                $unsigned += ('{0} -> {1} [{2}]' -f $name, $path, $status)
            }
        }

        @{ Total = $startup.Count; Unsigned = $unsigned.Count; Unresolved = $unresolved; Findings = @($unsigned | Select-Object -First 20) }
    }
} {
    param($v)
    if ($null -eq $v) { EV 'WARN' 'Startup signature analysis unavailable.' }
    elseif ($v.Unsigned -eq 0 -and $v.Unresolved -eq 0) { EV 'PASS' 'No unsigned startup binaries detected.' }
    elseif ($v.Unsigned -eq 0 -and $v.Unresolved -gt 0) { EV 'WARN' 'Some startup binaries could not be resolved for signature checks.' }
    elseif ($v.Unsigned -le 3) { EV 'WARN' 'Unsigned startup binaries detected; review required.' }
    else { EV 'FAIL' 'Multiple unsigned startup binaries detected.' }
}

Add-CheckDef 'Service' 'Suspicious Scheduled Task Indicators' 'Scheduled task actions should avoid suspicious script/execution patterns.' 'Get-ScheduledTask + action pattern analysis' {
    if (-not $hasTasks) { $null } else {
        $suspicious = @()
        foreach ($t in $tasks) {
            $taskPath = [string](Prop $t 'TaskPath')
            $taskName = [string](Prop $t 'TaskName')

            $taskActions = Prop $t 'Actions'
            $actions = if ($null -eq $taskActions) { @() } else { @($taskActions) }
            $actionText = ($actions | ForEach-Object {
                    $exe = [string](Prop $_ 'Execute')
                    $args = [string](Prop $_ 'Arguments')
                    ('{0} {1}' -f $exe, $args).Trim()
                } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join ' | '

            if ([string]::IsNullOrWhiteSpace($actionText)) { continue }

            $isSuspicious = $false
            if ($actionText -match '(?i)(\\Users\\Public\\|\\AppData\\|\\Temp\\|\\ProgramData\\)') { $isSuspicious = $true }
            if ($actionText -match '(?i)(powershell|pwsh)(\.exe)?\s+.*(-enc|EncodedCommand|FromBase64String|DownloadString|IEX)') { $isSuspicious = $true }
            if ($actionText -match '(?i)(wscript|cscript|mshta|regsvr32|rundll32)(\.exe)?\b') { $isSuspicious = $true }

            if ($isSuspicious) {
                $suspicious += ('{0}{1} -> {2}' -f $taskPath, $taskName, $actionText)
            }
        }

        @{ Count = $suspicious.Count; Findings = @($suspicious | Select-Object -First 20) }
    }
} {
    param($v)
    if (-not $hasTasks) { EV 'WARN' 'Get-ScheduledTask not available.' }
    elseif ($null -eq $v) { EV 'WARN' 'Scheduled task indicator analysis unavailable.' }
    elseif ($v.Count -eq 0) { EV 'PASS' 'No suspicious scheduled task indicators detected.' }
    elseif ($v.Count -le 5) { EV 'WARN' 'Suspicious scheduled task indicators found; review required.' }
    else { EV 'FAIL' 'High number of suspicious scheduled task indicators detected.' }
}

Add-CheckDef 'Firewall' 'Inbound Firewall Exception Rules (Broad)' 'Broad inbound allow rules on Public/Any profile should be minimal.' 'Get-NetFirewallRule/Get-NetFirewallAddressFilter analysis' {
    if (-not (Cmd 'Get-NetFirewallRule') -or -not (Cmd 'Get-NetFirewallAddressFilter')) { $null } else {
        $allowRules = @(Safe { Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction Stop } @())
        if ($allowRules.Count -eq 0) {
            @{ Count = 0; Findings = @() }
        } else {
            $hasPortFilter = Cmd 'Get-NetFirewallPortFilter'
            $exceptions = @()

            foreach ($rule in $allowRules) {
                $profile = [string](Prop $rule 'Profile')
                $isPublicOrAny = ($profile -match 'Public') -or ($profile -match 'Any')
                if (-not $isPublicOrAny) { continue }

                $addrFilters = @(Safe { Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop } @())
                if ($addrFilters.Count -eq 0) { continue }

                $isBroadRemote = $false
                foreach ($af in $addrFilters) {
                    $remote = [string](Prop $af 'RemoteAddress')
                    if ([string]::IsNullOrWhiteSpace($remote) -or $remote -match '^(Any|\*|0\.0\.0\.0/0|::/0|Internet)$') {
                        $isBroadRemote = $true
                        break
                    }
                }
                if (-not $isBroadRemote) { continue }

                $portText = 'Any'
                if ($hasPortFilter) {
                    $pf = @(Safe { Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop } @())
                    if ($pf.Count -gt 0) {
                        $localPort = [string](Prop $pf[0] 'LocalPort')
                        if (-not [string]::IsNullOrWhiteSpace($localPort)) { $portText = $localPort }
                    }
                }

                $exceptions += ('{0} [Profile={1}; Port={2}]' -f [string](Prop $rule 'DisplayName'), $profile, $portText)
            }

            @{ Count = $exceptions.Count; Findings = @($exceptions | Select-Object -First 20) }
        }
    }
} {
    param($v)
    if ($null -eq $v) { EV 'WARN' 'Firewall rule exception analysis unavailable.' }
    elseif ($v.Count -eq 0) { EV 'PASS' 'No broad inbound firewall exceptions on Public/Any profiles.' }
    elseif ($v.Count -le 5) { EV 'WARN' 'Broad inbound firewall exceptions found; review required.' }
    else { EV 'FAIL' 'High number of broad inbound firewall exceptions.' }
}

Add-CheckDef 'Network' 'WinRM Listener Exposure' 'HTTP wildcard WinRM listener should not be present unless explicitly required.' 'winrm enumerate winrm/config/listener' {
    if (-not (Cmd 'winrm')) { $null } else {
        $txt = [string](Safe { (& winrm enumerate winrm/config/listener 2>&1 | Out-String) } '')
        if ([string]::IsNullOrWhiteSpace($txt)) {
            @{ Count = 0; HttpWildcard = 0; Https = 0; Listeners = @() }
        } else {
            $transports = [regex]::Matches($txt, '(?im)^\s*Transport\s*=\s*(HTTP|HTTPS)\s*$')
            $addresses = [regex]::Matches($txt, '(?im)^\s*Address\s*=\s*([^\r\n]+)\s*$')
            $listeners = @()
            $httpWildcard = 0
            $httpsCount = 0

            for ($i = 0; $i -lt $transports.Count; $i++) {
                $transport = $transports[$i].Groups[1].Value.ToUpperInvariant()
                $address = if ($i -lt $addresses.Count) { $addresses[$i].Groups[1].Value.Trim() } else { '<unknown>' }
                if ($transport -eq 'HTTPS') { $httpsCount++ }
                if ($transport -eq 'HTTP' -and $address -in @('*', 'IP:*')) { $httpWildcard++ }
                $listeners += ('{0}/{1}' -f $transport, $address)
            }

            @{ Count = $listeners.Count; HttpWildcard = $httpWildcard; Https = $httpsCount; Listeners = @($listeners | Select-Object -First 20) }
        }
    }
} {
    param($v)
    if ($null -eq $v) { EV 'WARN' 'WinRM listener data unavailable.' }
    elseif ($v.Count -eq 0) { EV 'PASS' 'No WinRM listeners detected.' }
    elseif ($v.HttpWildcard -gt 0) { EV 'FAIL' 'HTTP wildcard WinRM listener detected.' }
    else { EV 'WARN' 'WinRM listeners configured; verify management exposure.' }
}

Add-CheckDef 'Service' 'Risky Services Active or Auto-Start' 'High-risk remote/legacy services should be disabled or not active.' 'Get-CimInstance Win32_Service (risky list)' {
    $risky = @('RemoteRegistry', 'TlntSvr', 'SNMP', 'SNMPTRAP', 'RemoteAccess', 'SSDPSRV', 'upnphost')
    $svcs = @(Safe { Get-CimInstance -ClassName Win32_Service -ErrorAction Stop | Where-Object { $risky -contains $_.Name } } @())
    if ($svcs.Count -eq 0) {
        @{ Found = 0; Active = 0; Critical = 0; Details = @() }
    } else {
        $active = @($svcs | Where-Object { $_.State -eq 'Running' -or $_.StartMode -eq 'Auto' })
        $critical = @($active | Where-Object { $_.Name -in @('RemoteRegistry', 'TlntSvr') })
        $details = @($active | ForEach-Object { '{0} State={1} StartMode={2}' -f $_.Name, $_.State, $_.StartMode } | Select-Object -First 20)
        @{ Found = $svcs.Count; Active = $active.Count; Critical = $critical.Count; Details = $details }
    }
} {
    param($v)
    if ($null -eq $v) { EV 'WARN' 'Risky service inventory unavailable.' }
    elseif ($v.Active -eq 0) { EV 'PASS' 'No risky services active or auto-starting.' }
    elseif ($v.Critical -gt 0) { EV 'FAIL' 'Critical risky services are active/auto-starting.' }
    elseif ($v.Active -le 2) { EV 'WARN' 'Some risky services are active/auto-starting; review required.' }
    else { EV 'FAIL' 'Multiple risky services are active/auto-starting.' }
}

# Execute checks
if ($Checks.Count -ne $ExpectedCheckCount) {
    throw "Internal error: expected $ExpectedCheckCount checks but found $($Checks.Count)."
}

for ($i = 0; $i -lt $Checks.Count; $i++) {
    Invoke-Check -Id ($i + 1) -Check $Checks[$i]
}

# Export outputs
$Results | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
$Results | ConvertTo-Json -Depth 8 | Set-Content -Path $JsonPath -Encoding UTF8
$evidenceIndexRows = @($Results | Select-Object ID, Category, Check, Status, Evidence)
if ($BaselineEvidencePaths.Count -gt 0) {
    $baselineRows = @($BaselineEvidencePaths | ForEach-Object {
            [pscustomobject]@{
                ID = 'BASE'
                Category = 'Baseline'
                Check = [IO.Path]::GetFileName([string]$_)
                Status = 'INFO'
                Evidence = [string]$_
            }
        })
    $evidenceIndexRows = @($evidenceIndexRows + $baselineRows)
}
$evidenceIndexRows | Export-Csv -Path $EvidenceIndexPath -NoTypeInformation -Encoding UTF8

$statusOrder = @('PASS', 'FAIL', 'WARN', 'INFO', 'ERROR')
$statusLines = foreach ($s in $statusOrder) {
    $count = (@($Results | Where-Object { $_.Status -eq $s })).Count
    "{0}: {1}" -f $s, $count
}

Add-Content -Path $TxtPath -Value ''
Add-Content -Path $TxtPath -Value '=== SUMMARY ==='
foreach ($line in $statusLines) { Add-Content -Path $TxtPath -Value $line }
Add-Content -Path $TxtPath -Value ("TOTAL: {0}" -f $Results.Count)
Add-Content -Path $TxtPath -Value ("BASELINE EVIDENCE FILES: {0}" -f $BaselineEvidencePaths.Count)
Add-Content -Path $TxtPath -Value ("AUDIT FOLDER: {0}" -f $AuditFolder)

$passCount = (@($Results | Where-Object { $_.Status -eq 'PASS' })).Count
$failCount = (@($Results | Where-Object { $_.Status -eq 'FAIL' })).Count
$warnCount = (@($Results | Where-Object { $_.Status -eq 'WARN' })).Count
$infoCount = (@($Results | Where-Object { $_.Status -eq 'INFO' })).Count
$errorCount = (@($Results | Where-Object { $_.Status -eq 'ERROR' })).Count

$table = ($Results | Select-Object ID, Category, Check, Expected, Actual, Status, DurationMs, Note, Evidence) | ConvertTo-Html -Fragment
$categorySummary = @($Results | Group-Object Category | Sort-Object Name | ForEach-Object {
        $grp = @($_.Group)
        [pscustomobject]@{
            Category = $_.Name
            Total = $grp.Count
            PASS = (@($grp | Where-Object { $_.Status -eq 'PASS' })).Count
            FAIL = (@($grp | Where-Object { $_.Status -eq 'FAIL' })).Count
            WARN = (@($grp | Where-Object { $_.Status -eq 'WARN' })).Count
            INFO = (@($grp | Where-Object { $_.Status -eq 'INFO' })).Count
            ERROR = (@($grp | Where-Object { $_.Status -eq 'ERROR' })).Count
        }
    })
$categoryTable = if ($categorySummary.Count -gt 0) { $categorySummary | ConvertTo-Html -Fragment } else { '<p>No category summary available.</p>' }

$categoryOptions = "<option value=""ALL"">All Categories</option>"
foreach ($cat in @($Results | Select-Object -ExpandProperty Category -Unique | Sort-Object)) {
    $catText = [string]$cat
    $categoryOptions += "`r`n<option value=""$catText"">$catText</option>"
}

$baselineEvidenceLinks = if ($BaselineEvidencePaths.Count -gt 0) {
    ($BaselineEvidencePaths | ForEach-Object {
            $raw = [string]$_
            $href = './' + ($raw -replace '\\', '/')
            '<li><a href="' + $href + '" target="_blank" rel="noopener">' + [System.Net.WebUtility]::HtmlEncode($raw) + '</a></li>'
        }) -join "`r`n"
} else {
    '<li>No baseline evidence files.</li>'
}

$css = @"
<style>
body { font-family: Segoe UI, Arial, sans-serif; margin: 20px; background: #f3f6fb; color: #1f2937; }
.banner { background: #ffffff; border: 1px solid #d8e0eb; border-radius: 10px; padding: 14px 16px; margin-bottom: 14px; }
.brand { color: #0f7b3c; font-weight: 700; margin-bottom: 4px; }
h1 { margin: 0; font-size: 1.7rem; }
h2 { margin-top: 24px; margin-bottom: 8px; }
.meta { margin-top: 8px; color: #4b5563; }
.summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 10px; margin: 12px 0; }
.card { background: #ffffff; border: 1px solid #d8e0eb; border-radius: 8px; padding: 10px; }
.card .label { font-size: 0.82rem; color: #4b5563; }
.card .value { font-size: 1.4rem; font-weight: 700; margin-top: 4px; }
.card.pass { border-left: 4px solid #15803d; }
.card.fail { border-left: 4px solid #dc2626; }
.card.warn { border-left: 4px solid #ca8a04; }
.card.info { border-left: 4px solid #0891b2; }
.card.error { border-left: 4px solid #a21caf; }
.summary { margin: 8px 0 14px 0; padding: 12px; background: #ffffff; border: 1px solid #d8e0eb; border-radius: 8px; }
.controls { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; margin: 10px 0 12px; padding: 10px; background: #ffffff; border: 1px solid #d8e0eb; border-radius: 8px; }
.controls input[type="text"], .controls select { padding: 7px 9px; border: 1px solid #cbd5e1; border-radius: 6px; min-width: 180px; }
.controls label { color: #374151; font-size: 0.95rem; }
#resultsTable table { border-collapse: collapse; width: 100%; background: #ffffff; }
#resultsTable th, #resultsTable td { border: 1px solid #d8e0eb; padding: 8px; text-align: left; vertical-align: top; }
#resultsTable th { background: #e9f0fb; position: sticky; top: 0; z-index: 1; }
#resultsTable tr.st-pass { background: #f0fdf4; }
#resultsTable tr.st-fail { background: #fef2f2; }
#resultsTable tr.st-warn { background: #fffbeb; }
#resultsTable tr.st-info { background: #f0f9ff; }
#resultsTable tr.st-error { background: #fdf4ff; }
.status-badge { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 0.8rem; font-weight: 700; letter-spacing: 0.2px; }
.status-badge.st-pass { background: #dcfce7; color: #166534; }
.status-badge.st-fail { background: #fee2e2; color: #991b1b; }
.status-badge.st-warn { background: #fef3c7; color: #92400e; }
.status-badge.st-info { background: #cffafe; color: #0e7490; }
.status-badge.st-error { background: #f5d0fe; color: #86198f; }
a { color: #0369a1; text-decoration: none; }
a:hover { text-decoration: underline; }
ul { background: #ffffff; border: 1px solid #d8e0eb; border-radius: 8px; padding: 10px 24px; }
</style>
"@

$scriptJs = @'
<script>
(function () {
  const table = document.querySelector('#resultsTable table');
  if (!table) { return; }
  const rows = Array.from(table.querySelectorAll('tbody tr'));

  rows.forEach((row) => {
    const statusCell = row.children[5];
    const categoryCell = row.children[1];
    const evidenceCell = row.children[8];
    const status = (statusCell ? statusCell.textContent : '').trim().toUpperCase();
    const category = (categoryCell ? categoryCell.textContent : '').trim();

    row.dataset.status = status;
    row.dataset.category = category;
    row.dataset.search = (row.textContent || '').toLowerCase();

    const rowClass = 'st-' + status.toLowerCase();
    if (status) {
      row.classList.add(rowClass);
      statusCell.innerHTML = '<span class="status-badge ' + rowClass + '">' + status + '</span>';
    }

    const ev = (evidenceCell ? evidenceCell.textContent : '').trim();
    if (ev) {
      const href = './' + ev.replace(/\\/g, '/');
      evidenceCell.innerHTML = '<a href="' + href + '" target="_blank" rel="noopener">' + ev + '</a>';
    }
  });

  const searchInput = document.getElementById('searchInput');
  const statusFilter = document.getElementById('statusFilter');
  const categoryFilter = document.getElementById('categoryFilter');
  const nonPassOnly = document.getElementById('nonPassOnly');
  const visibleCount = document.getElementById('visibleCount');

  function applyFilters() {
    const query = (searchInput.value || '').trim().toLowerCase();
    const status = statusFilter.value;
    const category = categoryFilter.value;
    const onlyNonPass = nonPassOnly.checked;
    let visible = 0;

    rows.forEach((row) => {
      const rowStatus = row.dataset.status || '';
      const rowCategory = row.dataset.category || '';
      const rowText = row.dataset.search || '';

      const statusOk = (status === 'ALL' || rowStatus === status);
      const categoryOk = (category === 'ALL' || rowCategory === category);
      const queryOk = (query.length === 0 || rowText.indexOf(query) !== -1);
      const nonPassOk = (!onlyNonPass || rowStatus !== 'PASS');
      const show = statusOk && categoryOk && queryOk && nonPassOk;

      row.style.display = show ? '' : 'none';
      if (show) { visible += 1; }
    });

    visibleCount.textContent = String(visible);
  }

  [searchInput, statusFilter, categoryFilter, nonPassOnly].forEach((el) => {
    if (!el) { return; }
    el.addEventListener('input', applyFilters);
    el.addEventListener('change', applyFilters);
  });

  applyFilters();
})();
</script>
'@

$html = @"
<html>
<head>
<meta charset="utf-8" />
<title>Windows Audit - $env:COMPUTERNAME</title>
$css
</head>
<body>
<div class="banner">
  <h1>Windows Security Audit $ScriptVersion</h1>
  <div class="brand">$BannerText</div>
  <div class="meta">Computer: $env:COMPUTERNAME | User: $env:USERNAME | Run Start: $($RunStart.ToString('yyyy-MM-dd HH:mm:ss'))</div>
</div>

<div class="summary-grid">
  <div class="card pass"><div class="label">PASS</div><div class="value">$passCount</div></div>
  <div class="card fail"><div class="label">FAIL</div><div class="value">$failCount</div></div>
  <div class="card warn"><div class="label">WARN</div><div class="value">$warnCount</div></div>
  <div class="card info"><div class="label">INFO</div><div class="value">$infoCount</div></div>
  <div class="card error"><div class="label">ERROR</div><div class="value">$errorCount</div></div>
</div>

<div class="summary">
  <p><strong>Total Checks:</strong> $($Results.Count)</p>
  <p><strong>Baseline Evidence Files:</strong> $($BaselineEvidencePaths.Count)</p>
  <p><strong>Evidence Folder:</strong> $EvidenceFolder</p>
</div>

<div class="controls">
  <input id="searchInput" type="text" placeholder="Search checks, notes, values..." />
  <select id="statusFilter">
    <option value="ALL">All Statuses</option>
    <option value="PASS">PASS</option>
    <option value="FAIL">FAIL</option>
    <option value="WARN">WARN</option>
    <option value="INFO">INFO</option>
    <option value="ERROR">ERROR</option>
  </select>
  <select id="categoryFilter">
$categoryOptions
  </select>
  <label><input id="nonPassOnly" type="checkbox" /> Non-PASS only</label>
  <span>Visible Rows: <strong id="visibleCount">0</strong></span>
</div>

<div id="resultsTable">
$table
</div>

<h2>Category Summary</h2>
$categoryTable

<h2>Baseline Evidence</h2>
<ul>
$baselineEvidenceLinks
</ul>

$scriptJs
</body>
</html>
"@
Set-Content -Path $HtmlPath -Value $html -Encoding UTF8

$RunEnd = Get-Date
$duration = New-TimeSpan -Start $RunStart -End $RunEnd

@"
Windows Security Audit Metadata
===============================
Script Version : $ScriptVersion
Brand          : $BannerText
Run Start      : $($RunStart.ToString('yyyy-MM-dd HH:mm:ss'))
Run End        : $($RunEnd.ToString('yyyy-MM-dd HH:mm:ss'))
Duration       : $([math]::Round($duration.TotalSeconds, 2)) seconds
Computer       : $env:COMPUTERNAME
User           : $env:USERNAME
Is Admin       : $isAdmin

Output Paths
------------
Audit Folder   : $AuditFolder
CSV            : $CsvPath
TXT            : $TxtPath
JSON           : $JsonPath
HTML           : $HtmlPath
Evidence Folder: $EvidenceFolder
Evidence Index : $EvidenceIndexPath

Status Summary
--------------
PASS           : $passCount
FAIL           : $failCount
WARN           : $warnCount
INFO           : $infoCount
ERROR          : $errorCount
Total Checks   : $($Results.Count)
Baseline Files : $($BaselineEvidencePaths.Count)
"@ | Set-Content -Path $MetaPath -Encoding UTF8

Write-Host ''
Write-Host 'Audit complete.' -ForegroundColor Green
Write-Host $BannerText -ForegroundColor Green
Write-Host ("Total Checks : {0}" -f $Results.Count) -ForegroundColor Green
Write-Host ("PASS: {0} | FAIL: {1} | WARN: {2} | INFO: {3} | ERROR: {4}" -f $passCount, $failCount, $warnCount, $infoCount, $errorCount) -ForegroundColor Cyan
Write-Host ("Evidence path: {0}" -f $EvidenceFolder) -ForegroundColor Yellow
Write-Host ("Main report  : {0}" -f $HtmlPath) -ForegroundColor Yellow
