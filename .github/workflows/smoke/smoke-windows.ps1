#!/usr/bin/env pwsh
# Windows smoke test for the nebula tun + UDP + NLM code paths.
#
# Topology:
#   - lighthouse runs natively on the Windows host (wintun + windows UDP)
#   - peer runs inside WSL2 (Linux build of nebula, /dev/net/tun)
#
# WSL2 gives us a real netns boundary so the loopback fast-path on Windows
# does not short-circuit the overlay -- when WSL pings the lighthouse VPN IP,
# Linux has no idea that IP is local to the Windows host, so the packet is
# forced through nebula. Same in reverse.

$ErrorActionPreference = 'Stop'

# wsl.exe emits UTF-16 LE by default which PowerShell reads as bytes, mangling
# every captured string. WSL_UTF8 makes wsl.exe emit UTF-8 instead.
$env:WSL_UTF8 = '1'

$RepoRoot = Resolve-Path "$PSScriptRoot\..\..\.."
$Nebula = Join-Path $RepoRoot 'nebula.exe'
$NebulaCert = Join-Path $RepoRoot 'nebula-cert.exe'
$NebulaLinux = Join-Path $RepoRoot 'build\linux-amd64\nebula'

if (-not (Test-Path $Nebula)) { throw "missing $Nebula; run 'make bin-windows' first" }
if (-not (Test-Path $NebulaCert)) { throw "missing $NebulaCert; run 'make bin-windows' first" }
if (-not (Test-Path $NebulaLinux)) { throw "missing $NebulaLinux; build the linux nebula first" }

# Matches the distro installed by Vampire/setup-wsl in smoke-extra.yml.
$Distro = 'Ubuntu-24.04'
$listed = (wsl --list --quiet 2>$null) -join "`n"
if ($listed -notmatch [regex]::Escape($Distro)) {
    throw "WSL distro $Distro not registered. Got: $listed"
}
Write-Host "Using WSL distro: $Distro"

# Windows host as seen from inside WSL: WSL's default-route gateway. We extract
# it with a regex rather than awk fields so PowerShell does not eat any '$N'
# tokens, and tabs/double-spaces in `ip route` output do not confuse a cut.
$ipCmd = 'ip route show default | grep -oE "([0-9]+\.){3}[0-9]+" | head -1'
$WindowsIp = (wsl -d $Distro -- bash -c $ipCmd).Trim()
if (-not $WindowsIp) { throw "could not determine Windows host IP from WSL" }
Write-Host "Windows host IP from WSL: $WindowsIp"

$WorkDir = Join-Path $env:TEMP 'nebula-smoke-windows'
if (Test-Path $WorkDir) { Remove-Item -Recurse -Force $WorkDir }
New-Item -ItemType Directory -Path $WorkDir | Out-Null

$WslDir = '/tmp/nebula-smoke'
wsl -d $Distro -- bash -c "rm -rf $WslDir && mkdir -p $WslDir" | Out-Null

$DevName = 'nebula-smoke'
$Ip1 = '192.168.241.1'
$Ip2 = '192.168.241.2'
$Port = 4242

& $NebulaCert ca -name 'smoke-ca' -out-crt "$WorkDir\ca.crt" -out-key "$WorkDir\ca.key"
if ($LASTEXITCODE -ne 0) { throw "nebula-cert ca failed (exit $LASTEXITCODE)" }

& $NebulaCert sign -name 'lighthouse' -networks "$Ip1/24" -ca-crt "$WorkDir\ca.crt" -ca-key "$WorkDir\ca.key" -out-crt "$WorkDir\lighthouse.crt" -out-key "$WorkDir\lighthouse.key"
if ($LASTEXITCODE -ne 0) { throw "nebula-cert sign lighthouse failed (exit $LASTEXITCODE)" }

& $NebulaCert sign -name 'peer' -networks "$Ip2/24" -ca-crt "$WorkDir\ca.crt" -ca-key "$WorkDir\ca.key" -out-crt "$WorkDir\peer.crt" -out-key "$WorkDir\peer.key"
if ($LASTEXITCODE -ne 0) { throw "nebula-cert sign peer failed (exit $LASTEXITCODE)" }

# Windows lighthouse config.
@"
pki:
  ca: $WorkDir\ca.crt
  cert: $WorkDir\lighthouse.crt
  key: $WorkDir\lighthouse.key
static_host_map: {}
lighthouse:
  am_lighthouse: true
  interval: 60
  hosts: []
listen:
  host: 0.0.0.0
  port: $Port
tun:
  disabled: false
  dev: $DevName
  drop_local_broadcast: false
  drop_multicast: false
  tx_queue: 500
  mtu: 1300
  network_category: private
logging:
  level: info
  format: text
firewall:
  outbound_action: drop
  inbound_action: drop
  conntrack:
    tcp_timeout: 12m
    udp_timeout: 3m
    default_timeout: 10m
  outbound:
    - port: any
      proto: any
      host: any
  inbound:
    - port: any
      proto: any
      host: any
"@ | Out-File -FilePath "$WorkDir\lighthouse.yml" -Encoding utf8

# WSL peer config (paths are POSIX, deliberately).
@"
pki:
  ca: $WslDir/ca.crt
  cert: $WslDir/peer.crt
  key: $WslDir/peer.key
static_host_map:
  "${Ip1}": ["${WindowsIp}:$Port"]
lighthouse:
  am_lighthouse: false
  interval: 60
  hosts:
    - "${Ip1}"
listen:
  host: 0.0.0.0
  port: 0
tun:
  disabled: false
  dev: nebula1
  drop_local_broadcast: false
  drop_multicast: false
  tx_queue: 500
  mtu: 1300
logging:
  level: info
  format: text
firewall:
  outbound_action: drop
  inbound_action: drop
  conntrack:
    tcp_timeout: 12m
    udp_timeout: 3m
    default_timeout: 10m
  outbound:
    - port: any
      proto: any
      host: any
  inbound:
    - port: any
      proto: any
      host: any
"@ | Out-File -FilePath "$WorkDir\peer.yml" -Encoding utf8

# Stage WSL artifacts. Convert Windows paths to WSL paths ourselves rather than
# calling `wslpath`, because PowerShell's argument-passing to external EXEs
# strips backslashes from path arguments in ways that are hard to escape around.
function ConvertTo-WslPath {
    param([string]$WindowsPath)
    if ($WindowsPath -notmatch '^([A-Za-z]):\\(.*)$') {
        throw "cannot convert path to WSL: $WindowsPath"
    }
    return "/mnt/$($matches[1].ToLower())/$($matches[2].Replace('\','/'))"
}

$WslWorkDir = ConvertTo-WslPath $WorkDir
$WslNebulaPath = ConvertTo-WslPath $NebulaLinux
wsl -d $Distro -- bash -c "cp '$WslWorkDir/ca.crt' '$WslWorkDir/peer.crt' '$WslWorkDir/peer.key' '$WslWorkDir/peer.yml' $WslDir/ && cp '$WslNebulaPath' $WslDir/nebula && chmod +x $WslDir/nebula"

# Make sure WSL has tun support and /dev/net/tun is usable before starting
# nebula. Diagnostics first so a fail here points at the real problem (e.g.
# WSL1 distros do not have a real kernel and will not have tun).
Write-Host '=== WSL diagnostic ==='
wsl --version 2>&1 | Out-Host
wsl --list --verbose 2>&1 | Out-Host
wsl -d $Distro -u root -- uname -a | Out-Host
wsl -d $Distro -u root -- bash -c "modprobe tun 2>&1 || true; mkdir -p /dev/net; [ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200; chmod 600 /dev/net/tun; ls -l /dev/net/tun"
if ($LASTEXITCODE -ne 0) { throw "failed to prepare /dev/net/tun in WSL (TUN support missing?)" }

# Allow inbound nebula UDP from WSL, plus inbound ICMPv4 echo so the kernel
# actually responds to overlay pings rather than silently dropping them.
New-NetFirewallRule -DisplayName 'Nebula smoke inbound UDP' -Direction Inbound -Protocol UDP -LocalPort $Port -Action Allow -ErrorAction SilentlyContinue | Out-Null
New-NetFirewallRule -DisplayName 'Nebula smoke inbound ICMPv4 echo' -Direction Inbound -Protocol ICMPv4 -IcmpType 8 -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null

$lhOut = Join-Path $WorkDir 'lighthouse.out.log'
$lhErr = Join-Path $WorkDir 'lighthouse.err.log'
$lhProc = Start-Process -FilePath $Nebula -ArgumentList @('-config', "$WorkDir\lighthouse.yml") `
    -PassThru -NoNewWindow `
    -RedirectStandardOutput $lhOut `
    -RedirectStandardError $lhErr

# Run nebula in WSL as root with no sudo + no shell wrapper. PowerShell's
# Start-Process arg quoting mangles `bash -c "..."` strings that contain
# spaces/redirections, so we skip bash entirely and let Start-Process do the
# stdout/stderr capture itself.
$peerOut = Join-Path $WorkDir 'peer.out.log'
$peerErr = Join-Path $WorkDir 'peer.err.log'
$peerProc = Start-Process -FilePath 'wsl' `
    -ArgumentList @('-d', $Distro, '-u', 'root', '--', "$WslDir/nebula", '-config', "$WslDir/peer.yml") `
    -PassThru -NoNewWindow `
    -RedirectStandardOutput $peerOut `
    -RedirectStandardError $peerErr

function Wait-Until {
    param([scriptblock]$Predicate, [int]$TimeoutSec, [string]$What)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        if (& $Predicate) { return }
        Start-Sleep -Milliseconds 500
    }
    throw "timed out waiting for: $What"
}

try {
    Wait-Until -TimeoutSec 30 -What "windows wintun adapter $DevName with NetworkCategory=Private" -Predicate {
        if ($lhProc.HasExited) { throw "lighthouse exited (code $($lhProc.ExitCode)) before tun was ready" }
        $p = Get-NetConnectionProfile -InterfaceAlias $DevName -ErrorAction SilentlyContinue
        $p -and ("$($p.NetworkCategory)" -ieq 'Private')
    }
    Write-Host "OK: $DevName NetworkCategory=Private"

    Wait-Until -TimeoutSec 30 -What "WSL nebula1 with $Ip2" -Predicate {
        if ($peerProc.HasExited) { throw "peer exited (code $($peerProc.ExitCode)) before tun was ready" }
        $r = wsl -d $Distro -u root -- bash -c "ip -o addr show nebula1 2>/dev/null | grep -q 'inet $Ip2' && echo yes"
        ("$r").Trim() -eq 'yes'
    }
    Write-Host "OK: WSL nebula1 has $Ip2"

    Wait-Until -TimeoutSec 30 -What "ping from WSL peer to windows lighthouse ($Ip1)" -Predicate {
        if ($peerProc.HasExited) { throw "peer exited (code $($peerProc.ExitCode)) before ping succeeded" }
        $r = wsl -d $Distro -u root -- bash -c "ping -c1 -W1 $Ip1 >/dev/null 2>&1 && echo OK"
        ("$r").Trim() -eq 'OK'
    }
    Write-Host "OK: WSL peer -> windows lighthouse"

    Wait-Until -TimeoutSec 30 -What "ping from windows lighthouse to WSL peer ($Ip2)" -Predicate {
        $null = & ping.exe -n 1 -w 1000 $Ip2
        $LASTEXITCODE -eq 0
    }
    Write-Host "OK: windows lighthouse -> WSL peer"

    Write-Host ''
    Write-Host 'All smoke checks passed.'
}
catch {
    Write-Host ''
    Write-Host '=== lighthouse stdout ==='
    Get-Content $lhOut -ErrorAction SilentlyContinue | Out-Host
    Write-Host '=== lighthouse stderr ==='
    Get-Content $lhErr -ErrorAction SilentlyContinue | Out-Host
    Write-Host '=== peer stdout ==='
    Get-Content $peerOut -ErrorAction SilentlyContinue | Out-Host
    Write-Host '=== peer stderr ==='
    Get-Content $peerErr -ErrorAction SilentlyContinue | Out-Host
    throw
}
finally {
    if (-not $lhProc.HasExited) {
        Stop-Process -Id $lhProc.Id -Force -ErrorAction SilentlyContinue
        $lhProc.WaitForExit(5000) | Out-Null
    }
    wsl -d $Distro -u root -- bash -c "pkill -f $WslDir/nebula 2>/dev/null; true" | Out-Null
    # pkill returns 1 when no match and wsl propagates that; the smoke is done
    # so we don't want it to leak into the script's exit code.
    $global:LASTEXITCODE = 0
    if ($peerProc -and -not $peerProc.HasExited) {
        Stop-Process -Id $peerProc.Id -Force -ErrorAction SilentlyContinue
    }
}
