#!/usr/bin/env pwsh
$ErrorActionPreference = 'Stop'

$RepoRoot = Resolve-Path "$PSScriptRoot\..\..\.."
$Nebula = Join-Path $RepoRoot 'nebula.exe'
$NebulaCert = Join-Path $RepoRoot 'nebula-cert.exe'

if (-not (Test-Path $Nebula)) { throw "missing $Nebula; run 'make bin-windows' first" }
if (-not (Test-Path $NebulaCert)) { throw "missing $NebulaCert; run 'make bin-windows' first" }

$WorkDir = Join-Path $env:TEMP "nebula-smoke-windows"
if (Test-Path $WorkDir) { Remove-Item -Recurse -Force $WorkDir }
New-Item -ItemType Directory -Path $WorkDir | Out-Null

$DevName = "nebula-smoke"
$CaCrt   = Join-Path $WorkDir 'ca.crt'
$CaKey   = Join-Path $WorkDir 'ca.key'
$HostCrt = Join-Path $WorkDir 'host.crt'
$HostKey = Join-Path $WorkDir 'host.key'

& $NebulaCert ca -name "smoke-ca" -out-crt $CaCrt -out-key $CaKey
if ($LASTEXITCODE -ne 0) { throw "nebula-cert ca failed (exit $LASTEXITCODE)" }

& $NebulaCert sign -name "smoke" -networks "192.168.241.1/24" -ca-crt $CaCrt -ca-key $CaKey -out-crt $HostCrt -out-key $HostKey
if ($LASTEXITCODE -ne 0) { throw "nebula-cert sign failed (exit $LASTEXITCODE)" }

function Write-Config {
    param([string]$Category)
    $cfg = Join-Path $WorkDir 'config.yml'
    @"
pki:
  ca: $CaCrt
  cert: $HostCrt
  key: $HostKey
static_host_map: {}
lighthouse:
  am_lighthouse: true
  interval: 60
  hosts: []
listen:
  host: 0.0.0.0
  port: 4242
tun:
  disabled: false
  dev: $DevName
  drop_local_broadcast: false
  drop_multicast: false
  tx_queue: 500
  mtu: 1300
  network_category: $Category
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
"@ | Out-File -FilePath $cfg -Encoding utf8
    return $cfg
}

function Test-Category {
    param(
        [Parameter(Mandatory)] [string]$ConfigValue,
        [Parameter(Mandatory)] [string]$ExpectedCategory
    )
    Write-Host ""
    Write-Host "=== smoke: network_category=$ConfigValue (expecting $ExpectedCategory) ==="

    $cfg = Write-Config -Category $ConfigValue
    $stdoutLog = Join-Path $WorkDir "nebula-$ConfigValue.out.log"
    $stderrLog = Join-Path $WorkDir "nebula-$ConfigValue.err.log"

    $proc = Start-Process -FilePath $Nebula -ArgumentList @('-config', $cfg) `
        -PassThru -NoNewWindow `
        -RedirectStandardOutput $stdoutLog `
        -RedirectStandardError $stderrLog

    try {
        $deadline = (Get-Date).AddSeconds(30)
        $observed = $null
        while ((Get-Date) -lt $deadline) {
            if ($proc.HasExited) {
                Get-Content $stdoutLog -ErrorAction SilentlyContinue | Out-Host
                Get-Content $stderrLog -ErrorAction SilentlyContinue | Out-Host
                throw "nebula exited prematurely (code $($proc.ExitCode))"
            }
            $netProfile = Get-NetConnectionProfile -InterfaceAlias $DevName -ErrorAction SilentlyContinue
            if ($netProfile) {
                $observed = "$($netProfile.NetworkCategory)"
                if ($observed -ieq $ExpectedCategory) {
                    Write-Host "OK: $DevName NetworkCategory=$observed"
                    return
                }
            }
            Start-Sleep -Milliseconds 500
        }

        Get-Content $stdoutLog -ErrorAction SilentlyContinue | Out-Host
        Get-Content $stderrLog -ErrorAction SilentlyContinue | Out-Host
        throw "expected NetworkCategory=$ExpectedCategory, observed='$observed' within 30s"
    }
    finally {
        if (-not $proc.HasExited) {
            Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
            $proc.WaitForExit(5000) | Out-Null
        }
    }
}

Test-Category -ConfigValue 'private' -ExpectedCategory 'Private'
Test-Category -ConfigValue 'public'  -ExpectedCategory 'Public'

Write-Host ""
Write-Host "All smoke checks passed."
