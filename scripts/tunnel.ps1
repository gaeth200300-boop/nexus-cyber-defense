# =============================================================================
#  NEXUS CYBER DEFENSE - public link via Cloudflare Quick Tunnel
#  Usage: PUBLIC-LINK.cmd             reuse the running tunnel or start one
#         PUBLIC-LINK.cmd -Restart    force a new public URL
#
#  The URL is random and changes on every restart. It stays valid only while
#  this PC is on and the platform + cloudflared keep running.
#  Keep the URL private: it exposes the login page to the internet.
# =============================================================================

[CmdletBinding()]
param(
    [int]$Port = 8000,
    [switch]$Restart
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# ---------------------------------------------------------------------------
# Paths (cloudflared binary and log stay OUTSIDE the repository)
# ---------------------------------------------------------------------------
$ToolsDir = Join-Path $env:LOCALAPPDATA "NexusTools"
$CfdExe   = Join-Path $ToolsDir "cloudflared.exe"
$CfdLog   = Join-Path $ToolsDir "tunnel.log"
$CfdUrl   = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe"

New-Item -ItemType Directory -Force -Path $ToolsDir | Out-Null

function Write-Step([string]$Text) {
    Write-Host ""
    Write-Host ("=" * 72) -ForegroundColor DarkCyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host ("=" * 72) -ForegroundColor DarkCyan
}

function Test-LocalApi {
    try {
        $health = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/api/v1/system/health" -TimeoutSec 8
        return ($health.status -eq "ok")
    } catch {
        return $false
    }
}

function Get-TunnelUrlFromLog {
    if (-not (Test-Path -LiteralPath $CfdLog)) { return $null }
    $match = Select-String -Path $CfdLog -Pattern "https://[a-z0-9-]+\.trycloudflare\.com" -ErrorAction SilentlyContinue |
             Select-Object -First 1
    if ($match) { return $match.Matches[0].Value }
    return $null
}

# ---------------------------------------------------------------------------
# 1. The local platform must be answering
# ---------------------------------------------------------------------------
if (-not (Test-LocalApi)) {
    Write-Host ""
    Write-Host "  [!] The local platform is not answering on port $Port." -ForegroundColor Yellow
    Write-Host "      Start it first:  START-NEXUS.cmd" -ForegroundColor Yellow
    Write-Host ""
    exit 1
}

# ---------------------------------------------------------------------------
# 2. cloudflared must exist (download once, ~53 MB)
# ---------------------------------------------------------------------------
if (-not (Test-Path -LiteralPath $CfdExe)) {
    Write-Step "Downloading cloudflared (one time)"
    Invoke-WebRequest -Uri $CfdUrl -OutFile $CfdExe -UseBasicParsing -TimeoutSec 300
}

# ---------------------------------------------------------------------------
# 3. Reuse a running tunnel unless -Restart was given
# ---------------------------------------------------------------------------
$running = @(Get-Process -Name "cloudflared" -ErrorAction SilentlyContinue)

if ($Restart -and $running.Count -gt 0) {
    Write-Step "Restarting the public tunnel"
    $running | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    $running = @()
}

if ($running.Count -eq 0) {
    Remove-Item -LiteralPath $CfdLog -ErrorAction SilentlyContinue
    Write-Step "Starting public tunnel -> http://127.0.0.1:$Port"
    Start-Process -FilePath $CfdExe `
        -ArgumentList "tunnel", "--url", "http://127.0.0.1:$Port", "--no-autoupdate", "--logfile", $CfdLog `
        -WindowStyle Hidden | Out-Null
}

# ---------------------------------------------------------------------------
# 4. Wait for the public URL
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "  Waiting for the public URL ..." -ForegroundColor Gray
$url = $null
for ($i = 0; $i -lt 60; $i++) {
    $url = Get-TunnelUrlFromLog
    if ($url) { break }
    Start-Sleep -Seconds 2
}

if (-not $url) {
    Write-Host ""
    Write-Host "  [!] No public URL appeared within 120s. Check the log:" -ForegroundColor Red
    Write-Host "      $CfdLog" -ForegroundColor Red
    Write-Host ""
    exit 1
}

Write-Host ""
Write-Host ("=" * 72) -ForegroundColor Green
Write-Host "  PUBLIC LINK : $url" -ForegroundColor Green
Write-Host "  Local link  : http://127.0.0.1:$Port" -ForegroundColor Green
Write-Host ("=" * 72) -ForegroundColor Green
Write-Host ""
Write-Host "  - Valid while this PC is on and the platform is running." -ForegroundColor Gray
Write-Host "  - After a reboot run PUBLIC-LINK.cmd again (the URL will change)." -ForegroundColor Gray
Write-Host "  - Keep this URL private; it exposes the login page to the internet." -ForegroundColor Gray
Write-Host ""
exit 0
