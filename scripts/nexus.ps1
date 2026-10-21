# =============================================================================
#  NEXUS CYBER DEFENSE - Windows control script  (PowerShell 5.1 compatible)
#  Usage: scripts\nexus.cmd <command>
#  Commands:
#    doctor    Check Python / Node / npm / ports before doing anything
#    setup     Create venv, install backend+frontend deps, write .env, migrate DB
#    start     Start API + Web in background (logs + pid files under .run\)
#    dev       Run API + Web in the foreground (auto-reload, Ctrl+C to stop)
#    stop      Stop background processes
#    status    Show processes, ports and API health
#    logs      Show the tail of API/Web logs  (logs 200 api|web|both)
#    test      Run backend tests (pytest) and frontend tests+build
#    migrate   Apply database migrations (alembic upgrade head)
#    seed      (Re)create the bootstrap admin account
#    reset-db  Delete the local SQLite database and re-migrate (dev only)
#    build     Production frontend build into frontend\dist
#    open      Open the web UI in the default browser
#    help      Show this help
# =============================================================================

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$Command = "help",

    [Parameter(Position = 1)]
    [string]$Arg1 = "",

    [Parameter(Position = 2)]
    [string]$Arg2 = ""
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# --------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------
$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot    = Split-Path -Parent $ScriptDir
$BackendDir  = Join-Path $RepoRoot "backend"
$FrontendDir = Join-Path $RepoRoot "frontend"
$RunDir      = Join-Path $RepoRoot ".run"
$LogDir      = Join-Path $RunDir "logs"
$VenvDir     = Join-Path $BackendDir ".venv"
$VenvPy      = Join-Path $VenvDir "Scripts\python.exe"
$EnvFile     = Join-Path $BackendDir ".env"

$ApiPort     = 8000
$WebPort     = 5173
$RequiredPythonMinor = 11   # Python 3.11+

New-Item -ItemType Directory -Force -Path $RunDir, $LogDir | Out-Null

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
function Write-Title([string]$Text) {
    Write-Host ""
    Write-Host ("=" * 72) -ForegroundColor DarkCyan
    Write-Host ("  " + $Text) -ForegroundColor Cyan
    Write-Host ("=" * 72) -ForegroundColor DarkCyan
}
function Write-Step([string]$Text) { Write-Host ("[*] " + $Text) -ForegroundColor White }
function Write-Ok([string]$Text)   { Write-Host ("[OK] " + $Text) -ForegroundColor Green }
function Write-Warn2([string]$Text){ Write-Host ("[!] " + $Text) -ForegroundColor Yellow }
function Write-Err2([string]$Text) { Write-Host ("[x] " + $Text) -ForegroundColor Red }

function Fail([string]$Message, [string]$Hint) {
    Write-Err2 $Message
    if ($Hint) { Write-Host ("    -> " + $Hint) -ForegroundColor Yellow }
    exit 1
}

function Invoke-Exe {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [string]$WorkingDirectory = $RepoRoot,
        [switch]$Quiet
    )
    if ($Quiet) {
        $out = & $FilePath @Arguments 2>&1
    } else {
        Push-Location $WorkingDirectory
        try { & $FilePath @Arguments 2>&1 | ForEach-Object { Write-Host $_ } }
        finally { Pop-Location }
        return
    }
    return $out
}

function Test-PortInUse([int]$Port) {
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $iar = $client.BeginConnect("127.0.0.1", $Port, $null, $null)
        $ok = $iar.AsyncWaitHandle.WaitOne(300, $false)
        if ($ok -and $client.Connected) { $client.Close(); return $true }
        $client.Close()
        return $false
    } catch { return $false }
}

function Get-PythonInfo {
    # Returns @{ Exe = "py"|"python"; PreArgs = @("-3"); Version = "3.13.1" } or $null
    $candidates = @(
        @{ Exe = "py";     Pre = @("-3") },
        @{ Exe = "python"; Pre = @() },
        @{ Exe = "python3";Pre = @() }
    )
    foreach ($c in $candidates) {
        $exe = Get-Command $c.Exe -ErrorAction SilentlyContinue
        if (-not $exe) { continue }
        try {
            $raw = & $c.Exe @($c.Pre + @("-c", "import sys;print('%d.%d.%d' % sys.version_info[:3])")) 2>$null
            if (-not $raw) { continue }
            $ver = ($raw | Select-Object -First 1).ToString().Trim()
            if ($ver -match '^(\d+)\.(\d+)\.(\d+)$') {
                return @{ Exe = $c.Exe; PreArgs = $c.Pre; Version = $ver; Major = [int]$Matches[1]; Minor = [int]$Matches[2] }
            }
        } catch { continue }
    }
    return $null
}

function Get-NpmCommand {
    # PowerShell blocks npm.ps1 when the execution policy is Restricted -> use npm.cmd
    $cmd = Get-Command "npm.cmd" -ErrorAction SilentlyContinue
    if ($cmd) { return "npm.cmd" }
    $cmd = Get-Command "npm" -ErrorAction SilentlyContinue
    if ($cmd) { return "npm" }
    return $null
}

function Get-NodeVersion {
    $node = Get-Command "node" -ErrorAction SilentlyContinue
    if (-not $node) { return $null }
    try { return (& node --version 2>$null).ToString().Trim() } catch { return $null }
}

function Ensure-Venv([switch]$Create) {
    if (Test-Path $VenvPy) { return $true }
    if (-not $Create) { Fail "Python virtual environment not found: $VenvDir" "Run:  scripts\nexus.cmd setup" }
    $py = Get-PythonInfo
    if (-not $py) { Fail "Python was not found on this machine." "Install Python 3.11+ from https://www.python.org/downloads/ and enable 'Add python.exe to PATH'." }
    Write-Step ("Creating virtual environment with " + $py.Exe + " " + $py.Version + " ...")
    & $py.Exe @($py.PreArgs + @("-m", "venv", $VenvDir))
    if (-not (Test-Path $VenvPy)) { Fail "Failed to create the virtual environment." "Check that the path has no permission problems: $VenvDir" }
    Write-Ok "Virtual environment created."
    return $true
}

function Load-EnvFile([string]$Path) {
    $map = @{}
    if (-not (Test-Path $Path)) { return $map }
    foreach ($line in Get-Content -LiteralPath $Path) {
        $t = $line.Trim()
        if ($t -eq "" -or $t.StartsWith("#")) { continue }
        $i = $t.IndexOf("=")
        if ($i -lt 1) { continue }
        $k = $t.Substring(0, $i).Trim()
        $v = $t.Substring($i + 1).Trim()
        $map[$k] = $v
    }
    return $map
}

function Test-ApiHealth {
    try {
        $r = Invoke-RestMethod -Uri ("http://127.0.0.1:" + $ApiPort + "/api/v1/system/health") -TimeoutSec 4 -UseBasicParsing
        return $r
    } catch { return $null }
}

function Stop-Tracked([string]$Name) {
    $pidFile = Join-Path $RunDir ($Name + ".pid")
    if (-not (Test-Path $pidFile)) { Write-Warn2 ($Name + ": no pid file (not started by this script)."); return }
    $procId = (Get-Content -LiteralPath $pidFile -Raw).Trim()
    if ($procId -match '^\d+$') {
        $p = Get-Process -Id ([int]$procId) -ErrorAction SilentlyContinue
        if ($p) {
            Write-Step ("Stopping " + $Name + " (pid " + $procId + ") ...")
            # Kill the whole process tree (uvicorn/vite spawn children)
            try { & taskkill.exe /PID $procId /T /F | Out-Null } catch { try { Stop-Process -Id ([int]$procId) -Force } catch {} }
            Write-Ok ($Name + " stopped.")
        } else {
            Write-Warn2 ($Name + ": process " + $procId + " is not running.")
        }
    }
    Remove-Item -LiteralPath $pidFile -Force -ErrorAction SilentlyContinue
}

function Show-Help {
    Write-Title "NEXUS CYBER DEFENSE - launcher"
    Write-Host @"
Usage:  scripts\nexus.cmd <command> [args]

  doctor    Check Python / Node / npm / ports / disk before setup
  setup     Create venv, install dependencies, write .env, migrate, seed admin
  launch    One-click: start if needed, then open the web UI
  start     Start API + Web in the background  (logs: .run\logs)
  dev       Run API + Web in the foreground with auto-reload
  stop      Stop background processes
  status    Show processes, ports, API health
  logs [N] [api|web|both]   Tail logs (default: 80 lines, both)
  test      Run backend tests (pytest) and frontend tests + build
  migrate   Apply database migrations
  seed      (Re)create the bootstrap admin account
  reset-db  DEV ONLY: delete local SQLite DB and re-migrate
  build     Build the production frontend into frontend\dist
  open      Open the web UI in the default browser
  help      Show this help

First run:   scripts\nexus.cmd doctor
Then:        scripts\nexus.cmd setup
Finally:     scripts\nexus.cmd start      (then: scripts\nexus.cmd open)
"@
}

# --------------------------------------------------------------------------
# doctor
# --------------------------------------------------------------------------
function Cmd-Doctor {
    Write-Title "NEXUS doctor - environment check"
    $fails = 0

    # OS
    $os = [System.Environment]::OSVersion.Version
    Write-Step ("Windows version: " + $os.ToString() + "  (" + [System.Environment]::OSVersion.VersionString + ")")
    if ($os.Major -lt 10) { Write-Warn2 "Windows 10 or newer is recommended."; }

    # PowerShell
    Write-Step ("PowerShell: " + $PSVersionTable.PSVersion.ToString() + "  (5.1+ supported)")

    # Python
    $py = Get-PythonInfo
    if ($py) {
        Write-Ok ("Python found: " + $py.Exe + " " + ($py.PreArgs -join " ") + "  version " + $py.Version)
        if ($py.Minor -lt $RequiredPythonMinor) {
            Write-Err2 ("Python 3." + $RequiredPythonMinor + "+ is required, found " + $py.Version)
            Write-Host "    -> Install a newer Python from https://www.python.org/downloads/windows/" -ForegroundColor Yellow
            $fails++
        }
    } else {
        Write-Err2 "Python not found."
        Write-Host "    -> Install Python 3.11+ from https://www.python.org/downloads/ and check 'Add python.exe to PATH'." -ForegroundColor Yellow
        $fails++
    }

    # Node + npm
    $nodeVer = Get-NodeVersion
    if ($nodeVer) {
        Write-Ok ("Node.js found: " + $nodeVer)
        $major = [int](($nodeVer -replace '^v', '') -split '\.')[0]
        if ($major -lt 18) {
            Write-Err2 "Node.js 18+ is required (found $nodeVer)."
            Write-Host "    -> Install Node.js LTS from https://nodejs.org/en/download" -ForegroundColor Yellow
            $fails++
        }
    } else {
        Write-Err2 "Node.js not found."
        Write-Host "    -> Install Node.js LTS from https://nodejs.org/en/download" -ForegroundColor Yellow
        $fails++
    }

    $npm = Get-NpmCommand
    if ($npm) {
        $npmVer = (& $npm --version 2>$null)
        Write-Ok ("npm found: " + $npm + "  version " + $npmVer)
        if ($npm -eq "npm") {
            Write-Warn2 "npm.ps1 may be blocked by the execution policy - always use scripts\nexus.cmd (it uses npm.cmd)."
        }
    } else {
        Write-Err2 "npm not found (it ships with Node.js)."
        $fails++
    }

    # Ports
    foreach ($p in @($ApiPort, $WebPort)) {
        if (Test-PortInUse $p) { Write-Warn2 ("Port " + $p + " is already in use. Stop the other process or change the port.") }
        else { Write-Ok ("Port " + $p + " is free.") }
    }

    # Virtual env / deps
    if (Test-Path $VenvPy) { Write-Ok ("Virtual environment present: " + $VenvDir) }
    else { Write-Warn2 "Virtual environment not created yet -> run: scripts\nexus.cmd setup" }

    if (Test-Path (Join-Path $BackendDir ".env")) { Write-Ok "backend\.env present." }
    else { Write-Warn2 "backend\.env not found -> setup will create it from .env.example" }

    if (Test-Path (Join-Path $FrontendDir "node_modules")) { Write-Ok "Frontend dependencies installed." }
    else { Write-Warn2 "frontend\node_modules missing -> run: scripts\nexus.cmd setup" }

    # Disk space
    try {
        $drive = (Get-Item $RepoRoot).PSDrive.Name
        $free = (Get-PSDrive $drive).Free / 1GB
        Write-Step ("Free disk space on " + $drive + ": " + [math]::Round($free, 1) + " GB")
        if ($free -lt 2) { Write-Warn2 "Less than 2 GB free - installing dependencies may fail." }
    } catch {}

    # Optional integrations (informational only)
    $zap = Get-Command "zap" -ErrorAction SilentlyContinue
    $nmap = Get-Command "nmap" -ErrorAction SilentlyContinue
    if ($nmap) { Write-Ok ("nmap found: " + $nmap.Source) } else { Write-Warn2 "nmap not installed - the built-in TCP scanner will be used (real scans, fewer features)." }
    if ($zap)  { Write-Ok ("ZAP found: " + $zap.Source) }  else { Write-Warn2 "OWASP ZAP not installed - built-in web engine will be used. Configure NEXUS_ZAP_URL later for ZAP." }
    if (Test-Path (Join-Path $BackendDir ".env")) {
        $envMap = Load-EnvFile (Join-Path $BackendDir ".env")
        if ($envMap["NEXUS_AI_PROVIDER"] -and $envMap["NEXUS_AI_PROVIDER"] -ne "none" -and $envMap["NEXUS_AI_API_KEY"]) {
            Write-Ok ("AI Copilot provider configured: " + $envMap["NEXUS_AI_PROVIDER"])
        } else {
            Write-Warn2 "AI Copilot is NOT configured (optional). Set NEXUS_AI_PROVIDER + key in backend\.env to enable it."
        }
    }

    Write-Host ""
    if ($fails -gt 0) { Fail "$fails blocking problem(s) found - fix them then run doctor again." }
    Write-Ok "Environment looks good. Next: scripts\nexus.cmd setup"
}

# --------------------------------------------------------------------------
# setup
# --------------------------------------------------------------------------
function Cmd-Setup {
    Write-Title "NEXUS setup"
    Ensure-Venv -Create | Out-Null

    # --- backend deps
    Write-Step "Upgrading pip ..."
    & $VenvPy -m pip install --upgrade pip --quiet
    Write-Step "Installing backend dependencies (this can take a few minutes) ..."
    $req = Join-Path $BackendDir "requirements.txt"
    $reqDev = Join-Path $BackendDir "requirements-dev.txt"
    if (-not (Test-Path $req)) { Fail "requirements.txt not found in $BackendDir" "Is the repository complete?" }
    & $VenvPy -m pip install -r $req
    if ($LASTEXITCODE -ne 0) { Fail "pip install failed for backend dependencies." "Check your internet connection / proxy, then re-run setup." }
    & $VenvPy -m pip install -r $reqDev
    if ($LASTEXITCODE -ne 0) { Fail "pip install failed for dev dependencies." "Check your internet connection / proxy, then re-run setup." }
    Write-Ok "Backend dependencies installed."

    # --- .env
    if (-not (Test-Path $EnvFile)) {
        Write-Step "Creating backend\.env with a freshly generated secret key ..."
        $template = Join-Path $RepoRoot ".env.example"
        if (-not (Test-Path $template)) { Fail ".env.example not found." "Is the repository complete?" }
        $secret = & $VenvPy -c "import secrets;print(secrets.token_urlsafe(48))"
        $content = Get-Content -LiteralPath $template
        $out = foreach ($line in $content) {
            if ($line -match '^NEXUS_SECRET_KEY=') { "NEXUS_SECRET_KEY=$secret" } else { $line }
        }
        Set-Content -LiteralPath $EnvFile -Value $out -Encoding UTF8
        Write-Ok "backend\.env created (secret generated, AI provider = none)."
    } else {
        Write-Ok "backend\.env already exists - left untouched."
    }

    # --- frontend env
    $feEnv = Join-Path $FrontendDir ".env.local"
    if (-not (Test-Path $feEnv)) {
        $feEnvLines = @(
            "# Same-origin in development via the Vite proxy (see vite.config.ts).",
            "VITE_API_BASE_URL=/api/v1",
            ("VITE_DEV_API_TARGET=http://127.0.0.1:" + $ApiPort)
        )
        Set-Content -LiteralPath $feEnv -Value $feEnvLines -Encoding UTF8
        Write-Ok "frontend\.env.local created."
    }

    # --- frontend deps
    $npm = Get-NpmCommand
    if (-not $npm) { Fail "npm not found." "Install Node.js LTS and re-run setup." }
    Write-Step "Installing frontend dependencies (npm install - can take a few minutes) ..."
    Push-Location $FrontendDir
    try {
        & $npm install --no-fund --no-audit
        if ($LASTEXITCODE -ne 0) { Fail "npm install failed." "Try: cd frontend  then  npm.cmd install" }
    } finally { Pop-Location }
    Write-Ok "Frontend dependencies installed."

    # --- database
    Cmd-Migrate
    Cmd-Seed

    Write-Host ""
    Write-Ok "Setup finished."
    Write-Host "    Next:  scripts\nexus.cmd start   then   scripts\nexus.cmd open" -ForegroundColor Cyan
}

# --------------------------------------------------------------------------
# migrate / seed
# --------------------------------------------------------------------------
function Cmd-Migrate {
    Write-Step "Applying database migrations ..."
    Push-Location $BackendDir
    try {
        & $VenvPy -m alembic upgrade head
        if ($LASTEXITCODE -ne 0) { Fail "Migrations failed." "Check backend\.env (NEXUS_DATABASE_URL) and the storage folder permissions." }
    } finally { Pop-Location }
    Write-Ok "Database schema is up to date."
}

function Cmd-Seed {
    Write-Step "Ensuring bootstrap admin account exists ..."
    Push-Location $BackendDir
    try {
        & $VenvPy -m app.cli seed
        if ($LASTEXITCODE -ne 0) { Fail "Seeding failed." "Check backend\.env then run: scripts\nexus.cmd seed" }
    } finally { Pop-Location }
}

# --------------------------------------------------------------------------
# start / dev / stop / status / logs
# --------------------------------------------------------------------------
function Cmd-Start {
    Write-Title "Starting NEXUS (background)"
    Ensure-Venv | Out-Null
    if (-not (Test-Path (Join-Path $FrontendDir "node_modules"))) { Fail "Frontend dependencies are missing." "Run: scripts\nexus.cmd setup" }
    $npm = Get-NpmCommand

    if (Test-PortInUse $ApiPort)  { Fail ("Port " + $ApiPort + " is busy (API already running?)") "Use: scripts\nexus.cmd status  /  scripts\nexus.cmd stop" }
    if (Test-PortInUse $WebPort)  { Fail ("Port " + $WebPort + " is busy (web already running?)") "Use: scripts\nexus.cmd status  /  scripts\nexus.cmd stop" }

    $apiLog = Join-Path $LogDir "api.log"
    $webLog = Join-Path $LogDir "web.log"

    Write-Step "Starting API (uvicorn) ..."
    $api = Start-Process -FilePath $VenvPy `
        -ArgumentList @("-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "$ApiPort", "--log-level", "info") `
        -WorkingDirectory $BackendDir -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $apiLog -RedirectStandardError (Join-Path $LogDir "api.err.log")
    Set-Content -LiteralPath (Join-Path $RunDir "api.pid") -Value $api.Id -Encoding ASCII
    Write-Ok ("API started (pid " + $api.Id + ") -> http://127.0.0.1:" + $ApiPort)

    Write-Step "Starting Web (vite) ..."
    $web = Start-Process -FilePath "cmd.exe" -ArgumentList @("/c", $npm, "run", "dev", "--", "--host", "127.0.0.1", "--port", "$WebPort") `
        -WorkingDirectory $FrontendDir -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $webLog -RedirectStandardError (Join-Path $LogDir "web.err.log")
    Set-Content -LiteralPath (Join-Path $RunDir "web.pid") -Value $web.Id -Encoding ASCII
    Write-Ok ("Web started (pid " + $web.Id + ") -> http://127.0.0.1:" + $WebPort)

    Write-Step "Waiting for the API to become healthy ..."
    $healthy = $false
    for ($i = 1; $i -le 30; $i++) {
        Start-Sleep -Milliseconds 800
        $h = Test-ApiHealth
        if ($h) { $healthy = $true; break }
    }
    if ($healthy) {
        Write-Ok ("API health: " + $h.status + " | version " + $h.version + " | db " + $h.database)
    } else {
        Write-Warn2 "API did not report healthy yet. Check logs:  scripts\nexus.cmd logs 60 api"
    }

    Write-Host ""
    Write-Host ("    Web UI : http://127.0.0.1:" + $WebPort) -ForegroundColor Cyan
    Write-Host ("    API    : http://127.0.0.1:" + $ApiPort + "/docs") -ForegroundColor Cyan
    Write-Host ("    Stop   : scripts\nexus.cmd stop") -ForegroundColor DarkGray
}

function Cmd-Dev {
    Write-Title "NEXUS dev mode (foreground, auto-reload)"
    Ensure-Venv | Out-Null
    $npm = Get-NpmCommand
    if (Test-PortInUse $ApiPort) { Fail ("Port " + $ApiPort + " is busy.") "scripts\nexus.cmd stop" }
    if (Test-PortInUse $WebPort) { Fail ("Port " + $WebPort + " is busy.") "scripts\nexus.cmd stop" }

    Write-Step "Starting API with reload ..."
    $api = Start-Process -FilePath $VenvPy `
        -ArgumentList @("-m", "uvicorn", "app.main:app", "--reload", "--host", "127.0.0.1", "--port", "$ApiPort") `
        -WorkingDirectory $BackendDir -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $LogDir "api.log") -RedirectStandardError (Join-Path $LogDir "api.err.log")
    Set-Content -LiteralPath (Join-Path $RunDir "api.pid") -Value $api.Id -Encoding ASCII
    Write-Ok ("API pid " + $api.Id + " -> http://127.0.0.1:" + $ApiPort + "/docs")

    Write-Host "    Web UI dev server is starting in this window. Press Ctrl+C to stop both." -ForegroundColor Cyan
    try {
        Push-Location $FrontendDir
        & $npm run dev -- --host 127.0.0.1 --port $WebPort
    } finally {
        Pop-Location
        Stop-Tracked "api"
    }
}

function Cmd-Stop {
    Write-Title "Stopping NEXUS"
    Stop-Tracked "api"
    Stop-Tracked "web"
    Write-Ok "Done."
}

function Cmd-Status {
    Write-Title "NEXUS status"
    foreach ($pair in @(@{Name="api"; Port=$ApiPort}, @{Name="web"; Port=$WebPort})) {
        $pidFile = Join-Path $RunDir ($pair.Name + ".pid")
        $state = "not tracked"
        if (Test-Path $pidFile) {
            $procId = (Get-Content -LiteralPath $pidFile -Raw).Trim()
            if ($procId -match '^\d+$' -and (Get-Process -Id ([int]$procId) -ErrorAction SilentlyContinue)) {
                $state = "running (pid " + $procId + ")"
            } else { $state = "stale pid file" }
        }
        $port = if (Test-PortInUse $pair.Port) { "listening" } else { "closed" }
        Write-Host ("  " + $pair.Name.ToUpper().PadRight(4) + " port " + $pair.Port + " : " + $port + "  |  " + $state)
    }
    $h = Test-ApiHealth
    if ($h) {
        Write-Host ""
        Write-Ok ("API healthy: v" + $h.version + " | env " + $h.environment + " | db " + $h.database)
        Write-Host ("     engines: " + ($h.engines | ConvertTo-Json -Compress)) -ForegroundColor DarkGray
    } else {
        Write-Warn2 "API health endpoint is not reachable."
    }
}

function Cmd-Logs {
    $lines = 80
    if ($Arg1 -match '^\d+$') { $lines = [int]$Arg1 }
    $which = "both"
    if ($Arg1 -match '^(api|web|both)$') { $which = $Arg1 }
    if ($Arg2 -match '^(api|web|both)$') { $which = $Arg2 }

    foreach ($name in @("api", "web")) {
        if ($which -ne "both" -and $which -ne $name) { continue }
        $f = Join-Path $LogDir ($name + ".log")
        $ef = Join-Path $LogDir ($name + ".err.log")
        Write-Title ($name.ToUpper() + " log (last " + $lines + " lines)")
        if (Test-Path $f) { Get-Content -LiteralPath $f -Tail $lines } else { Write-Warn2 "no log file yet: $f" }
        if (Test-Path $ef) {
            $errTail = Get-Content -LiteralPath $ef -Tail 20 -ErrorAction SilentlyContinue
            if ($errTail) { Write-Host "-- stderr --" -ForegroundColor DarkYellow; $errTail }
        }
    }
}

# --------------------------------------------------------------------------
# test / build / reset / open
# --------------------------------------------------------------------------
function Cmd-Test {
    Write-Title "NEXUS tests"
    Ensure-Venv | Out-Null
    Write-Step "Backend tests (pytest) ..."
    Push-Location $BackendDir
    try {
        & $VenvPy -m pytest -q
        $code = $LASTEXITCODE
    } finally { Pop-Location }
    if ($code -ne 0) { Write-Err2 "Backend tests failed." } else { Write-Ok "Backend tests passed." }

    $npm = Get-NpmCommand
    Write-Step "Frontend type-check + build ..."
    Push-Location $FrontendDir
    try {
        & $npm run typecheck
        $feCode = $LASTEXITCODE
        if ($feCode -eq 0) { & $npm run build; $feCode = $LASTEXITCODE }
    } finally { Pop-Location }
    if ($feCode -ne 0) { Write-Err2 "Frontend checks failed." } else { Write-Ok "Frontend checks passed." }

    if ($code -ne 0 -or $feCode -ne 0) { exit 1 }
    Write-Ok "All checks passed."
}

function Cmd-Build {
    Write-Title "Building production frontend"
    $npm = Get-NpmCommand
    Push-Location $FrontendDir
    try {
        & $npm run build
        if ($LASTEXITCODE -ne 0) { Fail "Build failed." "Run: cd frontend  then  npm.cmd run build" }
    } finally { Pop-Location }
    Write-Ok ("Build ready: " + (Join-Path $FrontendDir "dist"))
}

function Cmd-ResetDb {
    Write-Title "Reset local database (DEV ONLY)"
    $envMap = Load-EnvFile $EnvFile
    $dbUrl = $envMap["NEXUS_DATABASE_URL"]
    if (-not $dbUrl) { $dbUrl = "sqlite:///./storage/nexus.db" }
    if ($dbUrl -notmatch '^sqlite') { Fail "Refusing to reset a non-SQLite database ($dbUrl)." "Drop it manually if you really mean it." }
    $rel = $dbUrl -replace '^sqlite:///', ''
    $dbPath = Join-Path $BackendDir $rel
    if (Test-Path $dbPath) {
        $backup = $dbPath + ".backup-" + (Get-Date -Format "yyyyMMdd-HHmmss")
        Copy-Item -LiteralPath $dbPath -Destination $backup
        Write-Warn2 ("Backup saved: " + $backup)
        Remove-Item -LiteralPath $dbPath -Force
        Remove-Item -LiteralPath ($dbPath + "-wal") -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath ($dbPath + "-shm") -Force -ErrorAction SilentlyContinue
        Write-Ok "Database file deleted."
    } else { Write-Warn2 "No database file found at $dbPath" }
    Cmd-Migrate
    Cmd-Seed
}

function Cmd-Open {
    # Prefer the single-origin production build served by the API. Fall back
    # to the Vite dev server when frontend\dist has not been built yet.
    $distIndex = Join-Path $FrontendDir "dist\index.html"
    if (Test-Path $distIndex) {
        Start-Process ("http://127.0.0.1:" + $ApiPort)
        Write-Ok ("Opened http://127.0.0.1:" + $ApiPort + " (production build)")
        return
    }
    Start-Process ("http://127.0.0.1:" + $WebPort)
    Write-Ok ("Opened http://127.0.0.1:" + $WebPort)
}

function Cmd-Launch {
    Write-Title "NEXUS launch"
    # One-click experience: install dependencies / generate .env on first run.
    if (-not (Test-Path $VenvPy) -or -not (Test-Path (Join-Path $FrontendDir "node_modules")) -or -not (Test-Path $EnvFile)) {
        Write-Warn2 "First run detected - installing dependencies and preparing the local environment."
        Cmd-Setup
    }
    if (-not (Test-PortInUse $ApiPort)) {
        Cmd-Start
    } else {
        $h = Test-ApiHealth
        if ($h) {
            Write-Ok ("API already running: v" + $h.version + " | env " + $h.environment)
        } else {
            Write-Warn2 "Port $ApiPort is busy but the NEXUS health endpoint did not answer."
            Write-Host "    Stop the other process or run: scripts\nexus.cmd status" -ForegroundColor DarkGray
        }
    }
    Cmd-Open
}

# --------------------------------------------------------------------------
# Dispatch
# --------------------------------------------------------------------------
switch ($Command.ToLower()) {
    "doctor"   { Cmd-Doctor }
    "setup"    { Cmd-Setup }
    "start"    { Cmd-Start }
    "dev"      { Cmd-Dev }
    "stop"     { Cmd-Stop }
    "status"   { Cmd-Status }
    "logs"     { Cmd-Logs }
    "test"     { Cmd-Test }
    "migrate"  { Cmd-Migrate }
    "seed"     { Cmd-Seed }
    "reset-db" { Cmd-ResetDb }
    "build"    { Cmd-Build }
    "open"     { Cmd-Open }
    "launch"   { Cmd-Launch }
    "help"     { Show-Help }
    default    { Write-Err2 ("Unknown command: " + $Command); Show-Help; exit 1 }
}
