# setup-secure.ps1 - one-command PRODUCTION (HTTPS) setup for DockVault on Windows.
#
# The Windows counterpart of deploy/setup-secure.sh: it writes ./.env with freshly generated
# secrets, provisions TLS certificates into ./certs, and starts the HTTPS-only stack from
# deploy/docker-compose.secure.yml (web UI/API on https://<name>, TLS terminated in-container; no
# plaintext listener). Postgres + Redis stay internal to the compose network.
#
# Requires Docker Desktop (Linux containers). The script lives in deploy/ but anchors
# itself at the repo root (where .env + certs/ live). Run it from the repo root in PowerShell:
#
#   ./deploy/setup-secure.ps1 -ServerName vault.example.com                 # self-signed (default)
#   ./deploy/setup-secure.ps1 -ServerName vault.example.com -CertMode byo `
#                             -CertPath C:\certs\fullchain.pem -KeyPath C:\certs\privkey.pem
#   ./deploy/setup-secure.ps1 -ServerName vault.example.com -EnableSftp     # also expose SFTP
#   ./deploy/setup-secure.ps1 -ServerName vault.example.com -NoStart        # set up, do not start
#
# Idempotent: re-running reuses an existing ./.env (keeps your data + secrets) and only
# (re)builds/starts. To start completely fresh, run
# `docker compose --env-file .env -f deploy/docker-compose.secure.yml down -v`, then delete ./.env.
#
# For a real public certificate use -CertMode byo with a cert you obtained yourself (your CA,
# a reverse proxy, or Let's Encrypt on a Linux host / via win-acme). Let's Encrypt issuance is
# not automated here (it needs port 80 + ACME tooling); self-signed is for testing production.

[CmdletBinding()]
param(
    [string] $ServerName,
    [ValidateSet('selfsigned', 'byo')]
    [string] $CertMode = 'selfsigned',
    [string] $CertPath,
    [string] $KeyPath,
    [switch] $EnableSftp,
    [switch] $NoStart
)

# The native tools here (docker, openssl, icacls) write progress + warnings to STDERR even on a
# fully successful run. Under ErrorActionPreference='Stop', Windows PowerShell 5.1 turns that stderr
# into a TERMINATING error, so a healthy `docker info` (which prints cgroup/blkio warnings) would
# abort the script. We therefore keep 'Continue' and check each native command's EXIT CODE explicitly.
$ErrorActionPreference = 'Continue'
Set-StrictMode -Version 2.0

# This script lives in deploy/ - the repo ROOT (parent dir) is where .env and certs/ live.
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root      = Split-Path -Parent $ScriptDir
$EnvFile   = Join-Path $Root '.env'
$CertDir   = Join-Path $Root 'certs'
# Absolute path so `docker compose` finds the file no matter which directory the script is
# invoked from. NB: compose's default project directory is the -f file's dir (deploy/), so
# every invocation below passes --env-file $EnvFile to anchor .env interpolation and
# COMPOSE_PROFILES at the repo root; the compose file's own relative paths (build context,
# env_file, certs bind) are written relative to deploy/ and resolve to the root by themselves.
$Compose = Join-Path $Root 'deploy\docker-compose.secure.yml'

function Say  ([string] $m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Warn ([string] $m) { Write-Host "WARNING: $m" -ForegroundColor Yellow }
function Die  ([string] $m) { Write-Host "ERROR: $m" -ForegroundColor Red; exit 1 }

# --- preflight ------------------------------------------------------------------------------
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Die 'docker was not found on PATH. Install Docker Desktop (Linux containers) and retry.'
}
# Gate on the exit code, not on stderr: a healthy engine prints warnings to stderr but exits 0.
docker info *> $null
if ($LASTEXITCODE -ne 0) { Die 'the Docker engine is not reachable. Start Docker Desktop and retry.' }
if (-not (Test-Path $Compose)) { Die 'deploy/docker-compose.secure.yml not found - run this script from its repository checkout.' }

if (-not $ServerName) {
    $ServerName = Read-Host 'Server name (DNS name or IP clients will use, e.g. vault.example.com)'
}
if (-not $ServerName) { Die 'a server name is required.' }
# Reject anything that is not a plain host name / IP: ServerName flows into the .env (single-quoted),
# the TLS cert subject/SAN and docker args, so restrict it to a safe character set to avoid injection.
if ($ServerName -notmatch '^[A-Za-z0-9.-]+$') {
    Die "invalid server name '$ServerName' (use letters, digits, dots and hyphens only)."
}

New-Item -ItemType Directory -Force -Path $CertDir -ErrorAction Stop | Out-Null

# --- secret generation (pure .NET; no OpenSSL needed) ---------------------------------------
function New-RandomBytes ([int] $n) {
    $b = New-Object 'byte[]' $n
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($b) } finally { $rng.Dispose() }
    return $b
}
function New-HexSecret     ([int] $bytes) { -join ((New-RandomBytes $bytes) | ForEach-Object { $_.ToString('x2') }) }
function New-FernetKey {
    # 32 random bytes, url-safe base64 (matches: openssl rand -base64 32 | tr '+/' '-_')
    ([Convert]::ToBase64String((New-RandomBytes 32))).Replace('+', '-').Replace('/', '_')
}

# --- certificates ---------------------------------------------------------------------------
# On Docker Desktop a bind-mounted ./certs is readable by the in-container app user, so no
# ownership fix-up is needed (unlike the Linux userns-remap case deploy/setup-secure.sh handles).

# Run OpenSSL from the host if present, otherwise via a throwaway container so the host needs
# nothing but Docker. Args run with the certs dir as the working directory.
function Invoke-OpenSSL {
    param([Parameter(Mandatory = $true)][string[]] $OsslArgs)
    $openssl = Get-Command openssl -ErrorAction SilentlyContinue
    if ($openssl) {
        Push-Location $CertDir
        try { return (& $openssl.Source @OsslArgs 2>$null) } finally { Pop-Location }
    }
    return (docker run --rm -v "${CertDir}:/certs" -w /certs alpine/openssl @OsslArgs 2>$null)
}

function Copy-ByoCert {
    if (-not $CertPath -or -not $KeyPath) { Die '-CertMode byo requires -CertPath and -KeyPath.' }
    if (-not (Test-Path $CertPath)) { Die "certificate not found: $CertPath" }
    if (-not (Test-Path $KeyPath))  { Die "private key not found: $KeyPath" }
    $keyText = Get-Content -Raw $KeyPath -ErrorAction Stop
    if ($keyText -match 'ENCRYPTED') {
        Die "the private key '$KeyPath' is passphrase-encrypted; the server cannot use it. Decrypt it first."
    }
    Copy-Item -Force $CertPath (Join-Path $CertDir 'cert.pem') -ErrorAction Stop
    Copy-Item -Force $KeyPath  (Join-Path $CertDir 'key.pem')  -ErrorAction Stop
    # Best-effort: confirm the cert and key are a matching pair (a mismatch fails TLS at startup with
    # an opaque error). Enforced only when OpenSSL is reachable; otherwise warn rather than block.
    $certPub = Invoke-OpenSSL @('x509', '-in', 'cert.pem', '-pubkey', '-noout')
    $keyPub  = Invoke-OpenSSL @('pkey', '-in', 'key.pem', '-pubout')
    if ($certPub -and $keyPub) {
        if ((($certPub -join "`n").Trim()) -ne (($keyPub -join "`n").Trim())) {
            Die 'the provided certificate and private key are not a matching pair.'
        }
    } else {
        Warn 'could not verify the cert/key pair (OpenSSL unavailable); make sure they match.'
    }
    Say "installed bring-your-own certificate for $ServerName"
}

function Test-CertPair {
    (Test-Path (Join-Path $CertDir 'cert.pem')) -and (Test-Path (Join-Path $CertDir 'key.pem'))
}

function New-SelfSignedCert {
    # Self-signed, RSA 4096, 825 days, with the server name as CN + SAN.
    $san = "DNS:$ServerName"
    if ($ServerName -match '^\d{1,3}(\.\d{1,3}){3}$') { $san = "IP:$ServerName" }
    Say "generating a self-signed certificate for $ServerName (RSA 4096, 825 days)"
    $osslArgs = @(
        'req', '-x509', '-newkey', 'rsa:4096', '-sha256', '-days', '825', '-nodes',
        '-keyout', 'key.pem', '-out', 'cert.pem', '-subj', "/CN=$ServerName",
        '-addext', "subjectAltName=$san"
    )
    $diag = ''

    # 1) Prefer a host OpenSSL if present (fast, no image pull). Capture its output (2>&1) so a
    #    failure is DIAGNOSABLE instead of being silently swallowed.
    $openssl = Get-Command openssl -ErrorAction SilentlyContinue
    if ($openssl) {
        Push-Location $CertDir
        try { $out = & $openssl.Source @osslArgs 2>&1 } finally { Pop-Location }
        if ($LASTEXITCODE -ne 0 -or -not (Test-CertPair)) {
            $diag = "host OpenSSL (exit $LASTEXITCODE): " + (($out | Out-String).Trim())
            Warn 'host OpenSSL did not produce a certificate; falling back to a throwaway Docker container.'
        }
    }

    # 2) Fall back to a throwaway alpine/openssl container (needs only Docker, already required
    #    above) when the host tool is missing OR failed. The Linux openssl also sidesteps Windows
    #    -subj path mangling by an MSYS/Git-based openssl.
    if (-not (Test-CertPair)) {
        $out = docker run --rm -v "${CertDir}:/certs" -w /certs alpine/openssl @osslArgs 2>&1
        if ($LASTEXITCODE -ne 0) {
            if ($diag) { $diag += "`n" }
            $diag += "docker openssl (exit $LASTEXITCODE): " + (($out | Out-String).Trim())
        }
    }

    if (-not (Test-CertPair)) {
        Die ("certificate generation failed (no cert.pem/key.pem produced).`n$diag`n" +
             'Ensure Docker Desktop is running (the script can generate the cert via a throwaway ' +
             'alpine/openssl container), or install a working OpenSSL.')
    }
}

$certExists = (Test-Path (Join-Path $CertDir 'cert.pem')) -and (Test-Path (Join-Path $CertDir 'key.pem'))
if ($CertMode -eq 'byo') {
    Copy-ByoCert
} elseif (-not $certExists) {
    New-SelfSignedCert
} else {
    Say 'reusing existing ./certs (pass -CertMode byo or delete ./certs to replace)'
}

# --- .env (secrets) -------------------------------------------------------------------------
# The compose file sets ENVIRONMENT=production, API_USE_HTTPS=true and the cert paths; .env
# only carries the secrets + host name (+ optional SFTP profile). Reused as-is if present.
if (Test-Path $EnvFile) {
    Say 'reusing existing ./.env (delete it to regenerate secrets)'
} else {
    Say 'writing ./.env with freshly generated secrets'
    $lines = @(
        "ENCRYPTION_KEY='$(New-FernetKey)'",
        "JWT_SECRET_KEY='$(New-HexSecret 32)'",
        "VAULT_DB_PASSWORD='$(New-HexSecret 16)'",
        "REDIS_PASSWORD='$(New-HexSecret 24)'",
        "ALLOWED_HOSTS='$ServerName'",
        "SERVER_NAME='$ServerName'"
    )
    if ($EnableSftp) { $lines += 'COMPOSE_PROFILES=sftp' }
    # ASCII, no BOM: the app and docker compose read this as a plain env file.
    [System.IO.File]::WriteAllText($EnvFile, (($lines -join "`n") + "`n"), (New-Object System.Text.ASCIIEncoding))
    # Best-effort: this file holds every secret, so drop inherited ACLs and grant only the current
    # user + local admins. A no-op-with-warning if icacls is unavailable or refuses.
    icacls $EnvFile /inheritance:r /grant:r "$($env:USERNAME):(R,W)" 'BUILTIN\Administrators:(F)' 'NT AUTHORITY\SYSTEM:(F)' *> $null
    if ($LASTEXITCODE -ne 0) { Warn 'could not tighten ./.env permissions; it holds all secrets - restrict it yourself.' }
}

# --- start ----------------------------------------------------------------------------------
if ($NoStart) {
    Say 'setup complete (-NoStart): start it from the repo root with'
    Write-Host "    docker compose --env-file .env -f deploy/docker-compose.secure.yml up -d --build"
    exit 0
}

Say 'building and starting the HTTPS stack'
docker compose --env-file $EnvFile -f $Compose up -d --build
if ($LASTEXITCODE -ne 0) { Die 'docker compose failed to start the stack.' }

Write-Host ''
Say 'DockVault is starting.'
Write-Host "    URL   : https://$ServerName"
if ($CertMode -eq 'selfsigned') {
    Write-Host '    Cert  : self-signed (browsers will warn; use -CertMode byo with a real cert for public use)'
}
$sftpState = 'disabled'
if ($EnableSftp) { $sftpState = 'enabled (host port 2322 by default; set SFTP_HOST_PORT in .env to change)' }
Write-Host "    SFTP  : $sftpState"
Write-Host '    Back up ENCRYPTION_KEY from ./.env off-host: without it, stored files are unrecoverable.'
Write-Host '    Open the URL and complete the first-run wizard to create your admin account.'
