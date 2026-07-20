# setup-secure.ps1 - one-command PRODUCTION (HTTPS) setup for DockVault on Windows.
#
# The Windows counterpart of ./setup-secure.sh: it writes ./.env with freshly generated
# secrets, provisions TLS certificates into ./certs, and starts the HTTPS-only stack from
# deploy/docker-compose.secure.yml (web UI/API on https://<name>, TLS terminated in-container; no
# plaintext listener). Postgres + Redis stay internal to the compose network.
#
# Requires Docker Desktop (Linux containers). The script lives in deploy/ but anchors
# itself at the repo root (where .env + certs/ live). Run it from the repo root in PowerShell:
#
#   ./setup-secure.ps1 -ServerName vault.example.com                 # self-signed (default)
#   ./setup-secure.ps1 -ServerName vault.example.com -CertMode byo `
#                             -CertPath C:\certs\fullchain.pem -KeyPath C:\certs\privkey.pem
#   ./setup-secure.ps1 -ServerName vault.example.com -EnableSftp     # also expose SFTP
#   ./setup-secure.ps1 -ServerName vault.example.com -AdminPassword 'a-strong-12+char-pass'
#   ./setup-secure.ps1 -ServerName vault.example.com -NoStart        # set up, do not start
#
# The first admin account is created at startup from ADMIN_USERNAME/ADMIN_PASSWORD (written to
# .env). If you don't pass -AdminPassword it prompts, and a blank answer auto-generates a strong
# password and prints it ONCE at the end. There is no separate web setup wizard.
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
    [string] $AdminUsername,
    [string] $AdminEmail,
    [string] $AdminPassword,
    [switch] $NoStart
)

# The native tools here (docker, openssl, icacls) write progress + warnings to STDERR even on a
# fully successful run. Under ErrorActionPreference='Stop', Windows PowerShell 5.1 turns that stderr
# into a TERMINATING error, so a healthy `docker info` (which prints cgroup/blkio warnings) would
# abort the script. We therefore keep 'Continue' and check each native command's EXIT CODE explicitly.
$ErrorActionPreference = 'Continue'
Set-StrictMode -Version 2.0

# This script lives at the repo ROOT - where .env and certs/ live.
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root      = $ScriptDir
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

# --- prompt for any CORE option not given on the command line -------------------------------
# These choices are security-relevant, so we don't silently assume a default: if a flag wasn't
# passed, ask. A fully-scripted caller that passes every core flag (-CertMode, -EnableSftp, and
# -CertPath/-KeyPath for byo) is never prompted; a partial invocation is completed interactively.
if (-not $PSBoundParameters.ContainsKey('CertMode')) {
    Write-Host ''
    Write-Host 'TLS certificate for the HTTPS listener:'
    Write-Host '  [1] self-signed      - quick; browsers show a warning (testing / private LAN use)'
    Write-Host '  [2] bring-your-own   - a real certificate you already have (public / trusted use)'
    $choice = Read-Host 'Choose 1 or 2 [1]'
    $CertMode = if ($choice -eq '2') { 'byo' } else { 'selfsigned' }
}
if ($CertMode -eq 'byo') {
    if (-not $CertPath) { $CertPath = Read-Host 'Path to the certificate file (e.g. fullchain.pem)' }
    if (-not $KeyPath)  { $KeyPath  = Read-Host 'Path to the private key file (e.g. privkey.pem)' }
}
if (-not $PSBoundParameters.ContainsKey('EnableSftp')) {
    $ans = Read-Host 'Expose SFTP file access (SSH-based, host port 2322)? [y/N]'
    $EnableSftp = ($ans -match '^(y|yes)$')
}
Say ("configuration: cert=$CertMode, SFTP=" + ($(if ($EnableSftp) { 'enabled' } else { 'disabled' })) + ", server=$ServerName")

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
# The cert + key are bind-mounted read-only into the container and read by uvicorn as the non-root
# app user (uid 10001). OpenSSL writes the key mode 0600 owned by root, so that user cannot read it
# (uvicorn then dies with a TLS-key PermissionError). Set-CertReadable (below) fixes the mode after
# generation; the Linux ./setup-secure.sh does the equivalent via a numeric chown.

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
    #    failure is DIAGNOSABLE instead of being silently swallowed. A Git-for-Windows / MSYS
    #    OpenSSL rewrites a leading-slash argument like -subj "/CN=host" into a Windows path
    #    ("C:/Program Files/Git/CN=host"), which corrupts the subject and fails the command;
    #    MSYS_NO_PATHCONV / MSYS2_ARG_CONV_EXCL disable that translation for this call.
    $openssl = Get-Command openssl -ErrorAction SilentlyContinue
    if ($openssl) {
        $savedPC = $env:MSYS_NO_PATHCONV; $savedCE = $env:MSYS2_ARG_CONV_EXCL
        $env:MSYS_NO_PATHCONV = '1'; $env:MSYS2_ARG_CONV_EXCL = '*'
        Push-Location $CertDir
        try { $out = & $openssl.Source @osslArgs 2>&1 }
        finally {
            Pop-Location
            $env:MSYS_NO_PATHCONV = $savedPC; $env:MSYS2_ARG_CONV_EXCL = $savedCE
        }
        if ($LASTEXITCODE -ne 0 -or -not (Test-CertPair)) {
            $diag = "host OpenSSL (exit $LASTEXITCODE): " + (($out | Out-String).Trim())
            Warn 'host OpenSSL could not generate the certificate; using Docker to generate it instead (this is fine).'
        }
    }

    # 2) Generate via a throwaway (--rm) alpine/openssl container: a one-shot container that runs
    #    OpenSSL against the mounted ./certs and is then deleted, so the host needs nothing but the
    #    already-required Docker. Used when there is no host OpenSSL, or the host one failed. The
    #    Linux OpenSSL here also sidesteps the Windows -subj path mangling entirely.
    if (-not (Test-CertPair)) {
        if (-not $openssl) { Say 'generating the certificate via a throwaway Docker container (no host OpenSSL needed)' }
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

function Set-CertReadable {
    # The web/API container runs uvicorn as the NON-ROOT app user (uid 10001  -  see the Dockerfile).
    # OpenSSL writes key.pem mode 0600 owned by root, so that user cannot read it and uvicorn aborts
    # at startup with "PermissionError: [Errno 13] Permission denied" loading the TLS key.
    #
    # The Linux setup-secure.sh makes the app user OWN the key (numeric chown to uid 10001, keeping
    # mode 0600). On Docker Desktop, though, a container-side chown to a Windows bind mount does NOT
    # reliably stick, so we cannot depend on ownership  -  but chmod IS honoured (that mode 0600 is
    # exactly what blocks the app user). So make the files world-READABLE within ./certs: the cert is
    # public anyway, and for the key this matches the Linux script's own fallback for when a numeric
    # chown is refused. This is safe for the self-hosted single-tenant model: ./certs is on the
    # operator's host, the key is bind-mounted READ-ONLY into the one app container, and the real
    # application secrets live in the separately ACL-locked ./.env. (A BYO cert on a shared host can
    # be tightened afterwards once the right container gid is known.) Run from a throwaway root
    # container so it works regardless of the host OS. Idempotent  -  safe to run every time.
    if (-not (Test-CertPair)) { return }
    docker run --rm -v "${CertDir}:/certs" alpine sh -c 'chmod 0644 /certs/cert.pem /certs/key.pem' *> $null
    if ($LASTEXITCODE -ne 0) {
        Warn 'could not adjust ./certs permissions; if the API logs a TLS-key PermissionError, chmod the key so uid 10001 can read it.'
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
# Ensure the non-root container user can read the cert+key (covers self-signed, BYO, AND a re-run
# over pre-existing root-owned certs that would otherwise still fail).
Set-CertReadable

# --- .env (secrets) -------------------------------------------------------------------------
# The compose file sets ENVIRONMENT=production, API_USE_HTTPS=true and the cert paths; .env
# only carries the secrets + host name (+ optional SFTP profile). Reused as-is if present.
#
# The FIRST ADMIN account is created by the app at startup from ADMIN_USERNAME/ADMIN_PASSWORD in
# .env (there is NO separate setup screen); it is a no-op once an admin exists. So .env MUST carry
# an ADMIN_PASSWORD, or the login page has no account. These carry the seeded admin to the summary.
$SeedAdminUser = $null   # username to show at the end
$SeedAdminPw   = $null   # generated password to show ONCE (null when the operator supplied their own)
if (Test-Path $EnvFile) {
    Say 'reusing existing ./.env (delete it to regenerate secrets)'
    # A .env written before admin-seeding (e.g. by an older copy of this script) may have NO
    # ADMIN_PASSWORD, in which case no admin is created and login has no valid account. Warn + guide.
    $envText = Get-Content -Raw $EnvFile -ErrorAction SilentlyContinue
    if ($envText -notmatch "(?m)^\s*ADMIN_PASSWORD\s*=\s*\S") {
        Warn 'your existing ./.env has no ADMIN_PASSWORD, so NO admin account will be created (the login page will have no valid account).'
        Write-Host "    Fix it: add these lines to ./.env, then re-run this script (or restart the stack):"
        Write-Host "        ADMIN_USERNAME='admin'"
        Write-Host "        ADMIN_PASSWORD='$(New-HexSecret 12)'   # example - a strong 12+ char value"
        Write-Host "    Restart:  docker compose --env-file .env -f deploy/docker-compose.secure.yml up -d"
    }
} else {
    Say 'writing ./.env with freshly generated secrets'

    # Resolve the first-admin credentials. ENVIRONMENT=production (set by the compose file) requires a
    # STRONG password (>= 12 chars, not a known placeholder) or the container refuses to boot.
    if (-not $AdminUsername) { $AdminUsername = 'admin' }
    if (-not $AdminEmail)    { $AdminEmail    = 'admin@example.com' }
    if (-not $AdminPassword -and -not $PSBoundParameters.ContainsKey('AdminPassword')) {
        $AdminPassword = Read-Host 'Admin password (leave blank to auto-generate a strong one and show it once)'
    }
    if (-not $AdminPassword) {
        $AdminPassword = New-HexSecret 12   # 24 hex chars: well over the 12-char floor, dotenv-safe
        $SeedAdminPw   = $AdminPassword     # remember to print it once at the end
    } else {
        if ($AdminPassword.Length -lt 12) { Die 'ADMIN_PASSWORD must be at least 12 characters (production requirement).' }
    }
    if ($AdminPassword -match "'" -or $AdminUsername -match "'") {
        Die 'ADMIN_USERNAME / ADMIN_PASSWORD must not contain a single quote (it breaks .env quoting).'
    }
    $SeedAdminUser = $AdminUsername

    $lines = @(
        "ENCRYPTION_KEY='$(New-FernetKey)'",
        "JWT_SECRET_KEY='$(New-HexSecret 32)'",
        "VAULT_DB_PASSWORD='$(New-HexSecret 16)'",
        "REDIS_PASSWORD='$(New-HexSecret 24)'",
        "ALLOWED_HOSTS='$ServerName'",
        "SERVER_NAME='$ServerName'",
        "ADMIN_USERNAME='$AdminUsername'",
        "ADMIN_EMAIL='$AdminEmail'",
        "ADMIN_PASSWORD='$AdminPassword'"
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
if ($SeedAdminUser) {
    Write-Host "    Admin : open the URL and log in as  $SeedAdminUser"
    if ($SeedAdminPw) {
        Write-Host '    Admin password (SHOWN ONCE - copy it now; it is also stored in ./.env):' -ForegroundColor Yellow
        Write-Host "        $SeedAdminPw" -ForegroundColor Green
        Write-Host '    Change it after your first login (Settings), then it is no longer needed in .env.'
    } else {
        Write-Host '            using the ADMIN_PASSWORD you set in ./.env.'
    }
} else {
    Write-Host '    Admin : log in with the ADMIN_USERNAME / ADMIN_PASSWORD values from ./.env.'
}
