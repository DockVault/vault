# RETIRED: setup-secure.ps1 has been replaced by the interactive management tool dockvault.py, which
# does Setup PLUS Backup and Restore / Volumes / Reset / Update / Logs. This shim just launches Setup;
# run  python dockvault.py  for the full menu.  (Requires Python 3 on the host.)
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root = $ScriptDir
python "$Root\dockvault.py" setup @args
