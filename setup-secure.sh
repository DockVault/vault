#!/usr/bin/env bash
#
# RETIRED: setup-secure.sh has been replaced by the interactive management tool dockvault.py, which
# does Setup PLUS Backup & Restore / Volumes / Reset / Update / Logs. This shim just launches Setup;
# run  python3 dockvault.py  for the full menu.  (Requires python3 on the host.)
set -e
cd "$(dirname "$0")"
exec python3 ./dockvault.py setup "$@"
