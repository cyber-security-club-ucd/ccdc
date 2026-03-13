#!/usr/bin/env bash
set -euo pipefail

# Reverse php.sh by reusing reversephp.sh logic.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "${SCRIPT_DIR}/reversephp.sh" "$@"
