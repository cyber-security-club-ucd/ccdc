#!/usr/bin/env bash
set -euo pipefail

# Reverse rbash.sh by invoking its built-in revert mode.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "${SCRIPT_DIR}/rbash.sh" revert
