#!/usr/bin/env bash
set -euo pipefail
umask 077
cd "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "$(uname -s)" == Darwin ]]; then
    export PATH="/opt/homebrew/bin:/usr/local/bin:$HOME/.local/bin:$PATH"
fi
uv="${PRESIDIO_UV:-uv}"
if ! command -v "$uv" >/dev/null; then
    [[ "$(uname -s)" == Darwin && "$uv" == uv ]] && command -v brew >/dev/null || { echo 'Install uv or set PRESIDIO_UV to its executable path.' >&2; exit 1; }
    brew install uv
fi
mkdir -p .local
staging="$(mktemp -d .local/mask4-build.XXXXXX)"
"$uv" run --no-project --python 3.13 python presidio-analyzer/scripts/stage_mask4_release.py \
    --baseline-wheel release-inputs/presidio_analyzer-2.2.366+ru.mask3-py3-none-any.whl \
    --output "$staging/source"
"$uv" build "$staging/source" --wheel --out-dir .local/dist
