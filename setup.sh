#!/usr/bin/env bash
# Plug-and-play installer for the Strix MCP server.
# Creates a local venv, installs deps, ensures the strix CLI, seeds .env,
# and prints the exact MCP config snippet for your machine (no secrets in it).
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

echo "==> Strix MCP setup in: $DIR"

# 1. Require uv (fast Python package/venv manager).
if ! command -v uv >/dev/null 2>&1; then
  echo "ERROR: 'uv' is not installed. Install it first:" >&2
  echo "  curl -LsSf https://astral.sh/uv/install.sh | sh" >&2
  exit 1
fi

# 2. Create the venv and install the MCP SDK.
echo "==> Creating virtual environment (.venv)"
uv venv --python 3.12 .venv
echo "==> Installing Python dependencies"
uv pip install --python .venv/bin/python -r requirements.txt

# 3. Ensure the strix CLI is available.
if command -v strix >/dev/null 2>&1 || [ -x "$HOME/.local/bin/strix" ]; then
  echo "==> strix CLI already installed"
else
  echo "==> Installing strix CLI (uv tool install strix-agent)"
  uv tool install --python 3.12 strix-agent
fi

# 4. Seed .env from the template if missing.
if [ ! -f .env ]; then
  cp .env.example .env
  echo "==> Created .env — edit it and add your LLM_API_KEY"
else
  echo "==> .env already exists, leaving it untouched"
fi

PYBIN="$DIR/.venv/bin/python"
SERVER="$DIR/strix_server.py"

cat <<EOF

============================================================
Setup complete.

1) Put your credentials in .env (never commit it):
     STRIX_LLM   = your provider/model  (e.g. openrouter/z-ai/glm-5.3)
     LLM_API_KEY = your API key

2) Add this to your Kiro MCP config
   (~/.kiro/settings/mcp.json, inside "mcpServers"):

    "strix": {
      "command": "$PYBIN",
      "args": ["$SERVER"]
    }

   No API key goes here — the server reads it from .env.

3) Make sure Docker is running, then reload MCP servers in Kiro.
   In Kiro, call the 'strix_check' tool to verify.
============================================================
EOF
