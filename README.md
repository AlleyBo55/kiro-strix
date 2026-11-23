# Strix MCP for Kiro

A self-contained [Model Context Protocol](https://modelcontextprotocol.io)
server that lets [Kiro](https://kiro.dev) (or any MCP client) run
[Strix](https://github.com/usestrix/strix) — an open-source AI penetration
testing tool — against your own apps.

Clone it, run one script, add one config block. Your API key stays in a local
`.env` file and is never committed or placed in Kiro's config.

> **Authorized use only.** Strix actively attacks whatever target it is pointed
> at. Only scan systems you own or have explicit written permission to test.
> Unauthorized testing is illegal in most places.

## Requirements

- [Docker](https://www.docker.com/) (running) — Strix runs scans in a sandbox container.
- [uv](https://docs.astral.sh/uv/) — `curl -LsSf https://astral.sh/uv/install.sh | sh`
- An LLM API key (OpenRouter, Anthropic, OpenAI, Vercel AI Gateway, etc.).

## Setup

```bash
git clone <your-fork-url> siti
cd siti
./setup.sh
```

`setup.sh` creates a local `.venv`, installs dependencies, installs the `strix`
CLI if needed, seeds `.env`, and prints the exact MCP config snippet for your
machine (with absolute paths, and **no secrets** in it).

Then:

1. Edit `.env` and set `STRIX_LLM` and `LLM_API_KEY`.
2. Paste the printed `strix` block into `~/.kiro/settings/mcp.json` under
   `"mcpServers"`.
3. Start Docker and reload MCP servers in Kiro.

The config block has no key in it — the server loads `.env` at startup:

```json
    "strix": {
      "command": "/absolute/path/to/siti/.venv/bin/python",
      "args": ["/absolute/path/to/siti/strix_server.py"]
    }
```

## Tools

| Tool | Purpose |
| --- | --- |
| `strix_check` | Health check: Strix version, Docker status, whether `.env` is configured (never prints the key). |
| `strix_scan_start` | Start a scan in the background. Requires `authorized: true`. Returns a `run_id`. |
| `strix_scan_status` | State of a run: `running` / `finished` / `stopped`, exit code, log tail. |
| `strix_scan_findings` | Read a run's output tree and report files. |
| `strix_scan_list` | List all runs. |
| `strix_scan_stop` | Stop a running scan and tear down its sandbox. |

Scans run in the background (they can take minutes to hours): start one, then
poll `strix_scan_status` and read `strix_scan_findings`.

## Security model

- **Credentials** live only in `.env` (gitignored). They are never written to
  Kiro's `mcp.json`, never logged, and never returned by a tool.
- **Scan outputs** (`runs/`, `strix_runs/`) are gitignored — findings can be
  sensitive, so they never get committed.
- **No machine-specific paths** are committed; `setup.sh` resolves them per
  machine, and `.kiro/settings/` is gitignored.
- The `strix_scan_start` tool refuses to run unless `authorized=true` is set,
  as a deliberate confirmation that the target is in scope.

## Project layout

```
strix_server.py        the MCP server
requirements.txt       Python deps (mcp<2)
setup.sh               installer
.env.example           credentials template (copy to .env)
.gitignore             blocks secrets, venv, scan outputs
.kiro/steering/        authorized-use context for Kiro models
runs/                  scan outputs (gitignored, created at runtime)
.venv/                 Python env (gitignored, created by setup.sh)
```
