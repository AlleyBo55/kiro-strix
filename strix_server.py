#!/usr/bin/env python3
"""Strix MCP server.

Exposes the Strix penetration-testing CLI (https://github.com/usestrix/strix)
to an MCP client (Kiro) as async tools. Strix scans are long-running and
autonomous, so scans launch in the background and are tracked by run id;
callers poll status and read findings instead of blocking on one call.

Credentials are read from a local `.env` file next to this script (gitignored)
or from the process environment. The key is never returned by any tool.

AUTHORIZED USE ONLY. Strix actively attacks whatever target it is pointed at.
Only scan systems you own or have explicit written permission to test.
"""

from __future__ import annotations

import json
import os
import shlex
import signal
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# --- load .env (next to this script) before anything reads the environment ---

SCRIPT_DIR = Path(__file__).resolve().parent


def _load_dotenv(path: Path) -> None:
    """Minimal .env loader. Existing real env vars win (setdefault)."""
    if not path.exists():
        return
    try:
        for raw in path.read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if key:
                os.environ.setdefault(key, val)
    except Exception:
        pass  # a broken .env must never crash the server


_load_dotenv(SCRIPT_DIR / ".env")

from mcp.server.fastmcp import FastMCP  # noqa: E402  (after .env load)

# --- configuration -----------------------------------------------------------

HOME = Path(os.path.expanduser("~"))


def _resolve_strix_bin() -> str:
    env = os.environ.get("STRIX_BIN")
    if env and Path(env).exists():
        return env
    for c in (
        HOME / ".local/bin/strix",
        Path("/opt/homebrew/bin/strix"),
        Path("/usr/local/bin/strix"),
    ):
        if c.exists():
            return str(c)
    return "strix"  # fall back to PATH lookup at call time


STRIX_BIN = _resolve_strix_bin()
RUNS_HOME = Path(os.environ.get("STRIX_MCP_HOME", str(SCRIPT_DIR / "runs")))
RUNS_HOME.mkdir(parents=True, exist_ok=True)

VALID_SCAN_MODES = {"quick", "standard", "deep"}
VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}

mcp = FastMCP("strix")


# --- helpers ------------------------------------------------------------------


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _run_dir(run_id: str) -> Path:
    return RUNS_HOME / run_id


def _read_meta(run_id: str) -> Optional[dict]:
    meta = _run_dir(run_id) / "meta.json"
    if not meta.exists():
        return None
    try:
        return json.loads(meta.read_text())
    except Exception:
        return None


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _exit_code(run_id: str) -> Optional[int]:
    f = _run_dir(run_id) / "exit_code"
    if not f.exists():
        return None
    try:
        return int(f.read_text().strip())
    except Exception:
        return None


def _exit_meaning(code: Optional[int]) -> str:
    return {
        0: "completed; no vulnerabilities found (or none at/above --fail-on)",
        1: "fatal error before/during scan (missing env, Docker down, bad config)",
        2: "vulnerabilities found",
    }.get(code, "unknown")


def _tail(path: Path, lines: int = 40, max_bytes: int = 16000) -> str:
    if not path.exists():
        return ""
    try:
        data = path.read_bytes()[-max_bytes:]
        text = data.decode("utf-8", errors="replace")
        return "\n".join(text.splitlines()[-lines:])
    except Exception as e:  # noqa: BLE001
        return f"<could not read log: {e}>"


def _output_dir(run_id: str) -> Optional[Path]:
    """Strix writes results to <cwd>/strix_runs/<auto-name>. Each run has its
    own cwd, so there is at most one such directory per run."""
    base = _run_dir(run_id) / "strix_runs"
    if not base.is_dir():
        return None
    subdirs = [d for d in base.iterdir() if d.is_dir()]
    return max(subdirs, key=lambda d: d.stat().st_mtime) if subdirs else None


def _status_dict(run_id: str) -> dict:
    meta = _read_meta(run_id)
    if meta is None:
        return {"run_id": run_id, "error": "unknown run_id"}
    pid = meta.get("pid")
    code = _exit_code(run_id)
    if code is not None:
        state = "finished"
    elif pid and _pid_alive(pid):
        state = "running"
    else:
        state = "stopped"  # process gone but no exit_code captured
    out = _output_dir(run_id)
    return {
        "run_id": run_id,
        "state": state,
        "exit_code": code,
        "exit_meaning": _exit_meaning(code) if code is not None else None,
        "targets": meta.get("targets"),
        "scan_mode": meta.get("scan_mode"),
        "started_at": meta.get("started_at"),
        "pid": pid,
        "run_dir": str(_run_dir(run_id)),
        "output_dir": str(out) if out else None,
        "log_tail": _tail(_run_dir(run_id) / "strix.log"),
    }


def _looks_like_path(target: str) -> bool:
    if "://" in target:  # url, postman://, etc.
        return False
    return os.path.sep in target or target in (".", "..") or Path(target).exists()


# --- tools --------------------------------------------------------------------


@mcp.tool()
def strix_check() -> dict:
    """Health check for the Strix integration.

    Reports the Strix version, whether Docker is reachable, and whether the
    required LLM env vars are present (values are never returned). Call this
    first if a scan fails to start."""
    info: dict = {"strix_bin": STRIX_BIN, "runs_home": str(RUNS_HOME)}
    try:
        v = subprocess.run(
            [STRIX_BIN, "--version"], capture_output=True, text=True, timeout=30
        )
        info["strix_version"] = (v.stdout or v.stderr).strip()
        info["strix_ok"] = v.returncode == 0
    except Exception as e:  # noqa: BLE001
        info["strix_ok"] = False
        info["strix_error"] = str(e)
    try:
        d = subprocess.run(
            ["docker", "info"], capture_output=True, text=True, timeout=30
        )
        info["docker_running"] = d.returncode == 0
        if d.returncode != 0:
            info["docker_hint"] = "Docker is not reachable; start Docker Desktop."
    except Exception as e:  # noqa: BLE001
        info["docker_running"] = False
        info["docker_error"] = str(e)
    info["env"] = {
        "STRIX_LLM_set": bool(os.environ.get("STRIX_LLM")),
        "LLM_API_KEY_set": bool(os.environ.get("LLM_API_KEY")),
        "LLM_API_BASE_set": bool(os.environ.get("LLM_API_BASE")),
    }
    if not info["env"]["STRIX_LLM_set"] or not info["env"]["LLM_API_KEY_set"]:
        info["env_hint"] = (
            "Set STRIX_LLM and LLM_API_KEY in the .env file next to strix_server.py "
            "(copy .env.example), then reload the MCP server."
        )
    return info


@mcp.tool()
def strix_scan_start(
    targets: list[str],
    authorized: bool = False,
    scan_mode: str = "quick",
    instruction: str = "",
    max_budget: Optional[float] = None,
    fail_on: str = "",
    extra_args: Optional[list[str]] = None,
) -> dict:
    """Start a Strix penetration test in the background and return a run id.

    AUTHORIZED USE ONLY. Set authorized=True only for targets the user owns or
    has explicit written permission to test (their own repos, domains, apps,
    localhost, or the current workspace). Do not scan third-party targets
    without that permission.

    Args:
        targets: One or more targets. Each is passed as `-t`. A target may be a
            URL, a git repo URL, a local directory/file path, a domain, an IP,
            an OpenAPI/Swagger/Postman spec file, or postman://<uuid>. Local
            paths are resolved to absolute paths. NOTE: a local directory is
            mounted writable into the sandbox and Strix may edit real files
            (except .git); commit or stash first.
        authorized: Must be True to proceed; confirms the targets are in scope.
        scan_mode: quick | standard | deep (default quick).
        instruction: Optional free-text guidance (credentials, focus areas).
        max_budget: Optional max LLM spend in USD for the whole scan.
        fail_on: Optional min severity for exit code 2 (critical|high|medium|low|info).
        extra_args: Optional additional raw CLI args passed through verbatim.

    Returns a dict with run_id, pid, run_dir and the command used. Poll with
    strix_scan_status and read results with strix_scan_findings.
    """
    if not targets or not all(isinstance(t, str) and t.strip() for t in targets):
        return {"error": "targets must be a non-empty list of non-empty strings"}
    if not authorized:
        return {
            "error": "authorized must be True. Only scan targets the user owns "
            "or has explicit written permission to test, then set "
            "authorized=True. Targets were: " + ", ".join(targets)
        }
    if scan_mode not in VALID_SCAN_MODES:
        return {"error": f"scan_mode must be one of {sorted(VALID_SCAN_MODES)}"}
    if fail_on and fail_on not in VALID_SEVERITIES:
        return {"error": f"fail_on must be one of {sorted(VALID_SEVERITIES)}"}

    resolved: list[str] = []
    for t in targets:
        t = t.strip()
        if _looks_like_path(t):
            p = Path(t).expanduser()
            resolved.append(str(p.resolve()) if p.exists() else t)
        else:
            resolved.append(t)

    run_id = datetime.now().strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
    rundir = _run_dir(run_id)
    rundir.mkdir(parents=True, exist_ok=True)

    cmd = [STRIX_BIN, "-n", "-m", scan_mode]
    for t in resolved:
        cmd += ["-t", t]
    if instruction.strip():
        cmd += ["--instruction", instruction]
    if max_budget is not None:
        cmd += ["--max-budget", str(max_budget)]
    if fail_on:
        cmd += ["--fail-on", fail_on]
    if extra_args:
        cmd += [str(a) for a in extra_args]

    # Run via a shell script so the exit code is captured to a file even if
    # this server restarts. All args are shell-quoted.
    quoted = " ".join(shlex.quote(c) for c in cmd)
    script = rundir / "run.sh"
    script.write_text(
        "#!/bin/sh\n"
        f"cd {shlex.quote(str(rundir))}\n"
        f"{quoted} > strix.log 2>&1\n"
        "echo $? > exit_code\n"
    )
    script.chmod(0o755)

    proc = subprocess.Popen(
        ["/bin/sh", str(script)],
        cwd=str(rundir),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,  # own process group, so we can stop the tree
        env=os.environ.copy(),
    )

    meta = {
        "run_id": run_id,
        "pid": proc.pid,
        "targets": resolved,
        "scan_mode": scan_mode,
        "instruction": instruction,
        "command": cmd,
        "started_at": _now(),
    }
    (rundir / "meta.json").write_text(json.dumps(meta, indent=2))

    return {
        "run_id": run_id,
        "pid": proc.pid,
        "state": "running",
        "run_dir": str(rundir),
        "command": quoted,
        "note": "Scan running in background. Poll strix_scan_status(run_id); "
        "read results with strix_scan_findings(run_id).",
    }


@mcp.tool()
def strix_scan_status(run_id: str) -> dict:
    """Return the current state of a scan: running | finished | stopped, its
    exit code and meaning once finished, and the tail of its log."""
    return _status_dict(run_id)


@mcp.tool()
def strix_scan_list() -> dict:
    """List all known scan runs with their current state, newest first."""
    runs = []
    if RUNS_HOME.is_dir():
        for d in sorted(RUNS_HOME.iterdir(), reverse=True):
            if (d / "meta.json").exists():
                s = _status_dict(d.name)
                runs.append(
                    {k: s.get(k) for k in ("run_id", "state", "exit_code", "targets", "started_at")}
                )
    return {"count": len(runs), "runs": runs}


@mcp.tool()
def strix_scan_findings(run_id: str, max_bytes: int = 20000) -> dict:
    """Read results of a scan. Returns the output directory tree plus the
    content of report-like files (markdown/json), each truncated to max_bytes.
    Falls back to the log tail if no structured results exist yet."""
    meta = _read_meta(run_id)
    if meta is None:
        return {"run_id": run_id, "error": "unknown run_id"}
    out = _output_dir(run_id)
    result: dict = {"run_id": run_id, "state": _status_dict(run_id)["state"]}
    if out is None:
        result["note"] = "No structured output yet."
        result["log_tail"] = _tail(_run_dir(run_id) / "strix.log", lines=60)
        return result

    result["output_dir"] = str(out)
    tree = []
    reports = {}
    for p in sorted(out.rglob("*")):
        if p.is_file():
            rel = str(p.relative_to(out))
            tree.append({"path": rel, "bytes": p.stat().st_size})
            name = p.name.lower()
            if name.endswith((".md", ".json")) and any(
                k in name for k in ("report", "finding", "vuln", "summary")
            ):
                try:
                    reports[rel] = p.read_text(errors="replace")[:max_bytes]
                except Exception as e:  # noqa: BLE001
                    reports[rel] = f"<could not read: {e}>"
    result["files"] = tree
    result["reports"] = reports
    if not reports:
        result["log_tail"] = _tail(_run_dir(run_id) / "strix.log", lines=60)
    return result


@mcp.tool()
def strix_scan_stop(run_id: str) -> dict:
    """Stop a running scan. Sends SIGINT then SIGTERM to the process group so
    Strix can tear down its Docker sandbox."""
    meta = _read_meta(run_id)
    if meta is None:
        return {"run_id": run_id, "error": "unknown run_id"}
    pid = meta.get("pid")
    if not pid or not _pid_alive(pid):
        return {"run_id": run_id, "state": "not running"}
    try:
        pgid = os.getpgid(pid)
        os.killpg(pgid, signal.SIGINT)
        time.sleep(2)
        if _pid_alive(pid):
            os.killpg(pgid, signal.SIGTERM)
        return {"run_id": run_id, "state": "stopping", "signaled_pgid": pgid}
    except Exception as e:  # noqa: BLE001
        return {"run_id": run_id, "error": f"could not stop: {e}"}


if __name__ == "__main__":
    mcp.run()
