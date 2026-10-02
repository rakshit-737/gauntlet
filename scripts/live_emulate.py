"""Run the allowlisted benign discovery commands and record event-level labels.

CI ONLY. Refuses to run unless on an ephemeral GitHub-hosted runner
(``GITHUB_ACTIONS=true`` and ``RUNNER_ENVIRONMENT=github-hosted``). Every command is
read-only system discovery: no credential access, persistence, privilege escalation,
file modification or network activity. Commands run with a fixed argv
(``shell=False``), as the unprivileged runner user, with a timeout. See
docs/adr/0005-benign-live-emulation.md.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

# (argv, ATT&CK technique). Changing this list needs CODEOWNERS review.
ALLOWLIST: tuple[tuple[tuple[str, ...], str], ...] = (
    (("whoami",), "T1033"),
    (("id",), "T1033"),
    (("uname", "-a"), "T1082"),
    (("hostname",), "T1082"),
    (("cat", "/etc/os-release"), "T1082"),
    (("ps", "-ef"), "T1057"),
    (("crontab", "-l"), "T1053.003"),
    (("ls", "-la", "/etc/cron.d"), "T1053.003"),
)
FORBIDDEN = {"curl", "wget", "nc", "ncat", "ssh", "scp", "sudo", "su", "useradd", "usermod", "passwd",
             "chmod", "chown", "rm", "mv", "cp", "dd", "python", "python3", "bash", "sh", "nmap"}


def check_allowlist() -> None:
    for argv, tech in ALLOWLIST:
        if argv[0] in FORBIDDEN or any(a.startswith(("-e", "-r")) for a in argv if argv[0] == "crontab"):
            raise SystemExit(f"forbidden command in allowlist: {argv}")
        if any(x in " ".join(argv) for x in ("/etc/shadow", "id_rsa", ".ssh", ">", "|", ";", "&")):
            raise SystemExit(f"forbidden argument in allowlist: {argv}")
        if not tech.startswith("T"):
            raise SystemExit(f"bad technique label {tech}")


def main(out: str = "live-out/labels.json") -> int:
    check_allowlist()
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        print("refusing to run: only on an ephemeral GitHub-hosted runner", file=sys.stderr)
        return 3
    if os.geteuid() == 0:  # type: ignore[attr-defined]
        print("refusing to run as root", file=sys.stderr)
        return 3
    rows = []
    for argv, tech in ALLOWLIST:
        t = time.time()
        exe = shutil.which(argv[0])  # absolute path: one execve, not one failed attempt per PATH entry
        if exe is None:
            rows.append({"argv": list(argv), "technique": tech, "pid": None, "start": t, "returncode": None})
            continue
        p = subprocess.Popen([exe, *argv[1:]], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=False)  # noqa: S603
        try:
            rc = p.wait(timeout=20)
        except subprocess.TimeoutExpired:
            p.kill()
            rc = -9
        rows.append({"argv": list(argv), "technique": tech, "pid": p.pid, "start": t, "returncode": rc})
        time.sleep(0.2)
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_text(json.dumps({"commands": rows}, indent=1), encoding="utf-8")
    print(json.dumps(rows, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(*sys.argv[1:]))
