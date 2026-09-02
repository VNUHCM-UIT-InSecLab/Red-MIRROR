from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Optional


class LocalShell:
    FORBIDDEN_COMMANDS = {"apt", "apt-get"}

    def __init__(self, cwd: Optional[str] = None, timeout: float = 120.0):
        self.cwd = Path(cwd or os.getcwd()).resolve()
        self.timeout = timeout
        self.shell = self

    def send(self, chars: str) -> None:
        del chars

    def close(self) -> None:
        return

    def _check_forbidden_commands(self, cmd: str) -> Optional[str]:
        parts = cmd.split()
        if any(part in self.FORBIDDEN_COMMANDS for part in parts):
            return "Command not allowed: network tunneling tools are restricted"
        return None

    def execute_cmd(self, cmd: str) -> str:
        if error_msg := self._check_forbidden_commands(cmd):
            return error_msg

        stripped = cmd.strip()
        if not stripped:
            return ""

        if stripped == "exit":
            return ""

        if stripped.startswith("cd "):
            target = stripped[3:].strip()
            next_cwd = (self.cwd / target).resolve() if not os.path.isabs(target) else Path(target).resolve()
            if next_cwd.exists() and next_cwd.is_dir():
                self.cwd = next_cwd
                return str(self.cwd)
            return f"bash: cd: {target}: No such file or directory"

        try:
            result = subprocess.run(
                stripped,
                cwd=str(self.cwd),
                shell=True,
                executable="/bin/bash",
                text=True,
                capture_output=True,
                timeout=self.timeout,
            )
            output = (result.stdout or "") + (result.stderr or "")
            return output.strip()
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout or ""
            stderr = exc.stderr or ""
            body = ((stdout or "") + (stderr or "")).strip()
            if body:
                return f"{body}\n[TIMEOUT]"
            return "[TIMEOUT]"
