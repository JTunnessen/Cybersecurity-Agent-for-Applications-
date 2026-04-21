from __future__ import annotations

import subprocess
import uuid
from abc import ABC, abstractmethod

from agent.config import Config
from agent.models import Finding


class BaseScanner(ABC):
    @abstractmethod
    def scan(self, repo_path: str) -> list[Finding]:
        ...

    def run_subprocess(
        self, cmd: list[str], cwd: str
    ) -> tuple[str, str, int]:
        try:
            result = subprocess.run(
                cmd,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=Config.SCANNER_TIMEOUT_SECONDS,
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", f"Scanner timed out after {Config.SCANNER_TIMEOUT_SECONDS}s", 1
        except FileNotFoundError:
            return "", f"Command not found: {cmd[0]}", 127

    @staticmethod
    def new_id() -> str:
        return str(uuid.uuid4())
