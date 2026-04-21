from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


class Config:
    ANTHROPIC_API_KEY: str = os.getenv("ANTHROPIC_API_KEY", "")
    GITHUB_TOKEN: str = os.getenv("GITHUB_TOKEN", "")
    NVD_API_KEY: str = os.getenv("NVD_API_KEY", "")
    WORK_DIR: str = os.getenv("WORK_DIR", "/tmp/cyb-agent-scans")

    OSV_BATCH_URL: str = "https://api.osv.dev/v1/querybatch"
    NVD_API_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    CISA_KEV_URL: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    CLAUDE_MODEL: str = "claude-sonnet-4-6"
    MAX_FINDINGS_PER_BATCH: int = 20
    SCANNER_TIMEOUT_SECONDS: int = 300

    DATA_DIR: Path = Path(__file__).parent.parent / "data"

    @classmethod
    def validate(cls) -> list[str]:
        errors = []
        if not cls.ANTHROPIC_API_KEY:
            errors.append("ANTHROPIC_API_KEY is not set")
        if not cls.GITHUB_TOKEN:
            errors.append("GITHUB_TOKEN is not set")
        Path(cls.WORK_DIR).mkdir(parents=True, exist_ok=True)
        return errors
