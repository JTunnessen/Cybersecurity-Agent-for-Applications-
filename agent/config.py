from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


class Config:
    AI_PROVIDER: str = os.getenv("AI_PROVIDER", "anthropic").lower()

    ANTHROPIC_API_KEY: str = os.getenv("ANTHROPIC_API_KEY", "")
    CLAUDE_MODEL: str = os.getenv("CLAUDE_MODEL", "claude-sonnet-4-6")

    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    OPENAI_MODEL: str = os.getenv("OPENAI_MODEL", "gpt-4o")

    GITHUB_TOKEN: str = os.getenv("GITHUB_TOKEN", "")
    NVD_API_KEY: str = os.getenv("NVD_API_KEY", "")
    WORK_DIR: str = os.getenv("WORK_DIR", "/tmp/cyb-agent-scans")

    OSV_BATCH_URL: str = "https://api.osv.dev/v1/querybatch"
    NVD_API_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    CISA_KEV_URL: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    MAX_FINDINGS_PER_BATCH: int = 20
    SCANNER_TIMEOUT_SECONDS: int = 300

    DATA_DIR: Path = Path(__file__).parent.parent / "data"

    SUPPORTED_PROVIDERS = ("anthropic", "openai")

    @classmethod
    def validate(cls, provider: str | None = None) -> list[str]:
        active = (provider or cls.AI_PROVIDER).lower()
        errors = []

        if active not in cls.SUPPORTED_PROVIDERS:
            errors.append(
                f"AI_PROVIDER '{active}' is not supported. Choose: {', '.join(cls.SUPPORTED_PROVIDERS)}"
            )

        if active == "anthropic" and not cls.ANTHROPIC_API_KEY:
            errors.append("ANTHROPIC_API_KEY is not set")
        if active == "openai" and not cls.OPENAI_API_KEY:
            errors.append("OPENAI_API_KEY is not set")

        if not cls.GITHUB_TOKEN:
            errors.append("GITHUB_TOKEN is not set")

        Path(cls.WORK_DIR).mkdir(parents=True, exist_ok=True)
        return errors
