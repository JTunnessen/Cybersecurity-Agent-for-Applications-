from __future__ import annotations

import re
from datetime import datetime

from github import Github, GithubException

from agent.config import Config


def _parse_owner_repo(repo_url: str) -> tuple[str, str]:
    patterns = [
        r"github\.com[:/]([^/]+)/([^/\s.]+?)(?:\.git)?$",
    ]
    for pattern in patterns:
        m = re.search(pattern, repo_url)
        if m:
            return m.group(1), m.group(2)
    raise ValueError(f"Cannot parse GitHub owner/repo from URL: {repo_url}")


class ReportInjector:
    def __init__(self, github_token: str | None = None) -> None:
        self._token = github_token or Config.GITHUB_TOKEN
        self._github = Github(self._token)

    def inject(
        self,
        repo_url: str,
        report_path: str,
        content: str,
        branch: str | None = None,
    ) -> str:
        owner, repo_name = _parse_owner_repo(repo_url)
        repo = self._github.get_repo(f"{owner}/{repo_name}")

        target_branch = branch or repo.default_branch
        datestamp = datetime.utcnow().strftime("%Y-%m-%d")
        commit_message = f"security: update vulnerability scan report [{datestamp}]"

        encoded = content.encode("utf-8")

        try:
            existing = repo.get_contents(report_path, ref=target_branch)
            repo.update_file(
                path=report_path,
                message=commit_message,
                content=encoded,
                sha=existing.sha,
                branch=target_branch,
            )
        except GithubException as e:
            if e.status == 404:
                repo.create_file(
                    path=report_path,
                    message=commit_message,
                    content=encoded,
                    branch=target_branch,
                )
            else:
                raise

        return f"https://github.com/{owner}/{repo_name}/blob/{target_branch}/{report_path}"
