from __future__ import annotations

import os
import re
import shutil
import uuid
from pathlib import Path
from typing import Any

import git
from github import Github, GithubException

from agent.config import Config


def _parse_owner_repo(repo_url: str) -> tuple[str, str]:
    """Extract owner and repo name from a GitHub URL."""
    patterns = [
        r"github\.com[:/]([^/]+)/([^/\s.]+?)(?:\.git)?$",
    ]
    for pattern in patterns:
        m = re.search(pattern, repo_url)
        if m:
            return m.group(1), m.group(2)
    raise ValueError(f"Cannot parse GitHub owner/repo from URL: {repo_url}")


class RepoFetcher:
    def __init__(self, github_token: str | None = None) -> None:
        self._token = github_token or Config.GITHUB_TOKEN

    def clone_repo(self, repo_url: str, branch: str = "main") -> str:
        owner, repo_name = _parse_owner_repo(repo_url)
        work_dir = Path(Config.WORK_DIR)
        work_dir.mkdir(parents=True, exist_ok=True)

        local_path = str(work_dir / f"{repo_name}_{uuid.uuid4().hex[:8]}")

        # Inject token into URL for authenticated cloning
        if self._token and "github.com" in repo_url:
            auth_url = repo_url.replace(
                "https://github.com",
                f"https://{self._token}@github.com",
            ).replace(
                "http://github.com",
                f"https://{self._token}@github.com",
            )
        else:
            auth_url = repo_url

        # Resolve branch: confirm it exists, fall back to repo default if not
        actual_branch = self._resolve_branch(repo_url, branch)

        try:
            git.Repo.clone_from(
                auth_url,
                local_path,
                branch=actual_branch,
                depth=1,
                multi_options=["--single-branch"],
            )
        except git.GitCommandError:
            # Clean up any partial clone directory before retrying
            shutil.rmtree(local_path, ignore_errors=True)
            git.Repo.clone_from(auth_url, local_path, depth=1)

        return local_path

    def _resolve_branch(self, repo_url: str, requested: str) -> str:
        """Return requested branch if it exists on the remote, else the repo default."""
        try:
            owner, repo_name = _parse_owner_repo(repo_url)
            g = Github(self._token)
            repo = g.get_repo(f"{owner}/{repo_name}")
            default = repo.default_branch
            try:
                repo.get_branch(requested)
                return requested          # branch exists, use it
            except GithubException:
                return default            # fall back to master/main/whatever
        except Exception:
            return requested              # can't reach API, try as-is

    def get_repo_metadata(self, repo_url: str) -> dict[str, Any]:
        try:
            owner, repo_name = _parse_owner_repo(repo_url)
            g = Github(self._token)
            repo = g.get_repo(f"{owner}/{repo_name}")
            return {
                "name": repo.name,
                "full_name": repo.full_name,
                "description": repo.description or "",
                "default_branch": repo.default_branch,
                "language": repo.language or "",
                "languages": list((repo.get_languages() or {}).keys()),
                "stars": repo.stargazers_count,
                "open_issues": repo.open_issues_count,
                "topics": repo.get_topics(),
            }
        except Exception:
            # Non-fatal — return minimal metadata
            parts = repo_url.rstrip("/").split("/")
            return {
                "name": parts[-1].replace(".git", "") if parts else "unknown",
                "full_name": "/".join(parts[-2:]) if len(parts) >= 2 else "unknown",
                "description": "",
                "default_branch": "main",
                "language": "",
                "languages": [],
                "stars": 0,
                "open_issues": 0,
                "topics": [],
            }

    @staticmethod
    def cleanup(local_path: str) -> None:
        if local_path and os.path.exists(local_path):
            shutil.rmtree(local_path, ignore_errors=True)
