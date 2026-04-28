from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
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


def _is_checkout_error(err: str) -> bool:
    """Return True when git transferred objects but couldn't write some files.

    This happens on Windows when the repo contains filenames with characters
    that are illegal on NTFS (colons, angle brackets, etc.).  The objects are
    present in .git; the partial working tree is still scannable.
    """
    markers = ("unable to checkout", "invalid path", "checkout failed")
    return any(m in err for m in markers)


def _force_checkout(local_path: str) -> None:
    """Retry working-tree checkout with core.protectNTFS=false.

    When git encounters a filename containing Windows-reserved characters
    (e.g. a colon) it aborts the entire checkout.  With protectNTFS disabled
    git attempts each file individually; the OS silently rejects the invalid
    ones while all other files land on disk normally.
    """
    try:
        subprocess.run(
            ["git", "-C", local_path, "-c", "core.protectNTFS=false",
             "checkout", "HEAD", "--", "."],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except Exception:
        pass


def _rmtree_robust(path: str) -> None:
    """Remove a directory tree, retrying after clearing read-only bits.

    Plain shutil.rmtree(ignore_errors=True) silently fails on Windows when
    .git/objects files are marked read-only, leaving a stale directory that
    blocks the next clone attempt.
    """
    def _on_error(func, fpath, _exc_info):
        try:
            os.chmod(fpath, stat.S_IWRITE)
            func(fpath)
        except Exception:
            pass

    if os.path.exists(path):
        shutil.rmtree(path, onerror=_on_error)


class RepoFetcher:
    def __init__(self, github_token: str | None = None) -> None:
        self._token = github_token or Config.GITHUB_TOKEN

    def clone_repo(self, repo_url: str, branch: str = "main") -> tuple[str, str]:
        """Return (local_path, actual_branch) — actual_branch may differ from requested."""
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
        except git.GitCommandError as e:
            err = str(e)
            if _is_checkout_error(err) and os.path.exists(local_path):
                # Objects transferred but checkout aborted due to OS-incompatible
                # filenames (e.g. colons on Windows).  Force a retry that lets
                # the OS silently skip the invalid files while checking out all
                # valid ones so the working tree is populated for scanning.
                _force_checkout(local_path)
            else:
                _rmtree_robust(local_path)
                try:
                    git.Repo.clone_from(auth_url, local_path, depth=1)
                except git.GitCommandError as e2:
                    if _is_checkout_error(str(e2)) and os.path.exists(local_path):
                        _force_checkout(local_path)
                    else:
                        raise

        return local_path, actual_branch

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
        _rmtree_robust(local_path)

