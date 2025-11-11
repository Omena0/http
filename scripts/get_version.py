from typing import Optional
import subprocess
import re
import os


def _candidate_from_commit_messages(max_commits: int = 200) -> Optional[str]:
    """Return a commit token like '3D' if found in recent commit messages.

    Scans recent commits' first lines for a pattern '<digits><optional-letter> -'.
    """
    try:
        revs = subprocess.check_output(["git", "rev-list", f"--max-count={max_commits}", "HEAD"], text=True)
    except Exception:
        return None
    for rev in revs.splitlines():
        try:
            msg = subprocess.check_output(["git", "log", "-1", "--pretty=%B", rev], text=True)
        except Exception:
            continue
        first = msg.splitlines()[0].strip() if msg else ""
        if "-" in first:
            candidate = first.split("-", 1)[0].strip()
            if re.match(r"^[0-9]+[A-Za-z]?$", candidate):
                return candidate
    return None

def _map_candidate_to_version(candidate: str) -> tuple[str, str]:
    """Map a candidate like '3D' to (display_name, numeric_version).

    Rules: digits are major; optional letter maps to minor as A->0, B->1, etc.
    Example: '3A' -> ('3A', '3.0'), '3D' -> ('3D', '3.3').
    """
    m = re.match(r"^([0-9]+)([A-Za-z])?$", candidate)
    if not m:
        # Fall back to a PEP-440 friendly zero version
        return candidate, "0.0.0"
    major = m[1]
    letter = m[2]
    minor = (ord(letter.upper()) - ord('A')) if letter else 0
    # Use a three-segment version (patch=0) for PEP-440 compatibility
    return candidate, f"{major}.{minor}.0"


# Determine release display name and numeric version
_release_display_name = os.environ.get("RELEASE_DISPLAY_NAME")
# Prefer the new PYHTTPLIB_VERSION env var but fall back to NETSPLIT_VERSION
_pyhttplib_version = os.environ.get("PYHTTPLIB_VERSION") or os.environ.get("NETSPLIT_VERSION")

if not (_release_display_name and _pyhttplib_version):
    cand = _candidate_from_commit_messages()
    if cand:
        disp, num = _map_candidate_to_version(cand)
        if not _release_display_name:
            _release_display_name = disp
        if not _pyhttplib_version:
            _pyhttplib_version = num

if not _release_display_name:
    _release_display_name = "dev"
if not _pyhttplib_version:
    _pyhttplib_version = "0.0.0"


def get_pyhttplib_version() -> str:
    """Return the numeric pyhttplib version string (e.g. '3.3')."""
    return str(_pyhttplib_version)


def get_release_display_name() -> str:
    """Return the human release display name (e.g. '3D')."""
    return str(_release_display_name)
