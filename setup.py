from setuptools import setup
import re
import pathlib
import os
import subprocess
from typing import Optional, Tuple
from setuptools.command.egg_info import egg_info as _egg_info

# Prefer to import the canonical version resolver when available so builds
# always use the same logic the rest of the project uses.
try:
    from scripts.get_version import get_pyhttplib_version, get_release_display_name
except Exception:
    get_pyhttplib_version = None
    get_release_display_name = None


class egg_info(_egg_info):
    """Ensure a top-level VERSION file exists during egg_info so it is
    included in the generated sdist. This helps isolated wheel builds that
    unpack the sdist in a temp dir without .git available.
    """

    def run(self):
        try:
            version_file = here / "VERSION"
            # Always ensure the resolved version is present in VERSION so
            # isolated wheel builds (which may unpack an sdist without .git)
            # read a deterministic version. Overwrite any existing file to
            # avoid mismatches between sdist and wheel.
            if version:
                version_file.write_text(str(version), encoding="utf8")
        except Exception:
            pass
        super().run()

here = pathlib.Path(__file__).parent

# Prefer an explicit env var set by CI
version = os.environ.get("PYHTTPLIB_VERSION")
display_name = os.environ.get("RELEASE_DISPLAY_NAME")

# If we can import the canonical resolver, use it as the authoritative source
if not version and get_pyhttplib_version:
    try:
        version = get_pyhttplib_version()
    except Exception:
        version = None
if not display_name and get_release_display_name:
    try:
        display_name = get_release_display_name()
    except Exception:
        display_name = None

def _candidate_from_commit_messages(max_commits: int = 200) -> Optional[str]:
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
def _map_candidate_to_version(candidate: str) -> Tuple[str, str]:
    m: Optional[re.Match[str]] = re.match(r"^([0-9]+)([A-Za-z])?$", candidate)
    if not m:
        # PEP-440 friendly fallback
        return candidate, "0.0.0"
    major = m.group(1)
    letter = m.group(2)
    minor = (ord(letter.upper()) - ord('A')) if letter else 0
    # Use three segments (patch=0) to be safe with packaging tools
    return candidate, f"{major}.{minor}.0"

if not version:
    cand = _candidate_from_commit_messages()
    if cand:
        disp, num = _map_candidate_to_version(cand)
        version = num
        if not display_name:
            display_name = disp

if not version:
    # Try a static VERSION file (useful in isolated PEP-517 wheel builds
    # or when git is not available). If present, the file should contain a
    # PEP-440 compatible version string on the first line.
    try:
        version_file = here / "VERSION"
        if version_file.exists():
            version = version_file.read_text(encoding="utf8").splitlines()[0].strip()
    except Exception:
        version = None

# If we resolved a version earlier (for example via git or environment),
# write it to a top-level VERSION file so isolated wheel builds (which
# unpack the sdist in a temporary directory without .git) can read the
# same static version. Do not overwrite an existing VERSION file.
try:
    version_file = here / "VERSION"
    # Write (or overwrite) the VERSION file with the resolved version so
    # the build backend running in an isolated environment sees the same
    # version string.
    if version:
        version_file.write_text(str(version), encoding="utf8")
except Exception:
    # Best-effort only; fall back below
    pass

if not version:
    # Default to a safe PEP-440 compatible zero version
    version = "0.0.0"

setup(
    name="pyhttplib",
    version=version,
    description=(f"pyhttplib release {display_name}" if display_name else "pyhttplib"),
    long_description=(here / "README.md").read_text(encoding="utf8"),
    long_description_content_type="text/markdown",
    cmdclass={"egg_info": egg_info},
    # If a top-level VERSION file exists, include it in the sdist/wheel so
    # isolated builds unpacking the sdist will see the same static version.
    data_files=[('', ['VERSION'])] if (here / 'VERSION').exists() else [],
    # Single-module distribution
    py_modules=["httplib"],
)
