"""Safe workspace path utilities.

Every file an agent tool touches is resolved here first. A path is accepted
only when it stays inside ``workspace/``:

* absolute paths are rejected;
* ``..`` in any position is rejected;
* a symlink anywhere along the path is rejected, so a link cannot be used to
  step outside the tree;
* the fully resolved path must still sit under the workspace root, which keeps
  ``vault/`` and ``data/`` unreachable;
* reads are capped at 1 MB.

These functions make no access-control decision about *who* may read a folder.
Role permissions belong to the gateway (Stage 8); this module only guarantees
that a path cannot escape the workspace.

The workspace root is read from ``config`` at call time, so tests can point it
at a temporary directory.
"""

import logging
import os
from pathlib import Path

from backend import config

logger = logging.getLogger(__name__)

MAX_READ_BYTES = 1024 * 1024  # 1 MB

# The folders Lim & Co's workspace is divided into. Used for listing only.
WORKSPACE_FOLDERS = ("inbox", "customers", "hr", "product_docs", "it")


class WorkspaceError(Exception):
    """Base class for every workspace access failure."""


class PathNotAllowed(WorkspaceError):
    """The path escapes the workspace, or is shaped so it might."""


class ResourceNotFound(WorkspaceError):
    """The path is safe but nothing is there."""


class FileTooLarge(WorkspaceError):
    """The file is larger than the read cap."""


def workspace_root() -> Path:
    """The one directory agent tools may read from."""
    return config.WORKSPACE_DIR.resolve()


def resolve_path(relative_path: str) -> Path:
    """Resolve a workspace-relative path, or raise PathNotAllowed.

    The check is deliberately conservative: anything that merely looks like an
    escape attempt is refused rather than normalised into something safe.
    """
    if relative_path is None or not isinstance(relative_path, str):
        raise PathNotAllowed("A path must be given as a string.")

    candidate = relative_path.strip()
    if not candidate:
        raise PathNotAllowed("An empty path is not a valid resource.")

    if "\x00" in candidate:
        raise PathNotAllowed("A path may not contain a null byte.")

    # Normalise separators before inspecting the parts.
    candidate = candidate.replace("\\", "/")

    if candidate.startswith("/") or os.path.isabs(candidate):
        raise PathNotAllowed(f"Absolute paths are not allowed: {relative_path!r}")

    if Path(candidate).drive or candidate.startswith("~"):
        raise PathNotAllowed(f"Only workspace-relative paths are allowed: {relative_path!r}")

    parts = [part for part in candidate.split("/") if part not in ("", ".")]
    if any(part == ".." for part in parts):
        raise PathNotAllowed(f"Parent directory traversal is not allowed: {relative_path!r}")
    if not parts:
        raise PathNotAllowed("An empty path is not a valid resource.")

    # A caller may address a file as "customers/orders.json" or, redundantly,
    # as "workspace/customers/orders.json". Both mean the same place.
    if parts[0] == "workspace":
        parts = parts[1:]
        if not parts:
            raise PathNotAllowed("An empty path is not a valid resource.")

    root = workspace_root()
    target = root.joinpath(*parts)

    # Reject a symlink at any depth, including the target itself. This is
    # checked before resolution, because resolution would silently follow it.
    current = root
    for part in parts:
        current = current / part
        if current.is_symlink():
            raise PathNotAllowed(f"Symbolic links are not allowed: {relative_path!r}")

    resolved = Path(os.path.realpath(target))
    if resolved != root and root not in resolved.parents:
        raise PathNotAllowed(f"Path escapes the workspace: {relative_path!r}")

    return resolved


def relative_name(path: Path) -> str:
    """The path as it should appear in an audit event or an alert."""
    try:
        return f"workspace/{path.resolve().relative_to(workspace_root()).as_posix()}"
    except ValueError:
        return path.name


def list_folder(folder: str) -> list[str]:
    """File names directly inside one workspace folder, sorted."""
    target = resolve_path(folder)

    if not target.exists():
        raise ResourceNotFound(f"No such folder: {folder}")
    if not target.is_dir():
        raise ResourceNotFound(f"Not a folder: {folder}")

    return sorted(
        entry.name
        for entry in target.iterdir()
        if entry.is_file() and not entry.name.startswith(".")
    )


def list_folders() -> list[str]:
    """The workspace folders that exist."""
    root = workspace_root()
    return [name for name in WORKSPACE_FOLDERS if (root / name).is_dir()]


def read_file(path: str) -> str:
    """Read a workspace file as text, capped at 1 MB.

    The caller gets the content; whether the *agent* gets it is decided by the
    gateway after the detector has scanned it.
    """
    target = resolve_path(path)

    if not target.exists():
        raise ResourceNotFound(f"No such file: {path}")
    if not target.is_file():
        raise ResourceNotFound(f"Not a file: {path}")

    size = target.stat().st_size
    if size > MAX_READ_BYTES:
        raise FileTooLarge(
            f"{path} is {size} bytes, over the {MAX_READ_BYTES} byte read limit."
        )

    return target.read_text(encoding="utf-8", errors="replace")


def file_size(path: str) -> int:
    """Size in bytes of a workspace file."""
    target = resolve_path(path)
    if not target.is_file():
        raise ResourceNotFound(f"No such file: {path}")
    return target.stat().st_size


def folder_counts() -> dict[str, int]:
    """How many files sit in each workspace folder.

    Used by the admin workspace screen, which reports counts per location.
    """
    counts: dict[str, int] = {}
    for folder in list_folders():
        counts[folder] = len(list_folder(folder))
    return counts
