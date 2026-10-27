"""Mail-archive helpers shared by the Cortex client and the inference server.

Stdlib only on purpose: ai_mail_classifier.py (the thin Cortex client) imports
this, and its image ships neither numpy nor torch. Everything that needs the ML
stack lives in mail_analysis.py, which re-exports these names so existing
callers (`mail_analysis.untar_file`) keep working.
"""
import os
import tarfile
from collections import defaultdict

# Limits for safe extraction. The archive holds an email's parsed parts
# (body .txt, .headers) — kilobytes in practice — so these caps are generous
# while still defeating a tarbomb that aims to exhaust the worker's disk.
_TAR_MAX_MEMBERS = 1_000
_TAR_MAX_TOTAL_UNCOMPRESSED = 200 * 1024 * 1024  # 200 MB


def _is_within_directory(directory, target):
    """True if `target` resolves inside `directory` (defeats ../ traversal)."""
    abs_directory = os.path.realpath(directory)
    abs_target = os.path.realpath(target)
    prefix = os.path.join(abs_directory, "")
    return abs_target == abs_directory or abs_target.startswith(prefix)


def _safe_extract(tar_ref, extract_to):
    """Extract a tar archive defensively.

    Guards against:
      * Path traversal (CVE-2007-4559) — members with ``../`` or absolute
        paths that would write outside ``extract_to``.
      * Symlink/hardlink/device members that could redirect a later write or
        leak host files.
      * Tarbombs — too many members or too much total uncompressed data.
    """
    os.makedirs(extract_to, exist_ok=True)
    members = tar_ref.getmembers()

    if len(members) > _TAR_MAX_MEMBERS:
        raise ValueError(
            f"Archive has too many entries ({len(members)} > {_TAR_MAX_MEMBERS})."
        )

    total = 0
    for member in members:
        # Only ever extract regular files and directories. Symlinks, hardlinks,
        # FIFOs and device nodes have no business in an email-parts archive.
        if not (member.isreg() or member.isdir()):
            raise ValueError(f"Archive contains an unsupported entry type: {member.name}")

        total += max(member.size, 0)
        if total > _TAR_MAX_TOTAL_UNCOMPRESSED:
            raise ValueError("Archive uncompressed size exceeds the allowed limit.")

        target = os.path.join(extract_to, member.name)
        if not _is_within_directory(extract_to, target):
            raise ValueError(f"Archive entry escapes the extraction directory: {member.name}")

    # filter="data" is the default from Python 3.14 (spelled out so 3.12/3.13 and
    # 3.14 behave the same and the DeprecationWarning goes away).
    tar_ref.extractall(path=extract_to, members=members, filter="data")


def untar_file(filepath, extract_to):
    try:
        with tarfile.open(filepath, 'r:*') as tar_ref:
            _safe_extract(tar_ref, extract_to)
            print(f"File {filepath} untarred to {extract_to}")
        return True
    except Exception as e:
        print(f"Error untarring file: {e}")
        return False

def get_header_dict_list(msg):
    headers = defaultdict(list)
    for key, value in msg.items():
        headers[key].append(value)
    return headers
