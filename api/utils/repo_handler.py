import zipfile
import os
import shutil


def extract_zip(zip_path: str, extract_to: str) -> str:
    """
    Extracts zip file and returns the path to the repo root.
    Handles nested folders (GitHub zips add a top-level folder).
    """
    with zipfile.ZipFile(zip_path, "r") as z:
        # Security check: prevent zip slip
        for member in z.namelist():
            member_path = os.path.realpath(
                os.path.join(extract_to, member)
            )
            if not member_path.startswith(
                os.path.realpath(extract_to)
            ):
                raise ValueError(f"Zip slip detected: {member}")
        z.extractall(extract_to)

    # Find the actual repo directory
    # GitHub zips: repo-name-branch/ as top level
    entries = [
        e for e in os.listdir(extract_to)
        if os.path.isdir(os.path.join(extract_to, e))
        and e not in ["__MACOSX"]
        and not e.endswith(".zip")
    ]

    if len(entries) == 1:
        # Standard GitHub zip — one top-level folder
        return os.path.join(extract_to, entries[0])

    # Multiple entries or flat structure — return root
    return extract_to