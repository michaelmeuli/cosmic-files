#!/usr/bin/env python3
"""Copy the cosmic-seq export bundle into res/sequences/references/.

The bundle is written by cosmic-seq `scripts/05_export_cosmic_files.py` (on the cluster:
output/cosmic-seq/results/cosmic_files/): the reference amplicon FASTAs, species_groups.tsv
(species -> group, used for 16S calls) and MANIFEST.txt. The destination is made to mirror it:
FASTA files missing from the bundle are removed. The script stops instead when the bundle lacks a
file the code embeds with include_str! (removing it would break the build).

Usage:
  python scripts/sync_cosmic_seq.py --from DIR              # a local copy of the bundle
  python scripts/sync_cosmic_seq.py --remote HOST:PATH      # scp -r from the cluster (OpenSSH)
  ... [--dry-run]

Afterwards: `cargo test -- sequencing`, review `git diff --stat res/sequences/references`, commit.
"""
from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEST = REPO / "res" / "sequences" / "references"
EXTRA = ("species_groups.tsv", "MANIFEST.txt")
INCLUDE = re.compile(r'include_str!\(\s*"[./]*/res/sequences/references/([^"]+)"\s*\)')


def records(path: Path) -> int:
    with path.open("rb") as handle:
        return sum(line.startswith(b">") for line in handle)


def same_content(a: Path, b: Path) -> bool:
    """Equal up to line endings (a Windows checkout with core.autocrlf has CRLF, the bundle LF)."""
    return a.read_bytes().replace(b"\r\n", b"\n") == b.read_bytes().replace(b"\r\n", b"\n")


def embedded() -> set[str]:
    """File names under references/ that the Rust code embeds."""
    names: set[str] = set()
    for source in (REPO / "src").rglob("*.rs"):
        names.update(INCLUDE.findall(source.read_text(encoding="utf-8")))
    return names


def sync(src: Path, dry_run: bool) -> int:
    fastas = {path.name: path for path in sorted(src.glob("*.fasta"))}
    if not fastas:
        sys.exit(f"no *.fasta in {src}")
    if not (src / "species_groups.tsv").is_file():
        sys.exit(f"no species_groups.tsv in {src} (rerun cosmic-seq scripts/04 and 05)")

    needed = embedded()
    missing = sorted(needed - set(fastas) - set(EXTRA))
    if missing:
        sys.exit(f"the bundle lacks files the code embeds: {', '.join(missing)}")

    DEST.mkdir(parents=True, exist_ok=True)
    added, changed, same = 0, 0, 0
    files = list(fastas.values()) + [src / name for name in EXTRA if (src / name).is_file()]
    for path in files:
        target = DEST / path.name
        fasta = path.suffix == ".fasta"
        if not target.exists():
            added += 1
            print(f"  added    {path.name}" + (f" ({records(path)} records)" if fasta else ""))
        elif same_content(path, target):
            same += 1
            continue
        else:
            changed += 1
            print(f"  changed  {path.name}" + (f" ({records(target)} -> {records(path)} records)" if fasta else ""))
        if not dry_run:
            shutil.copyfile(path, target)
    removed = sorted(path.name for path in DEST.glob("*.fasta") if path.name not in fastas)
    for name in removed:
        print(f"  removed  {name}")
        if not dry_run:
            (DEST / name).unlink()
    used = len(set(fastas) & needed)
    print(f"{added} added, {changed} changed, {len(removed)} removed, {same} unchanged"
          f"{' (dry run, nothing written)' if dry_run else ''}; {used} of {len(fastas)} FASTA are embedded")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--from", dest="src", type=Path, help="local directory holding the bundle")
    source.add_argument("--remote", help="scp source of the bundle directory, e.g. user@host:/path/cosmic_files")
    parser.add_argument("--dry-run", action="store_true", help="only report what would change")
    args = parser.parse_args()

    if args.src is not None:
        return sync(args.src, args.dry_run)
    with tempfile.TemporaryDirectory(prefix="cosmic_seq_") as tmp:
        print(f"scp -r {args.remote}")
        subprocess.run(["scp", "-q", "-r", args.remote, tmp], check=True)
        dirs = [path for path in Path(tmp).iterdir() if path.is_dir()]
        if len(dirs) != 1:
            sys.exit(f"expected one directory from scp, got {[p.name for p in Path(tmp).iterdir()]}")
        return sync(dirs[0], args.dry_run)


if __name__ == "__main__":
    sys.exit(main())
