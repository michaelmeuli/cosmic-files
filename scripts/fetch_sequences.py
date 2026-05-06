#!/usr/bin/env python3
"""Fetch reference FASTA sequences from NCBI for the cosmic-files sequencing module.

Reads res/sequences/sequences.toml and fetches any missing FASTA files.
Safe to run repeatedly; existing files are skipped unless --force is given.

Requires Python 3.11+ (uses stdlib tomllib).
On older Python: pip install tomli
"""

import os
import sys
import time
import urllib.request
import urllib.parse
import urllib.error
from pathlib import Path

try:
    import tomllib  # Python 3.11+
except ImportError:
    try:
        import tomli as tomllib  # pip install tomli
    except ImportError:
        sys.exit("Python 3.11+ is required (or: pip install tomli)")

EUTILS = "https://eutils.ncbi.nlm.nih.gov/entrez/eutils"
DELAY = 0.4  # seconds between requests — NCBI allows 3/s without an API key


def ncbi_get(endpoint: str, params: dict) -> str:
    time.sleep(DELAY)
    url = f"{EUTILS}/{endpoint}?" + urllib.parse.urlencode(params)
    try:
        with urllib.request.urlopen(url, timeout=120) as resp:
            data = resp.read().decode()
    except urllib.error.HTTPError as e:
        sys.exit(f"NCBI HTTP {e.code} for {url}: {e.reason}")
    except urllib.error.URLError as e:
        sys.exit(f"Network error fetching {url}: {e}")
    if "API rate limit exceeded" in data:
        sys.exit("NCBI rate limit hit — add api_key to sequences.toml or wait and retry")
    return data


def base_params(email: str, api_key: str) -> dict:
    p = {"email": email}
    if api_key:
        p["api_key"] = api_key
    return p


def fetch_direct(accession: str, out_path: Path, email: str, api_key: str) -> None:
    print(f"  [{accession}] fetching FASTA → {out_path.name}")
    fasta = ncbi_get("efetch.fcgi", {
        **base_params(email, api_key),
        "db": "nuccore",
        "id": accession,
        "rettype": "fasta",
        "retmode": "text",
    })
    if not fasta.startswith(">"):
        sys.exit(f"Unexpected response for {accession}:\n{fasta[:300]}")
    out_path.write_text(fasta)


def parse_feature_table(ft_text: str, locus_tag: str) -> tuple[int, int, int]:
    """Return (start, stop, strand) for the feature whose locus_tag matches.

    Coordinates are 1-based (NCBI convention).  Strand: 1 = forward, 2 = reverse.
    Forward features: start < stop in the table.
    Reverse/complement features: start > stop in the table.
    """
    cur_start: int | None = None
    cur_stop:  int | None = None
    cur_strand: int = 1

    for line in ft_text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(">"):
            continue

        if line[0] != "\t":
            # Feature location line: <start>\t<stop>\t<type>
            parts = stripped.split("\t")
            if len(parts) >= 2:
                try:
                    a = int(parts[0].lstrip("<>"))
                    b = int(parts[1].lstrip("<>"))
                    cur_start  = min(a, b)
                    cur_stop   = max(a, b)
                    cur_strand = 2 if a > b else 1
                except ValueError:
                    cur_start = cur_stop = None
        else:
            # Qualifier line: \t\t\t\t<key>\t<value>
            parts = stripped.split("\t")
            if len(parts) >= 2 and parts[0] == "locus_tag" and parts[1] == locus_tag:
                if cur_start is not None:
                    return cur_start, cur_stop, cur_strand

    raise ValueError(
        f"locus_tag {locus_tag!r} not found in feature table — "
        "check that the accession and locus_tag are correct"
    )


def fetch_genome_gene(
    accession: str,
    locus_tag: str | None,
    seq_start: int | None,
    seq_stop:  int | None,
    out_path: Path,
    email: str,
    api_key: str,
) -> None:
    strand = 1

    if locus_tag:
        print(f"  [{accession}] downloading feature table to locate {locus_tag} …")
        ft = ncbi_get("efetch.fcgi", {
            **base_params(email, api_key),
            "db": "nuccore",
            "id": accession,
            "rettype": "ft",
            "retmode": "text",
        })
        seq_start, seq_stop, strand = parse_feature_table(ft, locus_tag)
        print(f"    found: {seq_start}..{seq_stop} strand={'fwd' if strand == 1 else 'rev'}")

    if seq_start is None or seq_stop is None:
        sys.exit(
            f"Entry for {out_path.name}: must specify either 'locus_tag' or "
            "both 'seq_start' and 'seq_stop'"
        )

    print(f"  [{accession}:{seq_start}-{seq_stop}] fetching FASTA → {out_path.name}")
    fasta = ncbi_get("efetch.fcgi", {
        **base_params(email, api_key),
        "db": "nuccore",
        "id": accession,
        "rettype": "fasta",
        "retmode": "text",
        "seq_start": seq_start,
        "seq_stop": seq_stop,
        "strand": strand,
    })
    if not fasta.startswith(">"):
        sys.exit(
            f"Unexpected response for {accession}:{seq_start}-{seq_stop}:\n{fasta[:300]}"
        )
    out_path.write_text(fasta)


def main() -> None:
    force = "--force" in sys.argv

    repo_root   = Path(__file__).parent.parent
    config_path = repo_root / "res" / "sequences" / "sequences.toml"
    seq_dir     = repo_root / "res" / "sequences"

    if not config_path.exists():
        sys.exit(f"Config not found: {config_path}")

    with open(config_path, "rb") as f:
        config = tomllib.load(f)

    email   = config.get("email",   "")
    api_key = os.environ.get("NCBI_API_KEY") or config.get("api_key", "")
    if not email:
        sys.exit("sequences.toml must contain: email = \"your@email.com\"")

    fetched = skipped = errors = 0

    for entry in config.get("direct", []):
        out = seq_dir / entry["output"]
        if out.exists() and not force:
            print(f"  skip (exists): {out.name}")
            skipped += 1
            continue
        out.parent.mkdir(parents=True, exist_ok=True)
        try:
            fetch_direct(entry["accession"], out, email, api_key)
            fetched += 1
        except (SystemExit, ValueError) as e:
            print(f"  ERROR: {e}", file=sys.stderr)
            errors += 1

    for entry in config.get("genome", []):
        out = seq_dir / entry["output"]
        if out.exists() and not force:
            print(f"  skip (exists): {out.name}")
            skipped += 1
            continue
        out.parent.mkdir(parents=True, exist_ok=True)
        try:
            fetch_genome_gene(
                entry["accession"],
                entry.get("locus_tag"),
                entry.get("seq_start"),
                entry.get("seq_stop"),
                out, email, api_key,
            )
            fetched += 1
        except (SystemExit, ValueError) as e:
            print(f"  ERROR: {e}", file=sys.stderr)
            errors += 1

    print(f"\nDone: {fetched} fetched, {skipped} skipped, {errors} errors.")
    if errors:
        sys.exit(1)


if __name__ == "__main__":
    main()
