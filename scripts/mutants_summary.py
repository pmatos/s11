#!/usr/bin/env python3
"""Aggregate cargo-mutants shard outputs into a Markdown summary.

Usage:
    mutants_summary.py <root>                       # write summary to stdout
    mutants_summary.py <root> --pr-comment <path>   # also write PR comment body
"""

import argparse
import pathlib
import sys

BUCKETS = ("caught", "missed", "timeout", "unviable", "unrun")


def count_lines(path: pathlib.Path) -> int:
    if not path.exists():
        return 0
    with path.open() as f:
        return sum(1 for _ in f)


def read_shard(root: pathlib.Path) -> dict[str, int]:
    return {b: count_lines(root / f"{b}.txt") for b in BUCKETS}


def _has_bucket_files(root: pathlib.Path) -> bool:
    return any((root / f"{b}.txt").exists() for b in BUCKETS)


def format_pr_comment(
    totals: dict[str, int],
    missed_lines: list[str],
    max_missed: int = 10,
    run_url: str | None = None,
) -> str:
    parts = ["**cargo-mutants** (PR diff)", ""]
    parts.append(", ".join(f"{b}: {totals[b]}" for b in BUCKETS))
    if missed_lines:
        parts.append("")
        parts.append("### Missed mutants")
        shown = missed_lines[:max_missed]
        for line in shown:
            parts.append(f"- `{line}`")
        if len(missed_lines) > max_missed:
            parts.append(f"_(showing {max_missed} of {len(missed_lines)})_")
    if run_url:
        parts.append("")
        parts.append(f"Full results: [workflow run]({run_url})")
    return "\n".join(parts) + "\n"


def is_empty_result(totals: dict[str, int]) -> bool:
    return all(totals.get(b, 0) == 0 for b in BUCKETS)


def format_summary_md(agg: dict) -> str:
    lines = ["## cargo-mutants summary", ""]
    if not agg["shards"]:
        lines.append("_no shards found_")
        return "\n".join(lines) + "\n"
    header = "| shard | " + " | ".join(BUCKETS) + " |"
    sep = "|" + "|".join(["---"] * (len(BUCKETS) + 1)) + "|"
    lines += [header, sep]
    for name, counts in agg["shards"]:
        row = f"| {name} | " + " | ".join(str(counts[b]) for b in BUCKETS) + " |"
        lines.append(row)
    totals = agg["totals"]
    total_row = "| **total** | " + " | ".join(f"**{totals[b]}**" for b in BUCKETS) + " |"
    lines.append(total_row)
    return "\n".join(lines) + "\n"


def aggregate(root: pathlib.Path) -> dict:
    if _has_bucket_files(root):
        shards = [(root.name, read_shard(root))]
    else:
        shards = sorted(
            ((d.name, read_shard(d)) for d in root.iterdir() if d.is_dir() and _has_bucket_files(d)),
            key=lambda s: s[0],
        )
    totals = dict.fromkeys(BUCKETS, 0)
    for _, counts in shards:
        for b in BUCKETS:
            totals[b] += counts[b]
    return {"shards": shards, "totals": totals}


def _read_missed_lines(root: pathlib.Path) -> list[str]:
    if _has_bucket_files(root):
        candidates = [root]
    else:
        candidates = sorted(
            (d for d in root.iterdir() if d.is_dir() and _has_bucket_files(d)),
            key=lambda d: d.name,
        )
    out: list[str] = []
    for c in candidates:
        p = c / "missed.txt"
        if p.exists():
            out.extend(line.rstrip("\n") for line in p.read_text().splitlines() if line.strip())
    return list(dict.fromkeys(out))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("root", type=pathlib.Path)
    ap.add_argument("--pr-comment", type=pathlib.Path)
    ap.add_argument("--run-url", default=None, help="Workflow run URL to link from PR comment")
    args = ap.parse_args(argv)

    agg = aggregate(args.root)
    sys.stdout.write(format_summary_md(agg))

    # Skip writing the PR comment when there are no mutants at all (e.g. docs-only
    # PRs). The workflow guards the sticky-comment step with `hashFiles(...)` so a
    # missing file simply suppresses the comment.
    if args.pr_comment is not None and not is_empty_result(agg["totals"]):
        missed = _read_missed_lines(args.root)
        body = format_pr_comment(agg["totals"], missed, run_url=args.run_url)
        args.pr_comment.parent.mkdir(parents=True, exist_ok=True)
        args.pr_comment.write_text(body)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
