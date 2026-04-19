#!/usr/bin/env python3
"""
stix_to_iim - convert a STIX 2.1 bundle to an IIM chain (enrichment workflow).

This is *not* a lossless conversion. STIX lacks three IIM concepts:
chain-scoped role semantics, ordered chains, and infrastructure techniques.
The converter infers what it can, marks everything uncertain with
confidence="tentative" and needs_review=true, and produces an import report
describing what was inferred vs. round-tripped.

Analyst review is required before promoting the imported chain to higher
confidence.

Usage:
    python stix_to_iim.py bundle.json                     # print chain to stdout
    python stix_to_iim.py bundle.json -o chain.json       # write to file
    python stix_to_iim.py bundle.json --chain-id abc      # override chain_id
    python stix_to_iim.py bundle.json --report report.json  # also write import report
    python stix_to_iim.py bundle.json --summary           # print only the summary
    cat bundle.json | python stix_to_iim.py -             # read from stdin

Exit codes:
    0 - success (chain was produced; warnings may still be present)
    1 - input invalid or conversion failed
    2 - I/O error
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    from iim_stix import stix_to_iim_chain, import_report
except ImportError:
    print("Error: iim_stix.py must be in the same directory or on PYTHONPATH", file=sys.stderr)
    sys.exit(2)


def load_json(path: str) -> dict:
    if path == "-":
        return json.load(sys.stdin)
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"Input file not found: {path}")
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)


def print_summary(report: dict, fp=sys.stderr) -> None:
    """Print a human-readable summary of the import."""
    print("", file=fp)
    print("=" * 60, file=fp)
    print("STIX → IIM import report", file=fp)
    print("=" * 60, file=fp)
    print(f"  Round-trip detected:    {'yes' if report['round_trip_detected'] else 'no (heuristic import)'}",
          file=fp)
    print(f"  Source bundle:          {report.get('stix_bundle_id', '?')}", file=fp)
    print(f"  Derived chain ID:       {report.get('iim_chain_id', '?')}", file=fp)
    print(f"  Chain confidence:       {report.get('chain_confidence', '?')}", file=fp)
    print(f"  Needs review:           {'yes' if report.get('chain_needs_review') else 'no'}",
          file=fp)
    print("", file=fp)
    print(f"  STIX bundle contained:", file=fp)
    for t, n in sorted(report.get("stix_object_counts", {}).items()):
        print(f"    {t:<18}  {n:>4}", file=fp)
    print("", file=fp)
    print(f"  IIM chain produced:", file=fp)
    print(f"    entities              {report['iim_entity_count']:>4}", file=fp)
    print(f"    chain positions       {report['iim_position_count']:>4}", file=fp)
    print(f"    relations             {report['iim_relation_count']:>4}", file=fp)
    print(f"    positions to review   {report['positions_needing_review']:>4}", file=fp)

    warnings = report.get("warnings", [])
    if warnings:
        print("", file=fp)
        print(f"  Warnings ({len(warnings)}):", file=fp)
        for w in warnings:
            print(f"    • {w}", file=fp)

    print("", file=fp)


def write_output(data: dict, path: str | None, pretty: bool, label: str = "chain") -> None:
    text = json.dumps(data, indent=2 if pretty else None, sort_keys=False)
    if path and path != "-":
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
            f.write("\n")
        print(f"wrote {label} to {path}  ({len(text):,} bytes)", file=sys.stderr)
    else:
        print(text)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="stix_to_iim",
        description="Convert a STIX 2.1 bundle to an IIM chain (enrichment workflow).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Usage:", 1)[1],
    )
    ap.add_argument("input", help="STIX 2.1 bundle JSON file (or '-' for stdin)")
    ap.add_argument("-o", "--output", help="Output file for the IIM chain (default: stdout)")
    ap.add_argument("--chain-id", help="Override the derived chain_id")
    ap.add_argument("--report", help="Write the import report to this file (JSON)")
    ap.add_argument("--summary", action="store_true",
                    help="Print only the human-readable summary; don't output the chain JSON")
    ap.add_argument("--compact", action="store_true", help="Compact JSON output (no indentation)")
    ap.add_argument("--quiet", "-q", action="store_true", help="Suppress summary output")
    args = ap.parse_args(argv)

    # Load input
    try:
        bundle = load_json(args.input)
    except FileNotFoundError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as e:
        print(f"ERROR: invalid JSON in {args.input}: {e}", file=sys.stderr)
        return 1

    # Validate STIX structure
    if not isinstance(bundle, dict) or bundle.get("type") != "bundle":
        print("ERROR: input is not a STIX bundle (missing 'type: bundle')", file=sys.stderr)
        return 1

    # Convert
    try:
        chain = stix_to_iim_chain(bundle, chain_id=args.chain_id)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"ERROR: conversion failed: {e}", file=sys.stderr)
        return 1

    # Build report
    report = import_report(bundle, chain)

    # Write chain (unless --summary only)
    if not args.summary:
        try:
            write_output(chain, args.output, pretty=not args.compact, label="chain")
        except OSError as e:
            print(f"ERROR: could not write chain: {e}", file=sys.stderr)
            return 2

    # Write report if requested
    if args.report:
        try:
            write_output(report, args.report, pretty=not args.compact, label="report")
        except OSError as e:
            print(f"ERROR: could not write report: {e}", file=sys.stderr)
            return 2

    # Print summary unless quiet
    if not args.quiet:
        print_summary(report)

    # Exit with non-zero if the chain needs review but still produce output
    # (this lets CI pipelines detect "needs review" without treating it as failure)
    # We use exit 0 here because the conversion itself succeeded.
    return 0


if __name__ == "__main__":
    sys.exit(main())
