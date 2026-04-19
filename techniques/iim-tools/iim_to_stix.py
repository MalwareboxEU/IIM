#!/usr/bin/env python3
"""
iim_to_stix - convert an IIM chain to a STIX 2.1 bundle.

Usage:
    python iim_to_stix.py chain.json                     # print to stdout
    python iim_to_stix.py chain.json -o bundle.json      # write to file
    python iim_to_stix.py chain.json --catalog cat.json  # include technique catalog enrichment
    cat chain.json | python iim_to_stix.py -             # read from stdin

Exit codes:
    0 - success
    1 - input invalid or conversion failed
    2 - I/O error
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    from iim_stix import iim_chain_to_stix
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


def write_output(data: dict, path: str | None, pretty: bool) -> None:
    text = json.dumps(data, indent=2 if pretty else None, sort_keys=False)
    if path and path != "-":
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
            f.write("\n")
        print(f"wrote {path}  ({len(text):,} bytes, {len(data.get('objects', [])):,} STIX objects)",
              file=sys.stderr)
    else:
        print(text)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="iim_to_stix",
        description="Convert an IIM chain to a STIX 2.1 bundle.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Usage:", 1)[1],
    )
    ap.add_argument("input", help="IIM chain JSON file (or '-' for stdin)")
    ap.add_argument("-o", "--output", help="Output file (default: stdout)")
    ap.add_argument("--catalog", help="Path to IIM technique catalog for enrichment")
    ap.add_argument("--compact", action="store_true", help="Compact JSON output (no indentation)")
    ap.add_argument("--quiet", "-q", action="store_true", help="Suppress non-error output")
    args = ap.parse_args(argv)

    # Load input
    try:
        chain = load_json(args.input)
    except FileNotFoundError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as e:
        print(f"ERROR: invalid JSON in {args.input}: {e}", file=sys.stderr)
        return 1

    # Quick sanity check
    if not isinstance(chain, dict) or "entities" not in chain or "chain" not in chain:
        print("ERROR: input does not look like an IIM chain "
              "(missing 'entities' or 'chain' top-level fields)", file=sys.stderr)
        return 1

    # Optional catalog
    catalog = None
    if args.catalog:
        try:
            catalog = load_json(args.catalog)
            if not args.quiet:
                print(f"catalog loaded: {len(catalog.get('techniques', []))} techniques",
                      file=sys.stderr)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"WARNING: could not load catalog ({e}); proceeding without enrichment",
                  file=sys.stderr)

    # Convert
    try:
        bundle = iim_chain_to_stix(chain, catalog)
    except Exception as e:
        print(f"ERROR: conversion failed: {e}", file=sys.stderr)
        return 1

    # Write
    try:
        write_output(bundle, args.output, pretty=not args.compact)
    except OSError as e:
        print(f"ERROR: could not write output: {e}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
