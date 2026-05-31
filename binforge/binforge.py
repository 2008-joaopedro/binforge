#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════╗
║  BinForge v2.0.0 — Binary Magic Forensics Engine    ║
║  Reads magic bytes, maps blocks, exports reports     ║
╚══════════════════════════════════════════════════════╝

Usage:
  python binforge.py <file>  [options]
  python binforge.py --help

Examples:
  python binforge.py firmware.bin
  python binforge.py firmware.bin -v --json report.json
  python binforge.py archive.bin --categories image,audio -o results/
  python binforge.py sample.bin --extract --min-size 512
"""

from __future__ import annotations

import sys
import time
import logging
import argparse
import shutil
from pathlib import Path

# ── Local module path setup ────────────────────────────────────────────────────
_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(_ROOT))

from core.scanner  import SignatureDatabase, BinaryScanner
from core.reporter import (
    TerminalReporter,
    export_json, export_csv, export_markdown, export_html,
)

# ─────────────────────────────────────────────────────────────────────────────
#  Defaults
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_DB   = _ROOT / "data" / "magic_bytes.json"
DEFAULT_OUT  = Path("binforge_output")
VERSION      = "2.0.0"


# ─────────────────────────────────────────────────────────────────────────────
#  CLI argument parser
# ─────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="binforge",
        description="BinForge — Binary Magic Byte Forensics Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # ── Positional ─────────────────────────────────────────────────────────────
    p.add_argument(
        "target",
        metavar="FILE",
        nargs="?",
        default=None,
        help="Binary file to analyse",
    )

    # ── Database ───────────────────────────────────────────────────────────────
    p.add_argument(
        "--db",
        metavar="PATH",
        default=str(DEFAULT_DB),
        help=f"Magic bytes JSON database (default: {DEFAULT_DB})",
    )

    # ── Filtering ──────────────────────────────────────────────────────────────
    p.add_argument(
        "--categories", "-c",
        metavar="CAT1,CAT2",
        help="Comma-separated list of categories to scan (e.g. image,audio)",
    )
    p.add_argument(
        "--min-size",
        metavar="BYTES",
        type=int,
        default=0,
        help="Ignore blocks smaller than N bytes (default: 0)",
    )

    # ── Output ─────────────────────────────────────────────────────────────────
    p.add_argument(
        "--output", "-o",
        metavar="DIR",
        help="Output directory for reports (default: binforge_output/)",
    )
    p.add_argument(
        "--json",
        metavar="FILE",
        help="Also write a JSON report to FILE",
    )
    p.add_argument(
        "--csv",
        metavar="FILE",
        help="Also write a CSV report to FILE",
    )
    p.add_argument(
        "--markdown", "--md",
        metavar="FILE",
        help="Also write a Markdown report to FILE",
    )
    p.add_argument(
        "--html",
        metavar="FILE",
        help="Also write an HTML report to FILE",
    )
    p.add_argument(
        "--all-formats",
        action="store_true",
        help="Write JSON + CSV + Markdown + HTML reports (uses --output dir)",
    )

    # ── Extraction ─────────────────────────────────────────────────────────────
    p.add_argument(
        "--extract", "-e",
        action="store_true",
        help="Extract each block to a separate file inside --output dir",
    )

    # ── Verbosity ──────────────────────────────────────────────────────────────
    p.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show hex/ASCII preview for each block",
    )
    p.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colour output",
    )
    p.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress banner and progress; only print JSON to stdout",
    )
    p.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="WARNING",
        help="Internal log level (default: WARNING)",
    )

    # ── Info ───────────────────────────────────────────────────────────────────
    p.add_argument(
        "--list-categories",
        action="store_true",
        help="List all available categories in the database and exit",
    )
    p.add_argument(
        "--list-signatures",
        metavar="CATEGORY",
        help="List all signatures in a given category and exit",
    )
    p.add_argument(
        "--version",
        action="version",
        version=f"BinForge {VERSION}",
    )

    return p


# ─────────────────────────────────────────────────────────────────────────────
#  Info commands
# ─────────────────────────────────────────────────────────────────────────────

def cmd_list_categories(db: SignatureDatabase) -> None:
    cats: dict[str, int] = {}
    for sig in db.signatures:
        cats[sig.category] = cats.get(sig.category, 0) + 1
    print(f"\n  {'Category':<20} {'Count':>6}")
    print(f"  {'─'*20} {'─'*6}")
    for cat, count in sorted(cats.items()):
        print(f"  {cat:<20} {count:>6}")
    print()


def cmd_list_signatures(db: SignatureDatabase, category: str) -> None:
    sigs = [s for s in db.signatures if s.category.lower() == category.lower()]
    if not sigs:
        print(f"\n  [!] No signatures found for category: {category!r}")
        return
    print(f"\n  Signatures in [{category}] ({len(sigs)} total):\n")
    for s in sigs:
        print(f"  • {s.name:<30} {s.description}")
    print()


# ─────────────────────────────────────────────────────────────────────────────
#  Block extraction
# ─────────────────────────────────────────────────────────────────────────────

def extract_blocks(blocks, target_path: Path, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"\n  [*] Extracting {len(blocks)} block(s) to {out_dir}/")
    with open(target_path, "rb") as fh:
        for blk in blocks:
            sig = blk.match.signature
            ext = sig.extensions[0] if sig.extensions and sig.extensions[0] else ".bin"
            fname = f"block_{blk.index:03d}_{sig.name}{ext}"
            fpath = out_dir / fname
            fh.seek(blk.start_offset)
            data = fh.read(blk.size)
            fpath.write_bytes(data)
            print(f"       → {fname}  ({blk.size} bytes)")
    print()


# ─────────────────────────────────────────────────────────────────────────────
#  Main entry point
# ─────────────────────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args   = parser.parse_args(argv)

    # ── Logging ────────────────────────────────────────────────────────────────
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(levelname)s  %(name)s  %(message)s",
    )

    # ── Load database ──────────────────────────────────────────────────────────
    db_path = Path(args.db)
    if not db_path.exists():
        print(f"[!] Database not found: {db_path}", file=sys.stderr)
        return 2

    db = SignatureDatabase(db_path)

    # ── Info sub-commands ─────────────────────────────────────────────────────
    if args.list_categories:
        cmd_list_categories(db)
        return 0

    if args.list_signatures:
        cmd_list_signatures(db, args.list_signatures)
        return 0

    # ── Resolve target ─────────────────────────────────────────────────────────
    if args.target is None:
        parser.print_help()
        return 0

    target = Path(args.target)
    if not target.exists():
        print(f"[!] File not found: {target}", file=sys.stderr)
        return 2

    file_size = target.stat().st_size

    # ── Terminal reporter ──────────────────────────────────────────────────────
    reporter = TerminalReporter(
        color=not args.no_color,
        verbose=args.verbose,
    )

    if not args.quiet:
        reporter.print_header(str(target), file_size)

    # ── Build scanner ──────────────────────────────────────────────────────────
    categories = None
    if args.categories:
        categories = [c.strip() for c in args.categories.split(",")]

    scanner = BinaryScanner(
        db,
        deep_scan=True,
        compute_hashes=True,
        min_block_size=args.min_size,
        categories=categories,
    )

    # ── Scan ───────────────────────────────────────────────────────────────────
    if not args.quiet:
        print("  [*] Scanning…", end="", flush=True)

    t0     = time.perf_counter()
    blocks = scanner.scan_file(target)
    elapsed = time.perf_counter() - t0

    if not args.quiet:
        print(f"\r  [✓] Scan complete in {elapsed:.3f}s — {len(blocks)} block(s) found.\n")

    # ── Print results ──────────────────────────────────────────────────────────
    if not args.quiet:
        reporter.print_blocks(blocks)
        reporter.print_summary(blocks, elapsed)

    # ── Quiet mode: dump JSON to stdout ───────────────────────────────────────
    if args.quiet:
        import json, datetime
        out = {
            "file": str(target),
            "blocks": [blk.to_dict() for blk in blocks],
        }
        print(json.dumps(out, indent=2))

    # ── Output directory ───────────────────────────────────────────────────────
    out_dir = Path(args.output) if args.output else DEFAULT_OUT

    # ── Named exports ─────────────────────────────────────────────────────────
    if args.json:
        p = Path(args.json)
        p.parent.mkdir(parents=True, exist_ok=True)
        export_json(blocks, p)
        print(f"  [✓] JSON  → {p}")

    if args.csv:
        p = Path(args.csv)
        p.parent.mkdir(parents=True, exist_ok=True)
        export_csv(blocks, p)
        print(f"  [✓] CSV   → {p}")

    if args.markdown:
        p = Path(args.markdown)
        p.parent.mkdir(parents=True, exist_ok=True)
        export_markdown(blocks, p, str(target))
        print(f"  [✓] MD    → {p}")

    if args.html:
        p = Path(args.html)
        p.parent.mkdir(parents=True, exist_ok=True)
        export_html(blocks, p, str(target))
        print(f"  [✓] HTML  → {p}")

    # ── All-formats export ─────────────────────────────────────────────────────
    if args.all_formats:
        out_dir.mkdir(parents=True, exist_ok=True)
        stem = target.stem

        j  = out_dir / f"{stem}_report.json"
        c  = out_dir / f"{stem}_report.csv"
        md = out_dir / f"{stem}_report.md"
        h  = out_dir / f"{stem}_report.html"

        export_json    (blocks, j,  )
        export_csv     (blocks, c,  )
        export_markdown(blocks, md, str(target))
        export_html    (blocks, h,  str(target))

        print(f"\n  [✓] All reports written to {out_dir}/")
        for p in [j, c, md, h]:
            print(f"       {p.name}")

    # ── Block extraction ───────────────────────────────────────────────────────
    if args.extract:
        extract_blocks(blocks, target, out_dir / "extracted")

    if not args.quiet:
        print()

    return 0 if blocks else 1


if __name__ == "__main__":
    sys.exit(main())
