#!/usr/bin/env python3
"""
BinForge - Reporter Module
Generates human-readable and machine-readable reports from scan results.
"""

from __future__ import annotations

import json
import csv
import io
import datetime
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.scanner import Block

# ── ANSI color codes ──────────────────────────────────────────────────────────

RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"

RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"
WHITE  = "\033[97m"
GREY   = "\033[90m"

# Category → color
CATEGORY_COLORS: dict[str, str] = {
    "image":      CYAN,
    "video":      BLUE,
    "audio":      "\033[95m",   # magenta
    "archive":    YELLOW,
    "executable": RED,
    "document":   GREEN,
    "database":   "\033[93m",
    "network":    "\033[94m",
    "crypto":     "\033[91m",
    "font":       "\033[37m",
    "3d":         "\033[36m",
    "mobile":     "\033[32m",
    "data":       "\033[33m",
    "text":       WHITE,
    "medical":    "\033[35m",
    "debug":      "\033[31m",
    "disk":       "\033[34m",
}


def _cat_color(category: str) -> str:
    return CATEGORY_COLORS.get(category.lower(), GREY)


def _human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024
    return f"{n:.1f} PB"


# ─────────────────────────────────────────────────────────────────────────────
#  Terminal (rich) reporter
# ─────────────────────────────────────────────────────────────────────────────

class TerminalReporter:
    """Prints formatted scan results to stdout."""

    BAR_WIDTH = 60

    def __init__(self, *, color: bool = True, verbose: bool = False) -> None:
        self.color = color
        self.verbose = verbose

    def _c(self, code: str, text: str) -> str:
        return f"{code}{text}{RESET}" if self.color else text

    def print_header(self, path: str, file_size: int) -> None:
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print()
        print(self._c(BOLD + CYAN, "╔══════════════════════════════════════════════════════════════╗"))
        print(self._c(BOLD + CYAN, "║") + self._c(BOLD + WHITE, "  ██████╗ ██╗███╗   ██╗███████╗ ██████╗ ██████╗  ██████╗ ███████╗") + self._c(BOLD + CYAN, ""))
        print(self._c(BOLD + CYAN, "║") + self._c(BOLD + WHITE, "  ██╔══██╗██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝") + self._c(BOLD + CYAN, ""))
        print(self._c(BOLD + CYAN, "║") + self._c(BOLD + WHITE, "  ██████╔╝██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██║  ███╗█████╗  ") + self._c(BOLD + CYAN, ""))
        print(self._c(BOLD + CYAN, "║") + self._c(BOLD + WHITE, "  ██╔══██╗██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝  ") + self._c(BOLD + CYAN, ""))
        print(self._c(BOLD + CYAN, "║") + self._c(BOLD + WHITE, "  ██████╔╝██║██║ ╚████║██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗") + self._c(BOLD + CYAN, ""))
        print(self._c(BOLD + CYAN, "║") + self._c(BOLD + WHITE, "  ╚═════╝ ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝") + self._c(BOLD + CYAN, ""))
        print(self._c(BOLD + CYAN, "║") + self._c(DIM, f"  Binary Magic Forensics Engine v2.0.0  ·  {ts}"))
        print(self._c(BOLD + CYAN, "╚══════════════════════════════════════════════════════════════╝"))
        print()
        print(self._c(BOLD, "  Target : ") + self._c(YELLOW, path))
        print(self._c(BOLD, "  Size   : ") + self._c(WHITE, _human_size(file_size)))
        print()

    def print_blocks(self, blocks: list[Block]) -> None:
        if not blocks:
            print(self._c(YELLOW, "  ⚠  No magic signatures found."))
            return

        print(self._c(BOLD + WHITE, f"  ┌─ Found {len(blocks)} block(s) ─────────────────────────────────────"))
        print()

        for blk in blocks:
            sig = blk.match.signature
            cc  = _cat_color(sig.category)

            # Block header line
            idx_tag  = self._c(DIM,       f"  #{blk.index:>3}  ")
            name_tag = self._c(BOLD + cc, f"[{sig.name}]")
            cat_tag  = self._c(DIM,       f" ({sig.category})")
            print(idx_tag + name_tag + cat_tag)

            # Position / size bar
            start_hex = f"0x{blk.start_offset:08X}"
            end_hex   = f"0x{blk.end_offset:08X}"
            size_str  = _human_size(blk.size)
            print(f"         {self._c(BOLD,'Offset')}  {self._c(CYAN, start_hex)} → {self._c(CYAN, end_hex)}  "
                  f"({self._c(GREEN, size_str)})")

            # Description + MIME
            print(f"         {self._c(BOLD,'Type')}    {sig.description}")
            print(f"         {self._c(BOLD,'MIME')}    {self._c(DIM, sig.mime)}")

            if sig.extensions:
                exts = ", ".join(e for e in sig.extensions if e)
                if exts:
                    print(f"         {self._c(BOLD,'Exts')}    {exts}")

            # Hash
            if blk.sha256:
                print(f"         {self._c(BOLD,'SHA256')}  {self._c(DIM, blk.sha256)}")

            # Hex preview
            if blk.hex_preview and self.verbose:
                hex_pairs = " ".join(
                    blk.hex_preview[i:i+2] for i in range(0, len(blk.hex_preview), 2)
                )
                print(f"         {self._c(BOLD,'Hex')}     {self._c(GREY, hex_pairs)}")
                print(f"         {self._c(BOLD,'ASCII')}   {self._c(GREY, blk.ascii_preview)}")

            print(f"         {self._c(DIM, '─' * 50)}")
            print()

    def print_summary(self, blocks: list[Block], elapsed: float) -> None:
        if not blocks:
            return

        # Category stats
        cat_counts: dict[str, int] = {}
        for blk in blocks:
            cat = blk.match.signature.category
            cat_counts[cat] = cat_counts.get(cat, 0) + 1

        total_size = sum(b.size for b in blocks)

        print(self._c(BOLD + WHITE, "  ╔═ Summary ══════════════════════════════════════════════════╗"))
        print(f"  ║  Blocks found : {self._c(BOLD, str(len(blocks)))}")
        print(f"  ║  Total mapped : {self._c(GREEN, _human_size(total_size))}")
        print(f"  ║  Scan time    : {self._c(CYAN, f'{elapsed:.3f}s')}")
        print(f"  ║")
        print(f"  ║  Categories:")
        max_count = max(cat_counts.values()) if cat_counts else 1
        BAR_MAX   = 30
        for cat, count in sorted(cat_counts.items(), key=lambda x: -x[1]):
            bar_len = max(1, round(count / max_count * BAR_MAX))
            bar = "█" * bar_len
            cc  = _cat_color(cat)
            print(f"  ║    {self._c(cc, f'{cat:<14}')}  {self._c(cc, bar)}  {count}")
        print(self._c(BOLD + WHITE, "  ╚══════════════════════════════════════════════════════════════╝"))
        print()


# ─────────────────────────────────────────────────────────────────────────────
#  Export functions
# ─────────────────────────────────────────────────────────────────────────────

def export_json(blocks: list[Block], path: Path, *, indent: int = 2) -> None:
    """Export scan results as structured JSON."""
    output = {
        "generated": datetime.datetime.utcnow().isoformat() + "Z",
        "total_blocks": len(blocks),
        "blocks": [blk.to_dict() for blk in blocks],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(output, fh, indent=indent, ensure_ascii=False)


def export_csv(blocks: list[Block], path: Path) -> None:
    """Export scan results as CSV."""
    fieldnames = [
        "index", "start_offset", "end_offset", "size",
        "signature_name", "category", "mime", "description", "sha256",
    ]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames)
        w.writeheader()
        for blk in blocks:
            row = blk.to_dict()
            row["extensions"] = "|".join(row.get("extensions", []))
            w.writerow({k: row.get(k, "") for k in fieldnames})


def export_markdown(blocks: list[Block], path: Path, target_file: str = "") -> None:
    """Export scan results as a Markdown report."""
    lines: list[str] = []
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines += [
        f"# BinForge Report",
        f"",
        f"**Generated:** {ts}  ",
        f"**Target:** `{target_file}`  ",
        f"**Blocks found:** {len(blocks)}",
        f"",
        f"---",
        f"",
        f"## Block Map",
        f"",
        f"| # | Signature | Category | Start | End | Size | SHA-256 |",
        f"|---|-----------|----------|-------|-----|------|---------|",
    ]

    for blk in blocks:
        sig = blk.match.signature
        row = (
            f"| {blk.index} "
            f"| **{sig.name}** "
            f"| `{sig.category}` "
            f"| `0x{blk.start_offset:X}` "
            f"| `0x{blk.end_offset:X}` "
            f"| {_human_size(blk.size)} "
            f"| `{blk.sha256[:16]}…` |"
        )
        lines.append(row)

    lines += ["", "---", "", "## Detailed Blocks", ""]

    for blk in blocks:
        sig = blk.match.signature
        lines += [
            f"### Block {blk.index} — {sig.name}",
            f"",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| **Name** | {sig.name} |",
            f"| **Category** | {sig.category} |",
            f"| **MIME** | {sig.mime} |",
            f"| **Description** | {sig.description} |",
            f"| **Extensions** | {', '.join(sig.extensions)} |",
            f"| **Start offset** | `0x{blk.start_offset:08X}` ({blk.start_offset}) |",
            f"| **End offset** | `0x{blk.end_offset:08X}` ({blk.end_offset}) |",
            f"| **Size** | {_human_size(blk.size)} ({blk.size} bytes) |",
            f"| **SHA-256** | `{blk.sha256}` |",
            f"| **Hex preview** | `{blk.hex_preview}` |",
            f"| **ASCII preview** | `{blk.ascii_preview}` |",
            f"",
        ]

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))


def export_html(blocks: list[Block], path: Path, target_file: str = "") -> None:
    """Export scan results as a self-contained HTML report."""
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    rows = ""
    for blk in blocks:
        sig = blk.match.signature
        cc = CATEGORY_COLORS.get(sig.category, "")
        rows += f"""
        <tr>
          <td>{blk.index}</td>
          <td><strong>{sig.name}</strong></td>
          <td><span class="cat cat-{sig.category}">{sig.category}</span></td>
          <td><code>0x{blk.start_offset:X}</code></td>
          <td><code>0x{blk.end_offset:X}</code></td>
          <td>{_human_size(blk.size)}</td>
          <td class="mime">{sig.mime}</td>
          <td title="{blk.sha256}"><code>{blk.sha256[:12]}…</code></td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>BinForge Report — {target_file}</title>
<style>
  body {{ font-family: 'Courier New', monospace; background: #0d0d0d; color: #e0e0e0; padding: 2rem; }}
  h1 {{ color: #00e5ff; border-bottom: 1px solid #333; padding-bottom: .5rem; }}
  .meta {{ color: #888; margin-bottom: 2rem; }}
  table {{ width: 100%; border-collapse: collapse; font-size: .85rem; }}
  th {{ background: #1a1a2e; color: #00e5ff; padding: .6rem 1rem; text-align: left; }}
  td {{ padding: .5rem 1rem; border-bottom: 1px solid #1e1e1e; }}
  tr:hover td {{ background: #111; }}
  code {{ color: #00ff87; }}
  .mime {{ color: #888; font-size: .75rem; }}
  .cat {{ padding: .1rem .5rem; border-radius: 3px; font-size: .75rem; }}
  .cat-image {{ background: #0d47a1; }}
  .cat-video {{ background: #1a237e; }}
  .cat-audio {{ background: #4a148c; }}
  .cat-archive {{ background: #e65100; color: #000; }}
  .cat-executable {{ background: #b71c1c; }}
  .cat-document {{ background: #1b5e20; }}
  .cat-database {{ background: #f57f17; color: #000; }}
  .cat-network {{ background: #006064; }}
  .cat-crypto {{ background: #880e4f; }}
  .cat-font {{ background: #37474f; }}
</style>
</head>
<body>
<h1>🔬 BinForge — Binary Forensics Report</h1>
<div class="meta">
  <strong>Target:</strong> {target_file} &nbsp;·&nbsp;
  <strong>Blocks:</strong> {len(blocks)} &nbsp;·&nbsp;
  <strong>Generated:</strong> {ts}
</div>
<table>
  <thead>
    <tr><th>#</th><th>Signature</th><th>Category</th><th>Start</th><th>End</th><th>Size</th><th>MIME</th><th>SHA-256</th></tr>
  </thead>
  <tbody>{rows}
  </tbody>
</table>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
