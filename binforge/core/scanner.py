#!/usr/bin/env python3
"""
BinForge - Core Scanner Engine
Binary forensics and magic byte analysis engine.
"""

from __future__ import annotations

import json
import mmap
import struct
import hashlib
import logging
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Iterator

logger = logging.getLogger("binforge.scanner")


# ─────────────────────────────────────────────
#  Data models
# ─────────────────────────────────────────────

@dataclass
class Signature:
    """Compiled magic-byte signature ready for scanning."""
    name: str
    category: str
    mime: str
    extensions: list[str]
    pattern: bytes          # raw bytes (None bytes are wildcard slots)
    mask: bytes             # 0xFF = match this byte, 0x00 = wildcard
    offset: int             # where to look in the stream (-N means from EOF)
    description: str
    is_trailer: bool = False

    @property
    def pattern_len(self) -> int:
        return len(self.pattern)


@dataclass
class Match:
    """A confirmed magic-byte hit inside a binary stream."""
    signature: Signature
    file_offset: int        # absolute byte position in file
    pattern_hex: str        # hex representation of the matched bytes
    confidence: float = 1.0 # future: probabilistic scoring

    def __repr__(self) -> str:
        return (
            f"Match({self.signature.name!r} @ 0x{self.file_offset:X} "
            f"[{self.signature.category}])"
        )


@dataclass
class Block:
    """
    A semantic data block: from one signature hit to the next.

    Represents a contiguous region of the file that (likely) belongs
    to a single format / embedded stream.
    """
    index: int
    start_offset: int
    end_offset: int         # exclusive – first byte of NEXT block (or EOF)
    size: int
    match: Match
    sha256: str = ""

    # computed fields
    hex_preview: str = ""
    ascii_preview: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["signature_name"] = self.match.signature.name
        d["signature_category"] = self.match.signature.category
        d["mime"] = self.match.signature.mime
        d["extensions"] = self.match.signature.extensions
        d["description"] = self.match.signature.description
        del d["match"]
        return d


# ─────────────────────────────────────────────
#  Signature loader
# ─────────────────────────────────────────────

class SignatureDatabase:
    """Loads and compiles magic-byte signatures from a JSON database."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.signatures: list[Signature] = []
        self._meta: dict = {}
        self._load()

    def _load(self) -> None:
        with open(self.db_path, encoding="utf-8") as fh:
            raw = json.load(fh)

        self._meta = raw.get("_meta", {})
        loaded = skipped = 0

        for entry in raw.get("signatures", []):
            try:
                sig = self._compile(entry)
                self.signatures.append(sig)
                loaded += 1
            except Exception as exc:
                logger.debug("Skipping signature %r: %s", entry.get("name"), exc)
                skipped += 1

        # Sort: longer patterns first (reduces false positives on short prefixes)
        self.signatures.sort(key=lambda s: -s.pattern_len)

        logger.info(
            "Database loaded: %d signatures (%d skipped) from %s",
            loaded, skipped, self.db_path.name,
        )

    @staticmethod
    def _compile(entry: dict) -> Signature:
        """Parse a JSON entry into a binary-ready Signature."""
        raw_hex: str = entry["magic"].replace(" ", "").upper()
        wildcard: str = entry.get("wildcard", "??").upper()

        pattern_bytes = bytearray()
        mask_bytes = bytearray()

        # Walk two hex chars at a time
        i = 0
        while i < len(raw_hex):
            token = raw_hex[i:i+2]
            if token == wildcard:
                pattern_bytes.append(0x00)
                mask_bytes.append(0x00)
            else:
                pattern_bytes.append(int(token, 16))
                mask_bytes.append(0xFF)
            i += 2

        return Signature(
            name=entry["name"],
            category=entry.get("category", "unknown"),
            mime=entry.get("mime", "application/octet-stream"),
            extensions=entry.get("extensions", []),
            pattern=bytes(pattern_bytes),
            mask=bytes(mask_bytes),
            offset=entry.get("offset", 0),
            description=entry.get("description", ""),
            is_trailer=entry.get("is_trailer", False),
        )

    @property
    def version(self) -> str:
        return self._meta.get("version", "unknown")

    def __len__(self) -> int:
        return len(self.signatures)


# ─────────────────────────────────────────────
#  Scanner engine
# ─────────────────────────────────────────────

class BinaryScanner:
    """
    High-performance binary scanner using mmap + sliding-window pattern matching.

    Supports:
    - Fixed-offset anchored signatures (checked only at their declared offset)
    - Free-floating signatures (searched across the entire file)
    - Wildcards (mask-based matching)
    - Negative offsets (trailers / EOF markers)
    - Preview extraction (hex + printable ASCII)
    - Per-block SHA-256
    """

    PREVIEW_LEN = 32          # bytes shown in hex/ascii preview
    SCAN_CHUNK  = 1 << 20     # 1 MiB read chunks for progress reporting

    def __init__(
        self,
        db: SignatureDatabase,
        *,
        deep_scan: bool = True,
        preview_len: int = PREVIEW_LEN,
        compute_hashes: bool = True,
        min_block_size: int = 0,
        categories: list[str] | None = None,
    ) -> None:
        self.db = db
        self.deep_scan = deep_scan
        self.preview_len = preview_len
        self.compute_hashes = compute_hashes
        self.min_block_size = min_block_size
        self.categories = set(categories) if categories else None

        # Partition signatures by scan strategy
        self._anchored: list[Signature] = []   # fixed-offset: offset != 0
        self._floating: list[Signature] = []   # scan entire file: offset == 0

        for sig in db.signatures:
            if sig.is_trailer:
                continue   # trailers are handled separately
            if self.categories and sig.category not in self.categories:
                continue
            if sig.offset == 0:
                self._floating.append(sig)
            else:
                self._anchored.append(sig)

        self._trailers = [
            s for s in db.signatures
            if s.is_trailer and (not self.categories or s.category in self.categories)
        ]

        logger.debug(
            "Scanner ready: %d floating, %d anchored, %d trailers",
            len(self._floating), len(self._anchored), len(self._trailers),
        )

    # ── public API ────────────────────────────────────────────────────────────

    def scan_file(self, path: Path) -> list[Block]:
        """Scan a file and return a list of Blocks, sorted by offset."""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(path)
        if path.stat().st_size == 0:
            return []

        with open(path, "rb") as fh:
            try:
                mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
                try:
                    matches = list(self._find_all_matches(mm, path.stat().st_size))
                finally:
                    mm.close()
            except (ValueError, OSError):
                # mmap failed (e.g. pipe/special file) – fall back to read
                data = fh.read()
                matches = list(self._find_all_matches_bytes(data))

        blocks = self._build_blocks(matches, path.stat().st_size, path)
        return blocks

    def scan_bytes(self, data: bytes | bytearray, label: str = "<bytes>") -> list[Block]:
        """Scan an in-memory buffer."""
        if not data:
            return []
        matches = list(self._find_all_matches_bytes(bytes(data)))
        blocks = self._build_blocks(matches, len(data), None, raw_data=bytes(data))
        return blocks

    # ── matching core ─────────────────────────────────────────────────────────

    def _match_at(self, buf, offset: int, sig: Signature) -> bool:
        """Return True if sig matches buf at position offset."""
        end = offset + sig.pattern_len
        if end > len(buf):
            return False
        for i, (pb, mb) in enumerate(zip(sig.pattern, sig.mask)):
            if mb and buf[offset + i] != pb:
                return False
        return True

    def _find_all_matches(self, mm: mmap.mmap, file_size: int) -> Iterator[Match]:
        """Find matches using mmap; yields Match objects."""
        yield from self._run_search(mm, file_size)

    def _find_all_matches_bytes(self, data: bytes) -> Iterator[Match]:
        yield from self._run_search(data, len(data))

    def _run_search(self, buf, file_size: int) -> Iterator[Match]:
        seen: dict[int, str] = {}  # offset → signature name (dedup)

        # ── Anchored signatures ──────────────────────────────────────────────
        for sig in self._anchored:
            off = sig.offset if sig.offset >= 0 else file_size + sig.offset
            if off < 0 or off + sig.pattern_len > file_size:
                continue
            if self._match_at(buf, off, sig):
                if off not in seen:
                    seen[off] = sig.name
                    yield self._make_match(buf, off, sig)

        # ── Floating signatures ──────────────────────────────────────────────
        if not self._floating:
            return

        # Build first-byte index for fast rejection
        first_byte_map: dict[int, list[Signature]] = {}
        for sig in self._floating:
            # Only index on fixed (non-wildcard) first byte
            if sig.mask[0] == 0xFF:
                first_byte_map.setdefault(sig.pattern[0], []).append(sig)

        for off in range(file_size):
            byte_val = buf[off] if isinstance(buf[off], int) else buf[off]
            candidates = first_byte_map.get(byte_val, [])
            for sig in candidates:
                if off in seen:
                    # Allow multiple different sigs at same offset
                    if seen[off] == sig.name:
                        continue
                if self._match_at(buf, off, sig):
                    seen.setdefault(off, sig.name)
                    yield self._make_match(buf, off, sig)

    @staticmethod
    def _make_match(buf, offset: int, sig: Signature) -> Match:
        end = offset + sig.pattern_len
        matched_hex = buf[offset:end].hex().upper()
        return Match(
            signature=sig,
            file_offset=offset,
            pattern_hex=matched_hex,
        )

    # ── block assembly ────────────────────────────────────────────────────────

    def _build_blocks(
        self,
        matches: list[Match],
        file_size: int,
        path: Path | None,
        raw_data: bytes | None = None,
    ) -> list[Block]:
        if not matches:
            return []

        # Sort by offset, de-duplicate same offset+name
        seen_keys: set[tuple[int, str]] = set()
        unique: list[Match] = []
        for m in sorted(matches, key=lambda x: x.file_offset):
            key = (m.file_offset, m.signature.name)
            if key not in seen_keys:
                seen_keys.add(key)
                unique.append(m)

        # Apply min_block_size filter (post-hoc)
        blocks: list[Block] = []
        for i, m in enumerate(unique):
            start = m.file_offset
            end = unique[i + 1].file_offset if i + 1 < len(unique) else file_size
            size = end - start

            if size < self.min_block_size:
                continue

            blk = Block(
                index=len(blocks),
                start_offset=start,
                end_offset=end,
                size=size,
                match=m,
            )

            # Load raw bytes for this block (from file or buffer)
            block_data = self._read_block(blk, path, raw_data)

            if block_data:
                blk.hex_preview = block_data[: self.preview_len].hex().upper()
                blk.ascii_preview = "".join(
                    chr(b) if 0x20 <= b < 0x7F else "." for b in block_data[: self.preview_len]
                )
                if self.compute_hashes:
                    blk.sha256 = hashlib.sha256(block_data).hexdigest()

            blocks.append(blk)

        # Re-index
        for i, blk in enumerate(blocks):
            blk.index = i

        return blocks

    @staticmethod
    def _read_block(blk: Block, path: Path | None, raw_data: bytes | None) -> bytes | None:
        if raw_data is not None:
            return raw_data[blk.start_offset: blk.end_offset]
        if path:
            try:
                with open(path, "rb") as fh:
                    fh.seek(blk.start_offset)
                    return fh.read(blk.size)
            except OSError:
                pass
        return None
