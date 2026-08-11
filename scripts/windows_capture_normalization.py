"""Normalize inert saved Windows QA captures without changing raw evidence."""

from __future__ import annotations

import codecs
import hashlib
import json
from pathlib import Path
from typing import Any


class CaptureNormalizationError(ValueError):
    """A saved capture cannot become a parity-ready UTF-8 representation."""


_EXPLICIT_ENCODINGS = {"cp437": "cp437", "utf-8": "utf-8"}
_KNOWN_MOJIBAKE_MARKERS = ("â€”", "â€“", "â€™", "â€œ", "â€\x9d")


def _decode(raw: bytes, explicit_source_encoding: str | None) -> tuple[str, str, str]:
    if explicit_source_encoding is not None:
        requested = explicit_source_encoding.strip().lower().replace("_", "-")
        encoding = _EXPLICIT_ENCODINGS.get(requested)
        if encoding is None:
            raise CaptureNormalizationError("unsupported explicit source encoding")
        try:
            return raw.decode(encoding, errors="strict"), requested, "explicit"
        except UnicodeDecodeError as exc:
            raise CaptureNormalizationError("invalid bytes for explicit source encoding") from exc

    if raw.startswith(codecs.BOM_UTF8):
        encoding, source_encoding = "utf-8-sig", "utf-8"
    elif raw.startswith(codecs.BOM_UTF16_LE):
        encoding, source_encoding = "utf-16", "utf-16-le"
    elif raw.startswith(codecs.BOM_UTF16_BE):
        encoding, source_encoding = "utf-16", "utf-16-be"
    else:
        encoding = source_encoding = "utf-8"
    try:
        return (
            raw.decode(encoding, errors="strict"),
            source_encoding,
            (
                "bom"
                if raw.startswith((codecs.BOM_UTF8, codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE))
                else "default"
            ),
        )
    except UnicodeDecodeError as exc:
        if raw.startswith((codecs.BOM_UTF8, codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
            message = "capture contains invalid or truncated bytes for its BOM encoding"
        else:
            message = "capture is not valid UTF-8 and has no supported BOM"
        raise CaptureNormalizationError(message) from exc


def decode_saved_capture_bytes(raw: bytes) -> str:
    """Strictly decode an automatically supported raw saved-capture encoding."""
    try:
        return _decode(raw, None)[0]
    except CaptureNormalizationError as exc:
        raise UnicodeError(str(exc)) from exc


def normalize_saved_capture(
    source_path: str | Path,
    destination_path: str | Path,
    *,
    explicit_source_encoding: str | None = None,
    content_kind: str = "text",
) -> dict[str, Any]:
    """Write a distinct BOM-less UTF-8 parity representation and return provenance.

    The source is read-only evidence. Decoding is strict and BOM-driven; a legacy
    encoding is used only when the caller explicitly names an allowed encoding.
    """
    source = Path(source_path)
    destination = Path(destination_path)
    if source.resolve() == destination.resolve():
        raise CaptureNormalizationError("normalized destination must differ from raw source")
    if destination.exists() and source.samefile(destination):
        raise CaptureNormalizationError("normalized destination must not alias raw source")
    if content_kind not in {"text", "json"}:
        raise CaptureNormalizationError("unsupported content kind")

    raw = source.read_bytes()
    raw_sha256 = hashlib.sha256(raw).hexdigest()
    text, source_encoding, encoding_source = _decode(raw, explicit_source_encoding)
    if "\x00" in text:
        raise CaptureNormalizationError("capture contains ambiguous NUL characters")
    if any(marker in text for marker in _KNOWN_MOJIBAKE_MARKERS):
        raise CaptureNormalizationError(
            "known pre-existing mojibake is outside the capture-ingestion boundary"
        )

    parsed_source: Any = None
    if content_kind == "json":
        try:
            parsed_source = json.loads(text)
        except json.JSONDecodeError as exc:
            raise CaptureNormalizationError("decoded capture contains malformed JSON") from exc

    normalized = text.encode("utf-8", errors="strict")
    if normalized.startswith(codecs.BOM_UTF8):
        raise CaptureNormalizationError("canonical UTF-8 output unexpectedly contains a BOM")
    if content_kind == "json" and json.loads(normalized.decode("utf-8")) != parsed_source:
        raise CaptureNormalizationError("normalized JSON is not semantically equivalent")

    if source.read_bytes() != raw:
        raise CaptureNormalizationError("raw capture changed during normalization")
    destination.write_bytes(normalized)
    raw_after = source.read_bytes()
    if raw_after != raw or hashlib.sha256(raw_after).hexdigest() != raw_sha256:
        raise CaptureNormalizationError("raw capture changed during normalization")

    return {
        "normalization_status": "ok",
        "source_encoding": source_encoding,
        "encoding_source": encoding_source,
        "normalized_encoding": "utf-8",
        "raw_preserved": True,
        "raw_sha256": raw_sha256,
        "raw_size_bytes": len(raw),
        "normalized_sha256": hashlib.sha256(normalized).hexdigest(),
        "normalized_size_bytes": len(normalized),
        "content_kind": content_kind,
    }
