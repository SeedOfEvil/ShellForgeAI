import codecs
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

SCRIPT = Path("scripts/windows_capture_normalization.py")
SPEC = importlib.util.spec_from_file_location("windows_capture_normalization", SCRIPT)
assert SPEC and SPEC.loader
NORMALIZATION = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = NORMALIZATION
SPEC.loader.exec_module(NORMALIZATION)
CaptureNormalizationError = NORMALIZATION.CaptureNormalizationError
normalize_saved_capture = NORMALIZATION.normalize_saved_capture


def _normalize(tmp_path, raw: bytes, **kwargs):
    source = tmp_path / "raw.capture"
    normalized = tmp_path / "normalized.utf8"
    source.write_bytes(raw)
    before = source.read_bytes()
    before_hash = hashlib.sha256(before).hexdigest()
    metadata = normalize_saved_capture(source, normalized, **kwargs)
    assert source.read_bytes() == before
    assert hashlib.sha256(source.read_bytes()).hexdigest() == before_hash
    assert metadata["raw_preserved"] is True
    assert metadata["raw_sha256"] == before_hash
    assert metadata["raw_size_bytes"] == len(before)
    assert metadata["normalized_sha256"] == hashlib.sha256(normalized.read_bytes()).hexdigest()
    assert metadata["normalized_size_bytes"] == len(normalized.read_bytes())
    assert metadata["normalized_encoding"] == "utf-8"
    assert metadata["normalization_status"] == "ok"
    return normalized.read_bytes(), metadata


@pytest.mark.parametrize(
    ("raw", "source_encoding", "encoding_source"),
    [
        ("ASCII and café 雪".encode(), "utf-8", "default"),
        (codecs.BOM_UTF8 + "ASCII and café 雪".encode(), "utf-8", "bom"),
        (codecs.BOM_UTF16_LE + "ASCII and café 雪".encode("utf-16-le"), "utf-16-le", "bom"),
        (codecs.BOM_UTF16_BE + "ASCII and café 雪".encode("utf-16-be"), "utf-16-be", "bom"),
    ],
)
def test_supported_unicode_encodings_become_bomless_utf8(
    tmp_path, raw, source_encoding, encoding_source
):
    normalized, metadata = _normalize(tmp_path, raw)
    assert normalized == "ASCII and café 雪".encode()
    assert not normalized.startswith(codecs.BOM_UTF8)
    assert metadata["source_encoding"] == source_encoding
    assert metadata["encoding_source"] == encoding_source


def test_cp437_requires_explicit_metadata(tmp_path):
    raw = "box ├─ done".encode("cp437")
    normalized, metadata = _normalize(tmp_path, raw, explicit_source_encoding="cp437")
    assert normalized.decode("utf-8") == "box ├─ done"
    assert metadata["source_encoding"] == "cp437"
    assert metadata["encoding_source"] == "explicit"

    source = tmp_path / "raw-without-metadata.capture"
    source.write_bytes(raw)
    with pytest.raises(CaptureNormalizationError, match="not valid UTF-8"):
        normalize_saved_capture(source, tmp_path / "rejected.utf8")
    assert source.read_bytes() == raw


@pytest.mark.parametrize(
    ("raw", "explicit", "message"),
    [
        (b"\xffinvalid", None, "not valid UTF-8"),
        (b"\xffinvalid", "utf-8", "invalid bytes for explicit"),
        (b"\xff\xfe{", None, "invalid or truncated"),
        ("hello".encode("utf-16-le"), None, "ambiguous NUL"),
        (b"hello", "cp1252", "unsupported explicit"),
    ],
)
def test_invalid_or_ambiguous_input_fails_closed(tmp_path, raw, explicit, message):
    source = tmp_path / "raw.capture"
    destination = tmp_path / "normalized.utf8"
    source.write_bytes(raw)
    before = source.read_bytes()
    with pytest.raises(CaptureNormalizationError, match=message):
        normalize_saved_capture(
            source,
            destination,
            explicit_source_encoding=explicit,
            content_kind="text",
        )
    assert source.read_bytes() == before
    assert not destination.exists()


def test_preexisting_known_mojibake_is_rejected_without_repair(tmp_path):
    raw = "Model assessment â€” already corrupted".encode()
    source = tmp_path / "raw.txt"
    source.write_bytes(raw)
    with pytest.raises(CaptureNormalizationError, match="pre-existing mojibake"):
        normalize_saved_capture(source, tmp_path / "normalized.txt")
    assert source.read_bytes() == raw
    assert not (tmp_path / "normalized.txt").exists()


@pytest.mark.parametrize(
    "raw_builder",
    [
        lambda text: text.encode("utf-8"),
        lambda text: codecs.BOM_UTF8 + text.encode("utf-8"),
        lambda text: codecs.BOM_UTF16_LE + text.encode("utf-16-le"),
        lambda text: codecs.BOM_UTF16_BE + text.encode("utf-16-be"),
    ],
)
def test_json_semantics_are_identical_for_every_supported_encoding(tmp_path, raw_builder):
    value = {"heading": "Windows evidence", "healthy": True, "label": "café 雪"}
    text = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    normalized, _ = _normalize(tmp_path, raw_builder(text), content_kind="json")
    assert normalized == text.encode("utf-8")
    assert json.loads(text) == json.loads(normalized.decode("utf-8"))


def test_malformed_json_is_distinct_from_encoding_failure(tmp_path):
    source = tmp_path / "raw.json"
    source.write_text('{"valid_encoding":', encoding="utf-8")
    with pytest.raises(CaptureNormalizationError, match="malformed JSON"):
        normalize_saved_capture(source, tmp_path / "normalized.json", content_kind="json")


@pytest.mark.parametrize(
    "raw_builder",
    [
        lambda text: text.encode("utf-8"),
        lambda text: codecs.BOM_UTF16_LE + text.encode("utf-16-le"),
    ],
)
def test_transcript_is_preserved_exactly(tmp_path, raw_builder):
    text = (
        "## Windows evidence\nUnicode: café 雪\n\n## Model assessment\n"
        "Mutation refused. No command was executed.\nSafe next step: inspect read-only evidence.\n"
    )
    normalized, _ = _normalize(tmp_path, raw_builder(text))
    assert normalized.decode("utf-8") == text
    for marker in (
        "## Windows evidence",
        "## Model assessment",
        "Mutation refused",
        "No command was executed",
        "Safe next step",
    ):
        assert marker in normalized.decode("utf-8")


def test_raw_artifact_cannot_be_used_as_destination(tmp_path):
    source = tmp_path / "capture.txt"
    source.write_text("safe", encoding="utf-8")
    with pytest.raises(CaptureNormalizationError, match="must differ"):
        normalize_saved_capture(source, source)
    assert source.read_bytes() == b"safe"


def test_hardlink_alias_cannot_be_used_as_destination(tmp_path):
    source = tmp_path / "capture.txt"
    destination = tmp_path / "normalized.txt"
    raw = codecs.BOM_UTF16_LE + "immutable café 雪".encode("utf-16-le")
    source.write_bytes(raw)
    destination.hardlink_to(source)
    raw_sha256 = hashlib.sha256(raw).hexdigest()

    with pytest.raises(CaptureNormalizationError, match="must not alias"):
        normalize_saved_capture(source, destination)

    assert source.read_bytes() == raw
    assert destination.read_bytes() == raw
    assert hashlib.sha256(source.read_bytes()).hexdigest() == raw_sha256
    assert hashlib.sha256(destination.read_bytes()).hexdigest() == raw_sha256
