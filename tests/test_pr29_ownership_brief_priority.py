from shellforgeai.cli import _ownership_evidence_rows
from shellforgeai.core.evidence import EvidenceCategory, EvidenceItem


def test_ownership_rows_prioritize_mount_and_stat() -> None:
    items = [
        EvidenceItem(
            source="host.info",
            category=EvidenceCategory.host,
            title="h",
            summary="h",
            content="",
            ok=True,
        ),
        EvidenceItem(
            source="files.stat",
            category=EvidenceCategory.files,
            title="stat",
            summary="owner=root:root",
            content="",
            ok=True,
        ),
        EvidenceItem(
            source="storage.mount_target",
            category=EvidenceCategory.host,
            title="mt",
            summary="/usr/local/bin/docker /dev/mapper[/usr/bin/docker] ext4 ro",
            content="",
            ok=True,
        ),
        EvidenceItem(
            source="storage.mounts",
            category=EvidenceCategory.host,
            title="m",
            summary="root=ext4",
            content="",
            ok=True,
        ),
        EvidenceItem(
            source="package.file_owner",
            category=EvidenceCategory.packages,
            title="po",
            summary="not owned",
            content="",
            ok=True,
        ),
    ]
    rows = _ownership_evidence_rows(items)
    sources = [r["source"] for r in rows]
    assert sources[:4] == [
        "files.stat",
        "storage.mount_target",
        "storage.mounts",
        "package.file_owner",
    ]
