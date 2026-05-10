from rich.console import Console


def test_bracketed_mount_source_renders_literal_without_crash() -> None:
    c = Console(record=True, markup=False)
    mount_source = "/dev/mapper/pve-vm--106--disk--0[/usr/bin/docker]"
    c.print(f"source={mount_source}")
    out = c.export_text()
    assert mount_source in out
