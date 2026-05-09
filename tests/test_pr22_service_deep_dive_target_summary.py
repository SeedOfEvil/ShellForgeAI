from shellforgeai.interactive.repl import _deterministic_operator_summary


def test_nginx_deep_dive_summary_includes_nginx_specific_rows() -> None:
    checks = [
        {"tool": "service.manager_detect", "summary": "manager=container-none", "status": "ok"},
        {"tool": "service.processes", "summary": "nginx processes=none", "status": "unavailable"},
        {
            "tool": "service.ports",
            "summary": "nginx expected_ports=80,443 listeners=none",
            "status": "ok",
        },
        {
            "tool": "service.config_hints",
            "summary": "/etc/nginx/nginx.conf=present",
            "status": "ok",
        },
        {"tool": "service.logs", "summary": "journal unavailable", "status": "unavailable"},
    ]
    out = _deterministic_operator_summary("service_health_deep_dive", checks, "nginx")
    assert "nginx process status" in out
    assert "nginx listener status" in out
    assert "nginx config hints" in out


def test_service_inventory_summary_still_mentions_ports() -> None:
    checks = [
        {"tool": "service.manager_detect", "summary": "manager=container-none", "status": "ok"},
        {
            "tool": "network.listeners",
            "summary": "2 listening sockets ports=8000,8080",
            "status": "ok",
        },
        {"tool": "process.snapshot", "summary": "processes=12", "status": "ok"},
    ]
    out = _deterministic_operator_summary("service_inventory_deep_dive", checks, "services")
    assert "listening ports: 8000,8080" in out
