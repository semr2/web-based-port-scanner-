import socket
import pytest

from backend.scanner.tcp_scanner import scan_port, scan_ports


# ?? scan_port() ? single port tests ?????????????????????????????????

def test_scan_open_port_returns_open(monkeypatch):
    class FakeSocket:
        def __init__(self, *a, **kw): pass
        def settimeout(self, t): pass
        def connect_ex(self, addr): return 0  # 0 = success = port open
        def close(self): pass
        def __enter__(self): return self
        def __exit__(self, *a): pass

    monkeypatch.setattr(socket, "socket", lambda *a, **kw: FakeSocket())

    result = scan_port("8.8.8.8", 443, timeout=1.0)
    assert result == "open"


def test_scan_closed_port_returns_closed(monkeypatch):
    class FakeSocket:
        def __init__(self, *a, **kw): pass
        def settimeout(self, t): pass
        def connect_ex(self, addr): return 111  # ECONNREFUSED
        def close(self): pass
        def __enter__(self): return self
        def __exit__(self, *a): pass

    monkeypatch.setattr(socket, "socket", lambda *a, **kw: FakeSocket())

    result = scan_port("8.8.8.8", 9999, timeout=1.0)
    assert result == "closed"


def test_scan_filtered_port_returns_filtered_on_timeout(monkeypatch):
    class FakeSocket:
        def __init__(self, *a, **kw): pass
        def settimeout(self, t): pass
        def connect_ex(self, addr): raise socket.timeout()
        def close(self): pass
        def __enter__(self): return self
        def __exit__(self, *a): pass

    monkeypatch.setattr(socket, "socket", lambda *a, **kw: FakeSocket())

    result = scan_port("8.8.8.8", 12345, timeout=0.1)
    assert result == "filtered"


def test_scan_port_rejects_invalid_port_number_too_low():
    with pytest.raises(ValueError):
        scan_port("8.8.8.8", 0, timeout=1.0)


def test_scan_port_rejects_invalid_port_number_too_high():
    with pytest.raises(ValueError):
        scan_port("8.8.8.8", 70000, timeout=1.0)


def test_scan_port_rejects_empty_host():
    with pytest.raises(ValueError):
        scan_port("", 80, timeout=1.0)


# ?? scan_ports() ? concurrent multi-port tests ??????????????????????

def test_scan_ports_returns_result_per_port(monkeypatch):
    def fake_scan_port(host, port, timeout):
        return "open" if port == 443 else "closed"

    monkeypatch.setattr(
        "backend.scanner.tcp_scanner.scan_port", fake_scan_port
    )

    results = scan_ports("8.8.8.8", [80, 443, 8080], timeout=1.0)

    assert results == {
        80: "closed",
        443: "open",
        8080: "closed",
    }


def test_scan_ports_respects_concurrency_limit(monkeypatch):
    # Confirms the scanner doesn't open unlimited simultaneous connections
    max_concurrent_seen = 0
    current_concurrent = 0

    def fake_scan_port(host, port, timeout):
        nonlocal max_concurrent_seen, current_concurrent
        current_concurrent += 1
        max_concurrent_seen = max(max_concurrent_seen, current_concurrent)
        current_concurrent -= 1
        return "closed"

    monkeypatch.setattr(
        "backend.scanner.tcp_scanner.scan_port", fake_scan_port
    )

    scan_ports("8.8.8.8", list(range(1, 101)), timeout=1.0, max_concurrency=10)

    assert max_concurrent_seen <= 10


def test_scan_ports_empty_port_list_returns_empty_dict():
    results = scan_ports("8.8.8.8", [], timeout=1.0)
    assert results == {}
