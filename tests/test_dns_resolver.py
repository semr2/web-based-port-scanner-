import ipaddress
import socket
import pytest

from backend.scanner.dns_resolver import resolve_approved_hostname, verify_dns_unchanged
from backend.api.validation.network_policy import is_approved_ip, is_metadata_endpoint


# ?? is_approved_ip() tests ??????????????????????????????????????????

def test_public_ipv4_is_approved():
    addr = ipaddress.ip_address("8.8.8.8")
    assert is_approved_ip(addr) is True


def test_private_ipv4_rfc1918_is_rejected():
    addr = ipaddress.ip_address("192.168.1.1")
    assert is_approved_ip(addr) is False


def test_loopback_ipv4_is_rejected():
    addr = ipaddress.ip_address("127.0.0.1")
    assert is_approved_ip(addr) is False


def test_cloud_metadata_endpoint_is_rejected():
    addr = ipaddress.ip_address("169.254.169.254")
    assert is_approved_ip(addr) is False
    assert is_metadata_endpoint(addr) is True


def test_ipv4_mapped_ipv6_metadata_bypass_is_rejected():
    # ::ffff:169.254.169.254 ? a classic SSRF bypass attempt that must
    # be unwrapped and checked against the IPv4 denylist, not waved through
    addr = ipaddress.ip_address("::ffff:169.254.169.254")
    assert is_approved_ip(addr) is False


def test_ipv6_loopback_is_rejected():
    addr = ipaddress.ip_address("::1")
    assert is_approved_ip(addr) is False


def test_ipv6_link_local_is_rejected():
    addr = ipaddress.ip_address("fe80::1")
    assert is_approved_ip(addr) is False


def test_ipv6_unique_local_is_rejected():
    addr = ipaddress.ip_address("fc00::1")
    assert is_approved_ip(addr) is False


def test_public_ipv6_is_approved():
    addr = ipaddress.ip_address("2001:4860:4860::8888")  # Google public DNS
    assert is_approved_ip(addr) is True


def test_is_approved_ip_rejects_non_address_input():
    with pytest.raises(TypeError):
        is_approved_ip("8.8.8.8")  # string, not an ipaddress object


# ?? resolve_approved_hostname() tests ???????????????????????????????

def test_resolve_rejects_empty_hostname():
    with pytest.raises(ValueError):
        resolve_approved_hostname("")


def test_resolve_rejects_non_string_hostname():
    with pytest.raises(ValueError):
        resolve_approved_hostname(None)


def test_resolve_rejects_unresolvable_hostname(monkeypatch):
    def fake_getaddrinfo(*args, **kwargs):
        raise socket.gaierror("mock DNS failure")

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    with pytest.raises(ValueError, match="DNS resolution failed"):
        resolve_approved_hostname("nonexistent.invalid")


def test_resolve_accepts_public_hostname(monkeypatch):
    def fake_getaddrinfo(*args, **kwargs):
        # Mimic socket.getaddrinfo's return shape for a public IP
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    result = resolve_approved_hostname("dns.google")
    assert result == ["8.8.8.8"]


def test_resolve_rejects_hostname_pointing_at_private_ip(monkeypatch):
    def fake_getaddrinfo(*args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.1", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    with pytest.raises(ValueError, match="unapproved address"):
        resolve_approved_hostname("internal.test")


def test_resolve_rejects_hostname_pointing_at_metadata_endpoint(monkeypatch):
    # The core SSRF-via-DNS scenario: a hostname that resolves to the
    # cloud metadata IP must be rejected, not silently scanned
    def fake_getaddrinfo(*args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    with pytest.raises(ValueError, match="unapproved address"):
        resolve_approved_hostname("attacker-controlled.test")


# ?? verify_dns_unchanged() ? DNS rebinding defense tests ????????????

def test_verify_dns_unchanged_returns_true_when_stable(monkeypatch):
    def fake_getaddrinfo(*args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    assert verify_dns_unchanged("dns.google", ["8.8.8.8"]) is True


def test_verify_dns_unchanged_returns_false_after_rebind(monkeypatch):
    # Simulates a DNS rebinding attack: the hostname previously resolved
    # to a public IP, but now resolves somewhere else before the scan runs
    def fake_getaddrinfo(*args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    assert verify_dns_unchanged("dns.google", ["8.8.8.8"]) is False
