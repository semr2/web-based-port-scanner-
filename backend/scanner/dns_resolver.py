import socket
import ipaddress

from backend.api.validation.network_policy import is_approved_ip


def resolve_approved_hostname(hostname: str) -> list[str]:
    """
    Resolve an explicitly approved hostname.

    Every returned address must belong to the approved target registry.
    """

    if not isinstance(hostname, str) or not hostname:
        raise ValueError("Hostname is required")

    try:
        records = socket.getaddrinfo(
            hostname,
            None,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM
        )
    except socket.gaierror:
        raise ValueError("DNS resolution failed")

    resolved_addresses = set()

    for record in records:
        raw_address = record[4][0]

        # Remove IPv6 scope identifiers.
        raw_address = raw_address.split("%")[0]

        try:
            address = ipaddress.ip_address(raw_address)
        except ValueError:
            raise ValueError("DNS returned an invalid IP address")

        if not is_approved_ip(address):
            raise ValueError(
                f"DNS resolved to an unapproved address: {address}"
            )

        resolved_addresses.add(str(address))

    if not resolved_addresses:
        raise ValueError("Hostname did not resolve to an IP address")

    return sorted(resolved_addresses)


def verify_dns_unchanged(
    hostname: str,
    previously_approved: list[str]
) -> bool:
    """
    Re-resolve before connecting and compare with approved addresses.
    """

    current_addresses = resolve_approved_hostname(hostname)

    return set(current_addresses) == set(previously_approved)
