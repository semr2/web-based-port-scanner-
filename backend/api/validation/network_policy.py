import ipaddress
from typing import Union

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

_DENIED_IPV4_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
]

_DENIED_IPV6_NETWORKS = [
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("ff00::/8"),
]


def is_approved_ip(address: IPAddress) -> bool:
    if not isinstance(address, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        raise TypeError("is_approved_ip requires an ipaddress object, not a string")

    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return is_approved_ip(address.ipv4_mapped)

    if isinstance(address, ipaddress.IPv4Address):
        for network in _DENIED_IPV4_NETWORKS:
            if address in network:
                return False
        return True

    if isinstance(address, ipaddress.IPv6Address):
        for network in _DENIED_IPV6_NETWORKS:
            if address in network:
                return False
        return True

    return False


def is_private_ip(address: IPAddress) -> bool:
    return not is_approved_ip(address)


def is_metadata_endpoint(address: IPAddress) -> bool:
    try:
        return address == ipaddress.ip_address("169.254.169.254")
    except ValueError:
        return False
