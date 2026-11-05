import socket
from concurrent.futures import ThreadPoolExecutor, as_completed


def scan_port(host: str, port: int, timeout: float = 1.0) -> str:
    """
    Attempt a TCP connect to a single port.

    Returns one of: "open", "closed", "filtered"
      - "open"     : connection succeeded
      - "closed"   : connection actively refused (ECONNREFUSED)
      - "filtered" : no response at all (timeout) ? likely firewalled
    """
    if not host:
        raise ValueError("Host is required")

    if not isinstance(port, int) or port < 1 or port > 65535:
        raise ValueError(f"Port must be between 1 and 65535, got: {port}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            result = sock.connect_ex((host, port))
        except socket.timeout:
            return "filtered"
        except socket.gaierror:
            raise ValueError(f"Could not resolve host: {host}")
        except OSError:
            return "filtered"

        if result == 0:
            return "open"
        else:
            return "closed"


def scan_ports(
    host: str,
    ports: list[int],
    timeout: float = 1.0,
    max_concurrency: int = 50,
) -> dict[int, str]:
    """
    Scan multiple ports concurrently against a single host, with a cap
    on simultaneous connections to avoid overwhelming the target or
    the local machine's socket/file-descriptor limits.

    Returns a dict mapping port -> state ("open" | "closed" | "filtered")
    """
    if not ports:
        return {}

    results: dict[int, str] = {}

    with ThreadPoolExecutor(max_workers=max_concurrency) as executor:
        future_to_port = {
            executor.submit(scan_port, host, port, timeout): port
            for port in ports
        }

        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                results[port] = future.result()
            except ValueError:
                # Propagate validation errors (bad host, bad port) rather
                # than silently swallowing them as a scan result
                raise

    return results
