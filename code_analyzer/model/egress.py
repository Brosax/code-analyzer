"""Whether a request may leave for a host at all.

Client source code only ever goes to the local GPU.  The earlier rule judged
"local" by a profile *name*, so pointing a local-named profile at a cloud URL
passed it.  Here the decision is about addresses:

* creating an evaluation **pins** the model host -- its name, port and the
  addresses it resolved to -- and a client evaluation may only reach that pin;
* the pinned host must resolve entirely to loopback, RFC 1918, link-local or
  ULA space, unless a human explicitly confirmed a non-private host;
* every request re-resolves and must land inside the pinned address set -- a
  name that now answers with any other address, private or not, is blocked
  until a human re-pins -- then connects to that validated IP (https still
  verifies the certificate against the name), so a DNS answer that changes
  after the check cannot redirect the socket;
* a public evaluation may additionally use the third-party endpoint, and only
  when a human switched ``allow_public_model`` on.  There is no automatic
  failover to it, ever.

Changing settings.toml does not move an existing pin: an evaluation keeps the
host it was created with until a human re-pins it.
"""
from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import Any

from .client import Endpoint, ModelError

PRIVATE_NETWORKS = tuple(ipaddress.ip_network(net) for net in (
    "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
    "::1/128", "fc00::/7", "fe80::/10",
))
CONFIDENTIALITY = ("client", "public")

Resolver = Callable[[str, int], tuple[str, ...]]


class EgressBlocked(ModelError):
    def __init__(self, message: str) -> None:
        super().__init__("EGRESS_BLOCKED", message)


def resolve(host: str, port: int) -> tuple[str, ...]:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as error:
        raise ModelError("TRANSPORT", f"cannot resolve {host}: {error}") from error
    return tuple(sorted({str(info[4][0]) for info in infos}))


def is_private(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return any(ip in network for network in PRIVATE_NETWORKS)


@dataclass(frozen=True)
class Pin:
    host: str
    port: int
    addresses: tuple[str, ...]
    model: str
    digest: str = ""
    public_host_confirmed: bool = False
    scheme: str = "http"

    @property
    def private(self) -> bool:
        return bool(self.addresses) and all(is_private(a) for a in self.addresses)

    def to_json(self) -> dict[str, Any]:
        data = asdict(self)
        data["addresses"] = list(self.addresses)
        return data

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> Pin:
        return cls(str(data["host"]), int(data["port"]), tuple(str(a) for a in data.get("addresses", ())),
                   str(data.get("model", "")), str(data.get("digest", "")),
                   bool(data.get("public_host_confirmed", False)), str(data.get("scheme", "http")))


def pin_endpoint(endpoint: Endpoint, *, digest: str = "", public_host_confirmed: bool = False,
                 resolver: Resolver = resolve) -> Pin:
    """Pin the host an evaluation will talk to.  Refuses a public host unless a human confirmed it."""
    addresses = resolver(endpoint.host, endpoint.port)
    pin = Pin(endpoint.host, endpoint.port, addresses, endpoint.model, digest, public_host_confirmed, endpoint.scheme)
    if not addresses:
        raise EgressBlocked(f"{endpoint.host} resolves to no address")
    if not pin.private and not public_host_confirmed:
        raise EgressBlocked(
            f"{endpoint.host} resolves to {', '.join(addresses)}, which is not a private address; "
            "a client evaluation may only use a local model host unless a human confirms this one")
    return pin


@dataclass(frozen=True)
class Target:
    scheme: str
    connect_host: str
    host_header: str
    port: int
    tls_name: str = ""


@dataclass(frozen=True)
class EgressPolicy:
    """The evaluation's side of the decision.  ``None`` in place of one means: no evaluation content."""

    confidentiality: str
    pin: Pin | None
    allow_public_model: bool = False

    def __post_init__(self) -> None:
        if self.confidentiality not in CONFIDENTIALITY:
            raise ValueError(f"confidentiality must be one of {CONFIDENTIALITY}")
        if self.allow_public_model and self.confidentiality != "public":
            raise EgressBlocked("allow_public_model is only possible for a public evaluation")


def check(endpoint: Endpoint, policy: EgressPolicy | None, *, resolver: Resolver = resolve) -> Target:
    """Resolve ``endpoint`` to a connect target, or raise EgressBlocked."""
    if policy is None:
        return open_target(endpoint, resolver=resolver)
    pin = policy.pin
    on_pin = pin is not None and (endpoint.scheme, endpoint.host, endpoint.port) == (pin.scheme, pin.host, pin.port)
    if on_pin:
        assert pin is not None
        addresses = resolver(endpoint.host, endpoint.port)
        if not addresses:
            raise EgressBlocked(f"{endpoint.host} resolves to no address")
        moved = [address for address in addresses if address not in pin.addresses]
        if moved:
            raise EgressBlocked(
                f"pinned host {pin.host} now resolves to {', '.join(moved)}, not the pinned "
                f"{', '.join(pin.addresses)}; re-pin it on the profile page")
        for address in addresses:
            if not is_private(address) and not pin.public_host_confirmed:
                raise EgressBlocked(f"pinned host {pin.host} resolves to {address}, which is not private")
        return _target(endpoint, addresses[0])
    if policy.confidentiality == "client":
        where = f"{pin.host}:{pin.port}" if pin else "no pinned host"
        raise EgressBlocked(
            f"a client evaluation may only reach its pinned model host ({where}), not "
            f"{endpoint.host}:{endpoint.port}")
    if policy.allow_public_model and endpoint.kind == "public":
        return open_target(endpoint, resolver=resolver)
    raise EgressBlocked(
        f"{endpoint.host}:{endpoint.port} is not this evaluation's pinned host, and the public model is "
        "not enabled for it")


def open_target(endpoint: Endpoint, *, resolver: Resolver = resolve) -> Target:
    """A target with no evaluation policy: resolve once, still connect to what was resolved."""
    addresses = resolver(endpoint.host, endpoint.port)
    if not addresses:
        raise ModelError("TRANSPORT", f"{endpoint.host} resolves to no address")
    return _target(endpoint, addresses[0])


def _target(endpoint: Endpoint, address: str) -> Target:
    # The socket always goes to the address just resolved and checked; https
    # additionally verifies the certificate against the name.
    tls_name = endpoint.host if endpoint.scheme == "https" else ""
    return Target(endpoint.scheme, address, _host_header(endpoint), endpoint.port, tls_name)


def _host_header(endpoint: Endpoint) -> str:
    default = 443 if endpoint.scheme == "https" else 80
    host = f"[{endpoint.host}]" if ":" in endpoint.host else endpoint.host
    return host if endpoint.port == default else f"{host}:{endpoint.port}"


def bound(policy: EgressPolicy | None, *, resolver: Resolver = resolve) -> Callable[[Endpoint], Target]:
    """``policy`` as the ``egress`` callable a ModelClient takes."""
    return lambda endpoint: check(endpoint, policy, resolver=resolver)
