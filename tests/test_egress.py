from __future__ import annotations

import pytest
from fake_transport import FakeTransport, delta, sse

from code_analyzer.model.client import Endpoint, ModelClient
from code_analyzer.model.egress import (
    EgressBlocked,
    EgressPolicy,
    Pin,
    bound,
    check,
    is_private,
    pin_endpoint,
)

LOCAL = Endpoint("http://192.168.5.10:11434/v1", "qwen3.8:27b")
BAI = Endpoint("https://api.b.ai/v1", "glm-5.3-flash", kind="public", api_key_env="B_AI_API_KEY")


def resolver(table: dict[str, tuple[str, ...]]):
    return lambda host, port: table[host]


LAN = resolver({"192.168.5.10": ("192.168.5.10",), "api.b.ai": ("203.0.113.7",), "gpu.lab": ("192.168.5.10",)})


@pytest.mark.parametrize(("address", "private"), [
    ("127.0.0.1", True), ("10.1.2.3", True), ("172.20.0.1", True), ("192.168.5.10", True), ("169.254.1.1", True),
    ("::1", True), ("fd00::1", True), ("fe80::1%eth0", True), ("::ffff:192.168.1.1", True),
    ("8.8.8.8", False), ("172.32.0.1", False), ("203.0.113.7", False), ("2001:db8::1", False), ("nonsense", False),
])
def test_private_ranges(address: str, private: bool) -> None:
    assert is_private(address) is private


def test_pin_refuses_a_public_host_unless_a_human_confirmed() -> None:
    public_local = Endpoint("http://gpu.example.com:11434/v1", "qwen")
    lookup = resolver({"gpu.example.com": ("198.51.100.4",)})
    with pytest.raises(EgressBlocked):
        pin_endpoint(public_local, resolver=lookup)
    pin = pin_endpoint(public_local, resolver=lookup, public_host_confirmed=True)
    assert pin.addresses == ("198.51.100.4",) and not pin.private


def test_client_evaluation_reaches_only_its_pin_and_connects_by_validated_ip() -> None:
    policy = EgressPolicy("client", pin_endpoint(LOCAL, resolver=LAN))
    target = check(LOCAL, policy, resolver=LAN)
    assert (target.connect_host, target.host_header, target.port) == ("192.168.5.10", "192.168.5.10:11434", 11434)
    with pytest.raises(EgressBlocked, match="pinned model host"):
        check(BAI, policy, resolver=LAN)


def test_client_evaluation_is_blocked_even_with_the_public_model_configured() -> None:
    with pytest.raises(EgressBlocked):
        EgressPolicy("client", pin_endpoint(LOCAL, resolver=LAN), allow_public_model=True)


def test_a_pinned_name_that_rebinds_to_a_public_address_is_blocked() -> None:
    gpu = Endpoint("http://gpu.lab:11434/v1", "qwen")
    policy = EgressPolicy("client", pin_endpoint(gpu, resolver=LAN))
    rebound = resolver({"gpu.lab": ("192.168.5.10", "203.0.113.9")})
    with pytest.raises(EgressBlocked, match="203.0.113.9"):
        check(gpu, policy, resolver=rebound)


def test_settings_changes_do_not_move_a_pin() -> None:
    policy = EgressPolicy("client", Pin("192.168.5.10", 11434, ("192.168.5.10",), "qwen"))
    moved = Endpoint("http://10.0.0.99:11434/v1", "qwen")  # someone edited settings.toml
    with pytest.raises(EgressBlocked):
        check(moved, policy, resolver=resolver({"10.0.0.99": ("10.0.0.99",)}))


def test_public_evaluation_uses_the_third_party_only_when_a_human_allowed_it() -> None:
    pin = pin_endpoint(LOCAL, resolver=LAN)
    with pytest.raises(EgressBlocked, match="not enabled"):
        check(BAI, EgressPolicy("public", pin), resolver=LAN)
    target = check(BAI, EgressPolicy("public", pin, allow_public_model=True), resolver=LAN)
    assert (target.connect_host, target.tls_name, target.scheme) == ("203.0.113.7", "api.b.ai", "https")
    # A local-kind endpoint on a foreign host is not "the public model".
    stray = Endpoint("http://203.0.113.7:11434/v1", "qwen")
    with pytest.raises(EgressBlocked):
        check(stray, EgressPolicy("public", pin, allow_public_model=True), resolver=resolver({"203.0.113.7": ("203.0.113.7",)}))


def test_the_client_checks_egress_before_opening_anything(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CODE_ANALYZER_NO_MODEL", raising=False)
    monkeypatch.setenv("B_AI_API_KEY", "sk-test-key-000")
    transport = FakeTransport(sse(delta(content="leaked")))
    policy = EgressPolicy("client", pin_endpoint(LOCAL, resolver=LAN))
    with pytest.raises(EgressBlocked):
        ModelClient(BAI, transport=transport, egress=bound(policy, resolver=LAN)).chat(
            [{"role": "user", "content": "client source"}], max_tokens=5)
    assert transport.requests == []


def test_pin_round_trips_through_json() -> None:
    pin = pin_endpoint(LOCAL, resolver=LAN, digest="abc")
    assert Pin.from_json(pin.to_json()) == pin


def test_a_private_pin_does_not_follow_the_name_to_another_private_host() -> None:
    gpu = Endpoint("http://gpu.lab:11434/v1", "qwen")
    policy = EgressPolicy("client", pin_endpoint(gpu, resolver=LAN))
    with pytest.raises(EgressBlocked, match="re-pin"):
        check(gpu, policy, resolver=resolver({"gpu.lab": ("127.0.0.1",)}))


def test_a_confirmed_public_pin_is_bound_to_its_addresses_too() -> None:
    host = Endpoint("http://gpu.example.com:11434/v1", "qwen")
    pin = pin_endpoint(host, resolver=resolver({"gpu.example.com": ("198.51.100.4",)}), public_host_confirmed=True)
    with pytest.raises(EgressBlocked):
        check(host, EgressPolicy("client", pin), resolver=resolver({"gpu.example.com": ("10.9.9.9",)}))


def test_the_scheme_is_part_of_the_pin() -> None:
    policy = EgressPolicy("client", pin_endpoint(LOCAL, resolver=LAN))
    tls = Endpoint("https://192.168.5.10:11434/v1", "qwen3.8:27b")
    with pytest.raises(EgressBlocked):
        check(tls, policy, resolver=LAN)
    assert Pin.from_json({"host": "h", "port": 1, "addresses": ["10.0.0.1"], "model": "m"}).scheme == "http"
