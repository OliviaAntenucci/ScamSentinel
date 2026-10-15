"""S4: sandbox container hardening and browser policy (SECURITY.md T4).

The compose-level checks run now; browser-policy checks are enabled in M5.
"""

from pathlib import Path

import pytest
import yaml

COMPOSE = yaml.safe_load(
    (Path(__file__).resolve().parents[2] / "docker-compose.yml").read_text(encoding="utf-8")
)
SERVICES = COMPOSE["services"]
NETWORKS = COMPOSE["networks"]


@pytest.mark.parametrize("name", ["api", "sandbox", "ocr"])
def test_service_hardening(name):
    svc = SERVICES[name]
    assert svc["read_only"] is True
    assert svc["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in svc["security_opt"]


def test_api_published_on_loopback_only():
    assert SERVICES["api"]["ports"] == ["127.0.0.1:8000:8000"]


@pytest.mark.parametrize("name", ["sandbox", "ocr", "egress-proxy"])
def test_workers_publish_no_ports(name):
    assert "ports" not in SERVICES[name]


def test_sandbox_has_no_direct_internet():
    # Only internal networks; internet access goes through egress-proxy.
    for net in SERVICES["sandbox"]["networks"]:
        assert NETWORKS[net].get("internal") is True


def test_ocr_has_no_internet():
    for net in SERVICES["ocr"]["networks"]:
        assert NETWORKS[net].get("internal") is True


@pytest.mark.parametrize("name", ["sandbox", "ocr"])
def test_workers_get_no_secrets(name):
    svc = SERVICES[name]
    assert "env_file" not in svc
    assert "ANTHROPIC_API_KEY" not in svc.get("environment", {})


@pytest.mark.skip(reason="M5: detonator not implemented yet")
def test_downloads_and_popups_blocked():
    raise NotImplementedError


@pytest.mark.skip(reason="M5: detonator not implemented yet")
def test_navigation_timeout_enforced():
    raise NotImplementedError
