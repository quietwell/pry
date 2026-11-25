"""connect(machine=...) resolves a machine label case-insensitively and by
its learned computer name, so ``DESKTOP-ABC`` reaches the registry key
``desktop-abc`` (or the alias that box registered under)."""

from __future__ import annotations

import pytest

from pry.config import MachineConfig, PryConfig
from pry.session import Session


class _FakeRegistry:
    def __init__(self, by_cn: dict[str, str]):
        self._by_cn = {k.lower(): v for k, v in by_cn.items()}

    def find_alias_by_computer_name(self, name: str) -> str | None:
        return self._by_cn.get(str(name).lower())


def _session() -> Session:
    cfg = PryConfig()
    cfg.machines["desktop-abc"] = MachineConfig(host="10.0.0.5", token="t")
    cfg.machines["lab2"] = MachineConfig(host="10.0.0.9", token="t")
    s = Session(cfg)
    s._registry_provider = lambda: _FakeRegistry({"WIN-LAB2": "lab2"})
    return s


@pytest.mark.parametrize("machine", ["desktop-abc", "DESKTOP-ABC", "Desktop-Abc"])
def test_machine_label_is_case_insensitive(machine):
    label, kind, t = _session()._connect_plan(
        "kernel", machine, None, None, None)
    assert label == "desktop-abc"
    assert kind == "kernel"
    assert t.host == "10.0.0.5"


def test_dotted_view_name_is_case_insensitive():
    label, kind, t = _session()._connect_plan(
        "DESKTOP-ABC.user", None, None, None, None)
    assert (label, kind, t.host) == ("desktop-abc", "user", "10.0.0.5")


def test_computer_name_finds_registered_alias():
    label, _kind, t = _session()._connect_plan(
        "kernel", "win-lab2", None, None, None)
    assert label == "lab2"
    assert t.host == "10.0.0.9"


def test_unknown_machine_still_reports_no_endpoint():
    with pytest.raises(KeyError, match="no endpoint known for nobox.kernel"):
        _session()._connect_plan("kernel", "nobox", None, None, None)
