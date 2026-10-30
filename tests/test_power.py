"""Energy is reported as measured only when a supply rail was measured.

Every receipt says whether its joules were measured or estimated, and the
README promises an estimate is never presented as a measurement. A power
sensor that measures one part of a machine breaks that promise as surely as an
estimate would: on a laptop, integrating a sleeping GPU's sensor printed
"0.00 J total, measured" for a run that kept four cores busy for 104 seconds.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from voidai.telemetry import power


def _sensor(hwmon: Path, index: int, driver: str, microwatts: str | None) -> Path:
    device = hwmon / f"hwmon{index}"
    device.mkdir()
    (device / "name").write_text(f"{driver}\n")
    if microwatts is not None:
        (device / "power1_input").write_text(f"{microwatts}\n")
    return device


@pytest.fixture
def hwmon(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """An empty sysfs with no RAPL, so hwmon is the only candidate."""
    root = tmp_path / "hwmon"
    root.mkdir()
    monkeypatch.setattr(power, "_HWMON", root)
    monkeypatch.setattr(power, "_POWERCAP", tmp_path / "no-powercap")
    monkeypatch.delenv("VOIDAI_FORCE_ESTIMATE", raising=False)
    return root


class TestSupplyRails:
    def test_a_shunt_on_the_supply_rail_is_measured(self, hwmon: Path) -> None:
        shunt = _sensor(hwmon, 0, "ina219", "2700000")
        assert power.HwmonSource.available() == [shunt / "power1_input"]
        source = power.best_available_source()
        assert isinstance(source, power.HwmonSource)
        assert source.fidelity == power.Fidelity.MEASURED

    def test_a_laptop_component_sensor_is_an_estimate(self, hwmon: Path) -> None:
        """A GPU's sensor reads zero asleep and only the GPU awake.

        Neither is the machine's energy, so neither may be called measured.
        """
        _sensor(hwmon, 1, "amdgpu", "0")
        _sensor(hwmon, 2, "nouveau", "15000000")
        source = power.best_available_source()
        assert isinstance(source, power.EstimatedSource)
        assert source.fidelity == power.Fidelity.ESTIMATED

    def test_a_rail_reading_zero_is_not_used(self, hwmon: Path) -> None:
        _sensor(hwmon, 0, "ina219", "0")
        assert power.HwmonSource.available() == []

    def test_a_sensor_without_a_power_reading_is_skipped(self, hwmon: Path) -> None:
        _sensor(hwmon, 0, "k10temp", None)
        assert power.HwmonSource.available() == []
