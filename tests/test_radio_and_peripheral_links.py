"""Radio and peripheral links: a channel off the device that is not the IP network.

A tree whose only outbound channel is Bluetooth, a serial line, USB, a CAN bus or a Zigbee or mesh radio can send
data off the device, so it is not CLEAN. It is not network egress either, so it has its own kind, `peripheral-link`,
and its detail says REVIEW. Both halves are asserted: each library is reported, and a neighbouring name that is not
one of them (a variable called `serial_number`, a module called `canvas`, the word `usbcore` in a comment) is not.
"""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from entrovouch import no_egress_auditor
from entrovouch.sarif import RULES, to_sarif


def _audit(tmp_path: Path, files: dict[str, str]):
    for name, src in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(src).lstrip(), encoding="utf-8")
    return no_egress_auditor.audit(tmp_path, label="t")


RADIO_IMPORTS = [
    ("bleak", "from bleak import BleakClient\n"),
    ("bleak_scanner", "import bleak.backends.scanner\n"),
    ("pybluez", "import bluetooth\nsock = bluetooth.BluetoothSocket(bluetooth.RFCOMM)\n"),
    ("bluepy", "from bluepy.btle import Peripheral\n"),
    ("pygatt", "import pygatt\n"),
    ("simplepyble", "import simplepyble\n"),
    ("meshtastic", "import meshtastic.serial_interface\n"),
    ("zigpy", "import zigpy.application\n"),
    ("zigpy_znp", "from zigpy_znp.zigbee.application import ControllerApplication\n"),
    ("zigpy_deconz", "import zigpy_deconz\n"),
    ("zigpy_xbee", "import zigpy_xbee.api\n"),
    ("python_can", "import can\nbus = can.Bus(interface='socketcan', channel='can0')\n"),
    ("pyserial", "import serial\nport = serial.Serial('/dev/ttyUSB0', 9600)\n"),
    ("pyserial_tools", "from serial.tools import list_ports\n"),
    ("pyusb", "import usb.core\ndev = usb.core.find(idVendor=0x1234)\n"),
    ("aliased", "import serial as s\n"),
    ("lazy", "def open_port():\n    import serial\n    return serial.Serial('COM3')\n"),
]


@pytest.mark.parametrize("name,src", RADIO_IMPORTS, ids=[n for n, _ in RADIO_IMPORTS])
def test_each_radio_or_peripheral_import_is_reported(tmp_path, name, src):
    rep = _audit(tmp_path, {"a.py": src})
    kinds = [f["kind"] for f in rep.findings]
    assert "peripheral-link" in kinds, (name, rep.findings)
    # a link that is not the IP network is not claimed as network egress
    assert "network-import" not in kinds and "network-call" not in kinds, rep.findings
    # the only channel in the tree is a radio, and that is not CLEAN
    assert rep.verdict == "FINDINGS"
    detail = next(f["detail"] for f in rep.findings if f["kind"] == "peripheral-link")
    assert "REVIEW" in detail and "not the IP network" in detail
    # a library the tool now names is no longer listed as unknown to it
    assert not ({"bleak", "bluetooth", "bluepy", "pygatt", "simplepyble", "meshtastic", "zigpy", "can", "serial",
                 "usb"} & set(rep.unlisted_imports)), rep.unlisted_imports


NEIGHBOURS = [
    ("serial_number_variable", "serial_number = '0042'\nprint(serial_number)\n"),
    ("serial_attribute", "class Device:\n    serial = 'ABC'\n\nDevice().serial\n"),
    ("serialize_module", "import serialize\n"),
    ("canvas_module", "import canvas\nfrom canvas import draw\n"),
    ("cancel_name", "def cancel():\n    can = True\n    return can\n"),
    ("usbcore_in_comment", "# the usbcore kernel module binds the device\nx = 1\n"),
    ("usbcore_in_string", "DRIVER = 'usbcore'\n"),
    ("bleach_module", "import bleach\n"),
    ("bare_prefix", "import zigpy_\n"),
    ("serial_from_own_package", "from mypkg import serial\n"),
    ("bluetooth_in_text", "doc = 'pair over bluetooth, then import serial data'\n"),
]


@pytest.mark.parametrize("name,src", NEIGHBOURS, ids=[n for n, _ in NEIGHBOURS])
def test_a_neighbouring_name_is_not_a_radio(tmp_path, name, src):
    rep = _audit(tmp_path, {"a.py": src})
    assert "peripheral-link" not in {f["kind"] for f in rep.findings}, (name, rep.findings)


def test_a_module_the_tree_holds_shadows_the_installed_library(tmp_path):
    rep = _audit(tmp_path, {"serial.py": "def Serial(*a):\n    return None\n",
                            "app.py": "import serial\nserial.Serial()\n"})
    assert "peripheral-link" not in {f["kind"] for f in rep.findings}
    assert "serial" in rep.shadowed_imports


def test_the_kind_is_declared_for_sarif(tmp_path):
    rep = _audit(tmp_path, {"a.py": "import bleak\n"})
    from dataclasses import asdict
    log = to_sarif(asdict(rep))
    rules = {r["id"] for r in log["runs"][0]["tool"]["driver"]["rules"]}
    assert "peripheral-link" in RULES and "peripheral-link" in rules
    assert {r["ruleId"] for r in log["runs"][0]["results"]} == {"peripheral-link"}


def test_the_scope_statement_names_the_kind(tmp_path):
    rep = _audit(tmp_path, {"a.py": "x = 1\n"})
    assert rep.verdict == "CLEAN"
    assert "`peripheral-link`" in rep.scope_statement and "not the IP network" in rep.scope_statement


def test_the_published_list_holds_every_named_library():
    want = {"bleak", "bluetooth", "bluepy", "pygatt", "simplepyble", "meshtastic", "zigpy", "can", "serial", "usb"}
    assert want <= no_egress_auditor.PERIPHERAL_LINK_MODULES
    assert not (want & no_egress_auditor.FORBIDDEN_IMPORT_MODULES), "a radio is not listed as network egress"
    assert no_egress_auditor._classify_module("zigpy_znp") == "peripheral"
    assert no_egress_auditor._classify_module("zigpy_") is None
