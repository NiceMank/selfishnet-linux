import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import selfishnet as sn

from unittest.mock import patch
import selfishnet_windows as snw


def test_human_rate():
    assert sn.human_rate(None) == "illimité"
    assert sn.human_rate(500) == "500 kbit/s"
    assert sn.human_rate(1500) == "1.5 Mbit/s"


def test_human_bytes():
    assert sn.human_bytes(512).startswith("512 ")
    assert sn.human_bytes(2048) == "2.0 Ko"
    assert sn.human_bytes(2 * 1024 * 1024) == "2.0 Mo"


def test_sort_key_ip():
    ips = ["192.168.1.10", "192.168.1.2", "invalid"]
    assert sorted(ips, key=sn.sort_key_ip) == [
        "192.168.1.2",
        "192.168.1.10",
        "invalid",
    ]


def test_get_vendor_random_mac():
    sn._OUI_LOADED = True
    sn._OUI_CACHE.clear()
    assert sn.get_vendor("02:aa:bb:cc:dd:ee") == "Privé / Aléatoire (iOS/Android/Win11)"


def test_discovery_snapshot():
    disc = sn.Discovery("eth0", "192.168.1.5", "192.168.1.1", 24)
    now = sn.time.time()
    disc.devices["192.168.1.2"] = {
        "mac": "aa:bb:cc:dd:ee:ff",
        "first": now,
        "last": now,
        "pkts": 3,
        "bytes": 300,
    }
    disc.win["192.168.1.2"].append((now, 300))
    rows = disc.snapshot()
    ips = [row["ip"] for row in rows]
    assert "192.168.1.5" in ips
    assert "192.168.1.1" in ips
    assert "192.168.1.2" in ips


def test_render_table_empty():
    text = sn.render_table([], {}, tty=False)
    assert "aucun appareil local détecté" in text


def test_render_table_pause_state():
    rows = [{
        "ip": "192.168.1.2",
        "mac": "aa:bb:cc:dd:ee:ff",
        "vendor": "Test",
        "kbit": 100,
        "pkts": 4,
        "age": 2,
    }]
    text = sn.render_table(
        rows,
        {"192.168.1.2": {"mode": "pause"}},
        tty=False,
    )
    assert "PAUSE" in text


def test_build_parser_commands():
    parser = sn.build_parser()
    args = parser.parse_args(["--iface", "eth0", "limit", "2", "--rate", "250"])
    assert args.iface == "eth0"
    assert args.target == "2"
    assert args.rate == 250


def test_save_and_load_state(tmp_path, monkeypatch):
    state_file = tmp_path / "state.json"
    monkeypatch.setattr(sn, "STATE_DIR", str(tmp_path))
    monkeypatch.setattr(sn, "STATE_FILE", str(state_file))
    sn.save_state({"192.168.1.2": {"mode": "pause"}})
    assert sn.load_state() == {"192.168.1.2": {"mode": "pause"}}


def test_firewall_rule_name():
    assert snw.firewall_rule_name("192.168.1.42", "In") == "SelfishNet-In-192_168_1_42"


def test_pause_ip_creates_in_and_out_rules():
    with patch("selfishnet_windows.run_netsh", return_value=(0, "ok")) as run:
        assert snw.pause_ip("192.168.1.42")
        assert run.call_count == 4
        commands = [call.args for call in run.call_args_list]
        assert any("dir=in" in command for command in commands)
        assert any("dir=out" in command for command in commands)
        assert all("remoteip=192.168.1.42" in command for command in commands[1::2])


def test_pause_ip_rejects_invalid_address():
    try:
        snw.pause_ip("not-an-ip")
    except ValueError:
        pass
    else:
        raise AssertionError("Une adresse invalide doit etre rejetee")
