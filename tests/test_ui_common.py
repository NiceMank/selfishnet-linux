import csv
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import selfishnet_ui_common as ui


SAMPLE_DEVICES = [
    {"ip": "192.168.1.10", "mac": "aa:bb:cc:dd:ee:01", "vendor": "Intel", "alias": "Mon PC", "kbit": 450.0, "up_kbit": 50.0, "down_kbit": 400.0, "pkts": 120, "age": 1.0, "is_safe": True},
    {"ip": "192.168.1.2", "mac": "00:07:cb:00:00:01", "vendor": "Freebox", "alias": "", "kbit": 0.0, "up_kbit": 0.0, "down_kbit": 0.0, "pkts": 5, "age": 10.0, "is_safe": True},
    {"ip": "192.168.1.25", "mac": "11:22:33:44:55:66", "vendor": "Samsung", "alias": "TV Salon", "kbit": 3200.0, "up_kbit": 200.0, "down_kbit": 3000.0, "pkts": 900, "age": 0.5, "is_safe": False},
    {"ip": "192.168.1.30", "mac": "22:33:44:55:66:77", "vendor": "Apple", "alias": "", "kbit": 0.2, "up_kbit": 0.1, "down_kbit": 0.1, "pkts": 12, "age": 40.0, "is_safe": False},
]

SAMPLE_TARGETS = {
    "192.168.1.25": {"mode": "limit", "rate": 500},
    "192.168.1.30": {"mode": "pause", "rate": None},
}


def test_filter_devices_modes_and_search():
    assert len(ui.filter_devices(SAMPLE_DEVICES, SAMPLE_TARGETS, mode_filter="all")) == 4
    active = ui.filter_devices(SAMPLE_DEVICES, SAMPLE_TARGETS, mode_filter="active")
    assert [d["ip"] for d in active] == ["192.168.1.10", "192.168.1.25"]

    restricted = ui.filter_devices(SAMPLE_DEVICES, SAMPLE_TARGETS, mode_filter="restricted")
    assert [d["ip"] for d in restricted] == ["192.168.1.25", "192.168.1.30"]

    safe = ui.filter_devices(SAMPLE_DEVICES, SAMPLE_TARGETS, mode_filter="safe")
    assert [d["ip"] for d in safe] == ["192.168.1.10", "192.168.1.2"]

    search_alias = ui.filter_devices(SAMPLE_DEVICES, SAMPLE_TARGETS, query="tv salon")
    assert [d["ip"] for d in search_alias] == ["192.168.1.25"]


def test_sort_devices_by_ip_rate_and_state():
    by_ip = ui.sort_devices(SAMPLE_DEVICES, SAMPLE_TARGETS, sort_col="ip", reverse=False)
    assert [d["ip"] for d in by_ip] == ["192.168.1.2", "192.168.1.10", "192.168.1.25", "192.168.1.30"]

    by_rate = ui.sort_devices(SAMPLE_DEVICES, SAMPLE_TARGETS, sort_col="rate", reverse=True)
    assert by_rate[0]["ip"] == "192.168.1.25"

    by_state = ui.sort_devices(SAMPLE_DEVICES, SAMPLE_TARGETS, sort_col="state", reverse=True)
    assert by_state[0]["ip"] == "192.168.1.30"  # pause > limit > safe > normal


def test_compute_kpis():
    kpis = ui.compute_kpis(SAMPLE_DEVICES, SAMPLE_TARGETS, total_kbit=3650.2)
    assert kpis["total_devices"] == 4
    assert kpis["restricted"] == 2
    assert kpis["paused"] == 1
    assert kpis["limited"] == 1
    assert kpis["safe"] == 2
    assert kpis["total_kbit"] == 3650.2


def test_export_devices_csv_and_json(tmp_path):
    csv_path = str(tmp_path / "devices.csv")
    count_csv = ui.export_devices_file(SAMPLE_DEVICES, SAMPLE_TARGETS, csv_path)
    assert count_csv == 4
    with open(csv_path, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 4
    tv = next(r for r in rows if r["ip"] == "192.168.1.25")
    assert tv["alias"] == "TV Salon"
    assert tv["mode"] == "limit"
    assert tv["limit_kbit"] == "500"

    json_path = str(tmp_path / "devices.json")
    count_json = ui.export_devices_file(SAMPLE_DEVICES, SAMPLE_TARGETS, json_path)
    assert count_json == 4
    with open(json_path, encoding="utf-8") as f:
        data = json.load(f)
    assert len(data) == 4
    assert any(d["ip"] == "192.168.1.30" and d["mode"] == "pause" for d in data)
