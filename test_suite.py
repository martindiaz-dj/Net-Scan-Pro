"""
Suite de Pruebas Automatizadas para NetScan Pro.
Verifica la integridad de cálculos de red, utilidades, resolución OUI y exportación.
"""
import os
import unittest
import ipaddress
from core.utils import (
    is_valid_ipv4,
    is_valid_cidr,
    is_valid_mac,
    clean_mac,
    parse_port_range,
    format_bytes,
    format_speed
)
from core.oui import get_vendor
from modules.subnetting.vlsm_designer import design_vlsm
from modules.report.exporter import export_scan_results, REPORTS_DIR

class TestNetScanPro(unittest.TestCase):

    def test_utils_validation(self):
        self.assertTrue(is_valid_ipv4("192.168.1.1"))
        self.assertTrue(is_valid_ipv4("10.0.0.254"))
        self.assertFalse(is_valid_ipv4("192.168.1.300"))
        self.assertFalse(is_valid_ipv4("not-an-ip"))

        self.assertTrue(is_valid_cidr("192.168.1.0/24"))
        self.assertTrue(is_valid_cidr("10.0.0.0/8"))
        self.assertFalse(is_valid_cidr("192.168.1.0/35"))

        self.assertTrue(is_valid_mac("00:1A:2B:3C:4D:5E"))
        self.assertTrue(is_valid_mac("00-1a-2b-3c-4d-5e"))
        self.assertFalse(is_valid_mac("00:1A:2B:3C:4D:ZZ"))
        self.assertFalse(is_valid_mac("00:1A:2B"))

        self.assertEqual(clean_mac("001a2b3c4d5e"), "00:1A:2B:3C:4D:5E")

    def test_port_parsing(self):
        ports = parse_port_range("80,443,8080")
        self.assertEqual(ports, [80, 443, 8080])

        range_ports = parse_port_range("20-23")
        self.assertEqual(range_ports, [20, 21, 22, 23])

        mixed = parse_port_range("22,80-82,443")
        self.assertEqual(mixed, [22, 80, 81, 82, 443])

    def test_formatters(self):
        self.assertEqual(format_bytes(1024), "1.00 KB")
        self.assertEqual(format_bytes(1048576), "1.00 MB")
        self.assertIn("bps", format_speed(100))

    def test_oui_lookup(self):
        self.assertEqual(get_vendor("00:00:0C:11:22:33"), "Cisco Systems")
        self.assertEqual(get_vendor("00:0C:42:AA:BB:CC"), "MikroTik")
        self.assertEqual(get_vendor("00:15:6D:01:02:03"), "Ubiquiti Networks")
        self.assertEqual(get_vendor("00:03:93:44:55:66"), "Apple Inc.")

    def test_export_reports(self):
        dummy_data = {
            "hosts": [
                {"ip": "192.168.1.1", "mac": "00:11:22:33:44:55", "vendor": "TestVendor", "hostname": "router.local"}
            ]
        }
        json_file = export_scan_results("arp_scan_test", dummy_data, format_type="json")
        self.assertTrue(os.path.exists(json_file))
        if os.path.exists(json_file):
            os.remove(json_file)

if __name__ == "__main__":
    unittest.main()
