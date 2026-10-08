import sys
import types
import unittest
from unittest.mock import Mock, patch

from services.apk_svc import analyze_apk_bytes


class ApkServiceTests(unittest.TestCase):
    def test_analyze_apk_bytes_passes_uploaded_bytes_as_raw(self):
        apk = Mock()
        apk.get_permissions.return_value = [
            "android.permission.INTERNET",
            "android.permission.SEND_SMS",
        ]
        apk.get_activities.return_value = ["com.example.MainActivity"]
        apk.get_services.return_value = []
        apk.get_receivers.return_value = []
        apk.get_certificates.return_value = []

        analysis = Mock()
        analysis.get_strings.return_value = ["https://api.example.test/path"]
        analyze_apk = Mock(return_value=(apk, [], analysis))

        androguard = types.ModuleType("androguard")
        misc = types.ModuleType("androguard.misc")
        misc.AnalyzeAPK = analyze_apk
        androguard.misc = misc

        apk_bytes = b"test apk bytes"
        with patch.dict(sys.modules, {"androguard": androguard, "androguard.misc": misc}):
            result = analyze_apk_bytes(apk_bytes, "sample.apk")

        analyze_apk.assert_called_once_with(apk_bytes, raw=True)
        self.assertEqual(result["filename"], "sample.apk")
        self.assertIn("android.permission.SEND_SMS", result["dangerousPermissions"])
        self.assertEqual(result["networkUrls"], ["https://api.example.test/path"])
        self.assertGreater(result["riskScore"], 0)


if __name__ == "__main__":
    unittest.main()
