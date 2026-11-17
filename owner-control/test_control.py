import hashlib
import json
import re
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
from urllib.parse import urlencode
import control


class ControlsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = control.FileStore(Path(self.temp.name) / "vulnerabilities.json")
        self.store.initialize()
        self.origin = "http://localhost:8081"
        self.key = "test-only-key-not-a-deployment-secret"

    def get(self):
        return control.handle("GET", "/controls", {}, b"", self.store, self.key, self.origin)

    def form(self, action="save", enabled=()):
        page = self.get()["body"]
        fields = {key: re.search(f'name="{key}" value="([^"]+)"', page)[1] for key in ("revision", "csrf")}
        return {**fields, "action": action, "enabled": list(enabled)}

    def post(self, form, origin=None, **headers):
        return control.handle("POST", "/controls/save", {
            "origin": self.origin if origin is None else origin,
            "content-type": "application/x-www-form-urlencoded", **headers},
            urlencode(form, doseq=True).encode(), self.store, self.key, self.origin)

    def test_vulnerable_default_and_restart_preserves_fixed(self):
        self.assertTrue(all(self.store.read()[0]["enabled"].values()))
        self.assertEqual(self.post(self.form("fixed"))["statusCode"], 303)
        self.store.initialize()
        self.assertFalse(any(self.store.read()[0]["enabled"].values()))

    def test_all_fixed_individual_and_all_again(self):
        self.assertEqual(self.post(self.form("fixed"))["statusCode"], 303)
        self.assertFalse(any(self.store.read()[0]["enabled"].values()))
        self.assertEqual(self.post(self.form("save", ["XSS-01", "SQL-02"]))["statusCode"], 303)
        state = self.store.read()[0]
        self.assertEqual([code for code, on in state["enabled"].items() if on], ["SQL-02", "XSS-01"])
        self.assertEqual(self.post(self.form("all"))["statusCode"], 303)
        self.assertTrue(all(self.store.read()[0]["enabled"].values()))

    def test_cross_origin_and_missing_origin_rejected(self):
        form = self.form("all")
        self.assertEqual(self.post(form, origin="https://external.example.test")["statusCode"], 403)
        self.assertEqual(self.post(form, origin="")["statusCode"], 403)
        self.assertEqual(self.post(form, **{"sec-fetch-site": "cross-site"})["statusCode"], 403)

    def test_bad_and_expired_csrf(self):
        form = self.form()
        form["csrf"] = "0.forged"
        self.assertEqual(self.post(form)["statusCode"], 403)

    def test_stale_form_rejected(self):
        form = self.form("fixed")
        self.assertEqual(self.post(form)["statusCode"], 303)
        self.assertEqual(self.post(form)["statusCode"], 409)

    def test_duplicate_scalar_unknown_flag_and_unknown_fields_rejected(self):
        for change in ({"action": ["save", "all"]}, {"enabled": ["BACKDOOR"]},
                       {"enabled": ["XSS-01", "XSS-01"]}, {"extra": "x"}):
            self.assertEqual(self.post({**self.form(), **change})["statusCode"], 400)

    def test_missing_and_corrupt_config_never_reinitialized(self):
        self.store.path.write_text("broken")
        self.assertEqual(self.get()["statusCode"], 503)
        self.store.initialize()
        self.assertEqual(self.store.path.read_text(), "broken")
        self.store.path.unlink()
        self.assertEqual(self.get()["statusCode"], 503)
        # Restarting management must not silently recreate an all-vulnerable profile.
        self.store.initialize()
        self.assertFalse(self.store.path.exists())
        self.assertEqual(self.get()["statusCode"], 503)

    def test_existing_configuration_is_adopted_without_overwriting_owner_choice(self):
        other = control.FileStore(Path(self.temp.name) / "imported.json")
        other.path.write_text(json.dumps(control.profile(False)))
        other.initialize()
        self.assertFalse(any(other.read()[0]["enabled"].values()))
        other.path.unlink()
        other.initialize()
        self.assertFalse(other.path.exists())

    def test_oversized_or_symlinked_configuration_rejected(self):
        self.store.path.write_bytes(b" " * (control.MAX_BODY + 1))
        with self.assertRaises(ValueError):
            self.store.read()
        target = Path(self.temp.name) / "other.json"
        target.write_text(json.dumps(control.profile()))
        self.store.path.unlink()
        self.store.path.symlink_to(target)
        self.assertEqual(self.get()["statusCode"], 503)

    def test_strict_config_validation(self):
        value = control.profile()
        for bad in ({**value, "extra": True}, {**value, "version": True},
                    {**value, "enabled": {"XSS-01": True}}, {**value, "revision": "<script>"}):
            with self.assertRaises(ValueError):
                control.validate(bad)
        with self.assertRaises(ValueError):
            control.decode('{"version":1,"version":1}')

    def test_etag_compare_and_swap(self):
        _, etag = self.store.read()
        self.store.write(control.profile(), etag)
        with self.assertRaises(control.Conflict):
            self.store.write(control.profile(), etag)

    def test_headers_no_script_cors_or_frame_permissions(self):
        result = self.get()
        self.assertEqual(result["statusCode"], 200)
        self.assertIn("no-store", result["headers"]["cache-control"])
        self.assertNotIn("access-control-allow-origin", result["headers"])
        self.assertIn("form-action 'self'", result["headers"]["content-security-policy"])
        self.assertNotIn("<script", result["body"])
        self.assertEqual(result["body"].count('type="checkbox"'), 17)

    def test_direct_lambda_requests_fail_before_store_access(self):
        with patch.dict("os.environ", {"CONTROL_ORIGIN_SECRET": "s" * 64}):
            self.assertEqual(control.handler({"headers": {}}, None)["statusCode"], 403)
            self.assertEqual(control.handler({"headers": {"x-northstar-control-origin": "s" * 64}}, None)["statusCode"], 403)

    def test_unsupported_routes_and_methods(self):
        self.assertEqual(control.handle("GET", "/api", {}, b"", self.store, self.key, self.origin)["statusCode"], 404)
        self.assertEqual(control.handle("GET", "/controls/save", {}, b"", self.store, self.key, self.origin)["statusCode"], 405)


if __name__ == "__main__":
    unittest.main()
