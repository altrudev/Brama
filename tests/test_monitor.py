import unittest

from brama_assurance.monitor import analyze, validate_url


UA = """<!doctype html><html><body>
<p>Портал в режимі тестування та наповнення</p>
<a href='/en'>en</a><a href='/'>ua</a>
<time>14/08/2026</time><h2>Оновлення безпеки</h2>
</body></html>""".encode()

EN = """<!doctype html><html><body>
<p>The portal is in testing and filling mode</p>
<a href='/en'>en</a><a href='/'>ua</a>
<time>12/02/2024</time><h2>Українські новини сьогодні</h2><p>English guidance.</p>
</body></html>""".encode()

PRIVACY = """<!doctype html><html><body>
<p>Політика для https://stopfraud.com.ua.</p>
<p>Дані: IP адреса, МАС адреса, дані браузера.</p>
</body></html>""".encode()


class MonitorTests(unittest.TestCase):
    def test_url_policy(self):
        validate_url("https://stopfraud.gov.ua/en")
        with self.assertRaises(ValueError):
            validate_url("http://stopfraud.gov.ua/en")
        with self.assertRaises(ValueError):
            validate_url("https://example.org/")

    def test_expected_findings(self):
        _, findings = analyze({
            "https://stopfraud.gov.ua/": UA,
            "https://stopfraud.gov.ua/en": EN,
            "https://stopfraud.gov.ua/privacy-policy": PRIVACY,
        })
        ids = {f.finding_id for f in findings}
        self.assertIn("PUBLIC_TESTING_MODE", ids)
        self.assertIn("PUBLIC_TESTING_MODE_EN", ids)
        self.assertIn("EN_MIXED_LANGUAGE_SIGNAL", ids)
        self.assertIn("UA_EN_FRESHNESS_DRIFT", ids)
        self.assertIn("PRIVACY_CANONICAL_DOMAIN_DRIFT", ids)
        self.assertIn("PRIVACY_MAC_COLLECTION_DECLARATION", ids)
        self.assertNotIn("UNEXPECTED_RUSSIAN_LOCALE", ids)

    def test_russian_locale_surface_is_flagged(self):
        locale_path = "/" + "r" + "u" + "/"
        page = f"<html><body><a href='{locale_path}'>locale</a></body></html>".encode()
        _, findings = analyze({"https://stopfraud.gov.ua/": page})
        self.assertIn("UNEXPECTED_RUSSIAN_LOCALE", {f.finding_id for f in findings})


if __name__ == "__main__":
    unittest.main()
