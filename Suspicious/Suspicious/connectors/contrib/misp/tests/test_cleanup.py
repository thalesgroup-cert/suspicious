from django.test import SimpleTestCase

from connectors.contrib.misp.cleanup import scan_event

COMPANY = frozenset({"corp.example"})


def _attr(id, type, value, relation=None, **extra):
    return {"id": str(id), "type": type, "value": value, "object_relation": relation, **extra}


def _obj(id, name, *attrs, **extra):
    return {"id": str(id), "name": name, "Attribute": list(attrs), **extra}


class ScanEventTest(SimpleTestCase):
    def _scan(self, *objects, attributes=()):
        return scan_event({"Object": list(objects), "Attribute": list(attributes)}, COMPANY)

    def _by_id(self, findings):
        return {f.id: f for f in findings}

    def test_clean_event_has_no_findings(self):
        findings = self._scan(
            _obj(1, "email", _attr(10, "email-src", "evil@bad.test", "from"),
                 _attr(11, "email-dst", "partner@ext.test", "to")),
            _obj(2, "url", _attr(20, "url", "https://evil.test/x", "url")),
            _obj(3, "domain-ip", _attr(30, "domain", "evil.test", "domain")),
        )
        self.assertEqual(findings, [])

    def test_company_addresses_are_deleted_and_mixed_ones_rewritten(self):
        found = self._by_id(self._scan(_obj(
            1, "email",
            _attr(10, "email-dst", "jane@corp.example", "to"),
            _attr(11, "email-dst", "jane@corp.example, partner@ext.test", "cc"),
            _attr(12, "email-reply-to", "boss@mail.corp.example", "reply-to"),
            _attr(13, "email-src", "bounce@corp.example", "return-path"),
        )))
        self.assertEqual((found["10"].action, found["10"].keep), ("delete", ""))
        self.assertEqual((found["11"].action, found["11"].keep), ("rewrite", "partner@ext.test"))
        self.assertEqual(found["12"].action, "delete")
        self.assertEqual(found["13"].action, "delete")

    def test_recipient_display_names_are_always_flagged(self):
        found = self._by_id(self._scan(_obj(
            1, "email", _attr(10, "email-dst-display-name", "Jane Doe", "to-display-name"))))
        self.assertEqual(found["10"].reason, "recipient display name")

    def test_display_name_follows_a_company_sender_only(self):
        company = self._by_id(self._scan(_obj(
            1, "email", _attr(10, "email-src", "ceo@corp.example", "from"),
            _attr(11, "email-src-display-name", "Jane CEO", "from-display-name"))))
        self.assertEqual(set(company), {"10", "11"})
        external = self._scan(_obj(
            1, "email", _attr(10, "email-src", "evil@bad.test", "from"),
            _attr(11, "email-src-display-name", "Jane CEO", "from-display-name")))
        self.assertEqual(external, [])

    def test_company_url_and_domain_objects_are_removed_whole(self):
        found = self._scan(
            _obj(2, "url", _attr(20, "url", "https://portal.corp.example/a", "url"),
                 _attr(21, "comment", "Artifact from case 1", "comment")),
            _obj(3, "domain-ip", _attr(30, "domain", "mail.corp.example", "domain"),
                 _attr(31, "comment", "Artifact from case 1", "comment")),
        )
        self.assertEqual({(f.kind, f.id) for f in found}, {("object", "2"), ("object", "3")})

    def test_lookalikes_and_embedded_names_are_kept(self):
        self.assertEqual(self._scan(
            _obj(2, "url", _attr(20, "url", "https://corp.example@evil.test/", "url")),
            _obj(3, "domain-ip", _attr(30, "domain", "notcorp.example", "domain")),
            _obj(4, "email", _attr(40, "email-dst", "x@notcorp.example", "to")),
        ), [])

    def test_deleted_items_and_top_level_attributes(self):
        found = self._by_id(self._scan(
            _obj(1, "email", _attr(10, "email-dst", "jane@corp.example", "to", deleted=True)),
            _obj(2, "url", _attr(20, "url", "https://corp.example/", "url"), deleted=True),
            attributes=[_attr(50, "hostname", "vpn.corp.example"),
                        _attr(51, "domain|ip", "corp.example|10.0.0.1")],
        ))
        self.assertEqual(set(found), {"50", "51"})
