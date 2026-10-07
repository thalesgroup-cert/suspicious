import zlib

from django.test import SimpleTestCase

from connectors.contrib.thehive.campaign_iocs import extract_iocs
from connectors.contrib.thehive.campaign_material import Attachment, MailMaterial, select_attachments

HEADERS = (
    "Message-ID: <abc@m365-hr-update1.example>\r\n"
    'From: "HR Payroll Department" <hr-payroll1@m365-hr-update1.example>\r\n'
    "Reply-To: payroll-help@payroll-portal-verify.example\r\n"
    "Return-Path: <bounce@mailer.example>\r\n"
    "Subject: =?utf-8?q?Action_required=3A_verify?=\r\n"
    "Received: from mx1.example (mx1.example [185.11.21.31]) by mx.meridian.example; Wed, 7 Oct 2026\r\n"
    "Received: from internal (internal [10.0.0.5]) by mx.meridian.example; Wed, 7 Oct 2026\r\n"
    "X-Originating-IP: [91.20.30.40]\r\n"
    "Received-SPF: fail\r\n"
    "Authentication-Results: mx.meridian.example; spf=fail; dkim=none; dmarc=fail\r\n"
)

def NEVER(domain):
    return False



def _pdf(text: str, compress=False) -> bytes:
    body = f"BT ({text}) Tj ET".encode()
    return b"%PDF-1.4\nstream\n" + (zlib.compress(body) if compress else body) + b"\nendstream\n%%EOF"


def _iocs(material=None, attachments=(), own=(), allowed=NEVER):
    material = material or MailMaterial(headers=HEADERS)
    kept, skipped = select_attachments(list(attachments))
    return extract_iocs(material, kept, skipped, own_domains=own, is_allowed=allowed)


class UrlTest(SimpleTestCase):
    def test_urls_come_from_html_text_and_attachments(self):
        m = MailMaterial(
            headers=HEADERS,
            html="<a href='https://html.example/login?u=1'>x</a>",
            text="visit http://185.11.21.31/payroll/login.php now",
            attachments=[],
        )
        atts = [
            Attachment("form.html", b"<form action='https://form.example/collect'>"),
            Attachment("notice.pdf", _pdf("see https://pdf.example/doc1")),
            Attachment("packed.pdf", _pdf("see https://flate.example/doc2", compress=True)),
        ]
        urls = _iocs(m, atts).urls
        for expected in ("https://html.example/login?u=1", "http://185.11.21.31/payroll/login.php",
                         "https://form.example/collect", "https://pdf.example/doc1", "https://flate.example/doc2"):
            self.assertIn(expected, urls)

    def test_defanged_urls_are_refanged(self):
        m = MailMaterial(headers=HEADERS, text="go to hxxps://evil[.]example/pay now")
        self.assertIn("https://evil.example/pay", _iocs(m).urls)

    def test_urls_are_unique_and_capped(self):
        text = " ".join(f"https://u{i}.example/p" for i in range(300)) + " https://u1.example/p"
        urls = _iocs(MailMaterial(headers=HEADERS, text=text)).urls
        self.assertEqual(len(urls), len(set(urls)))
        self.assertLessEqual(len(urls), 100)


class BodySourceTest(SimpleTestCase):
    EML = (b"From: a@evil.example\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
           b"Alternative link: http://185.11.21.31/payroll/login.php\n\nHR Payroll Department\n")

    def test_bodies_are_read_from_the_raw_mail_not_the_flattened_text(self):
        # the stored .txt loses line breaks, which glues the next word onto a URL
        m = MailMaterial(headers=HEADERS, eml=self.EML,
                         text="Alternative link: http://185.11.21.31/payroll/login.phpHR Payroll Department")
        urls = _iocs(m).urls
        self.assertIn("http://185.11.21.31/payroll/login.php", urls)
        self.assertNotIn("http://185.11.21.31/payroll/login.phpHR", urls)

    def test_stored_parts_are_used_when_there_is_no_raw_mail(self):
        m = MailMaterial(headers=HEADERS, text="go to https://only-text.example/a")
        self.assertIn("https://only-text.example/a", _iocs(m).urls)


class DomainAndIpTest(SimpleTestCase):
    def test_domains_come_from_urls_and_sender_addresses(self):
        m = MailMaterial(headers=HEADERS, text="https://landing.example/x")
        d = _iocs(m).domains
        for expected in ("landing.example", "m365-hr-update1.example",
                         "payroll-portal-verify.example", "mailer.example"):
            self.assertIn(expected, d)

    def test_ip_hosts_are_ips_not_domains(self):
        m = MailMaterial(headers=HEADERS, text="http://185.11.21.31/a")
        iocs = _iocs(m)
        self.assertIn("185.11.21.31", iocs.ips)
        self.assertNotIn("185.11.21.31", iocs.domains)

    def test_public_header_ips_kept_private_dropped(self):
        ips = _iocs().ips
        self.assertIn("185.11.21.31", ips)
        self.assertIn("91.20.30.40", ips)
        self.assertNotIn("10.0.0.5", ips)

    def test_own_and_allow_listed_domains_are_ignored(self):
        m = MailMaterial(
            headers=HEADERS,
            text="https://intranet.meridian.example/wiki https://good.example/x https://evil.example/y",
        )
        iocs = _iocs(m, own=("meridian.example",), allowed=lambda d: d == "good.example")
        self.assertEqual(iocs.urls, ["https://evil.example/y"])
        self.assertNotIn("intranet.meridian.example", iocs.domains)
        self.assertNotIn("good.example", iocs.domains)


class HeaderIocTest(SimpleTestCase):
    def test_addresses_names_ids_and_subject(self):
        iocs = _iocs()
        self.assertEqual(iocs.emails[0], "hr-payroll1@m365-hr-update1.example")
        for expected in ("payroll-help@payroll-portal-verify.example", "bounce@mailer.example"):
            self.assertIn(expected, iocs.emails)
        self.assertEqual(iocs.display_names, ["HR Payroll Department"])
        self.assertEqual(iocs.message_ids, ["<abc@m365-hr-update1.example>"])
        self.assertEqual(iocs.subjects, ["Action required: verify"])

    def test_failed_authentication_is_recorded(self):
        self.assertEqual(sorted(_iocs().auth_failures), ["dmarc=fail", "spf=fail"])


class AttachmentIocTest(SimpleTestCase):
    def test_hashes_and_names_cover_kept_and_oversize_but_not_junk(self):
        big = Attachment("huge.bin", b"\x01" * (10 * 1024 * 1024 + 1))
        atts = [Attachment("a.pdf", b"%PDF-1"), Attachment("empty.dat", b""), big]
        iocs = _iocs(attachments=atts)
        self.assertEqual(sorted(iocs.filenames), ["a.pdf", "huge.bin"])
        self.assertEqual(len(iocs.hashes), 2)
