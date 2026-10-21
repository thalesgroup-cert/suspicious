# Allow-list launch, MISP and scoring rules Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop launching Cortex jobs for allow-listed IPs, keep campaign and allow-listed indicators out of MISP, and let a strict majority of safe plus allow-listed analyzer weight override a lone Dangerous signal.

**Architecture:** A small `settings/allow_lists.py` owns IP normalisation and the "deny / Watcher-monitored / campaign beat the allow list" check; the email path (`ArtifactJobLauncherService`) and web path (`CaseHandler`) both call it. MISP gets three more preloaded frozensets (campaign domains merged into the company-domain set, allow-listed IPs, allow-listed hashes) so `update_misp` keeps a constant query count. Scoring adds a pure `Vote` dataclass and a post-step inside `score_case`; `collect_votes(case, ai)` builds one vote per analyzer from the case's `AnalyzerReport` rows plus the AI signal.

**Tech Stack:** Django / MariaDB, `ipaddress`, `pymisp`, Django `TestCase` / `SimpleTestCase`. Tests: `ww test backend <dotted labels>` from `/home/forensics/suspicious/wt-allowlist`.

**Spec:** `docs/plans/2026-10-20-allowlist-launch-misp-scoring-design.md` (executors read it too).

## Global Constraints

- Paths are relative to `Suspicious/Suspicious/` unless they start with `docs/`, `mkdocs.yml` or `CHANGELOG.md`. Work only in worktree `/home/forensics/suspicious/wt-allowlist` (branch `fix/allowlist-launch-misp-scoring`). No migrations (the `IP` mixin adds no field).
- User decisions: weighted vote; **strict majority** (exactly half does not override); exact-domain matching at launch (no subdomain widening); per-IOC MISP skips (never a whole-case skip); campaign domains stay Dangerous and are never pushed; deny list, Watcher monitored and campaign domains are never overridden by an allow-list entry.
- Allow-listed artifact level is exactly `SAFE-ALLOW_LISTED`; new rule name exactly `allow-list-majority`.
- `score_case` keeps its positional signature; the new input is the keyword `votes=()`. Without a whitelisted vote the verdict must equal today's. IOC-road (`finalise_ioc_group`, `observable_engine`) is untouched.
- Conventional Commits, each ending with `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`. No emojis; comments only where they carry information.

## Review Focus

1. Lookalike and subdomain hosts at launch (`allowlisted.test.evil.tld`, `evil-allowlisted.test`, `sub.allowlisted.test`) must still launch; only the exact domain is skipped (Task 1).
2. A domain on the allow list **and** the deny / Watcher-monitored / campaign list is never silenced: deny stays `dangerous`, campaign still launches, the web URL path does not return an allow-listed case (Task 1); `score_case` with `deny_listed=True` ignores whitelisted votes (Task 3).
3. An analyzer that flags one target Dangerous and is whitelisted on another votes **dissent**; reruns do not leave a stale dissenter (Task 4).
4. Failed, pending, `info`, low-confidence reports and zero-weight analyzers are not votes; total weight 0 means no override; float drift on exactly-half weights (`0.1 + 0.2` vs `0.3`) must not flip the strict-majority test (Tasks 3, 4).
5. The majority verdict is still raised by an embedded Dangerous IOC (`mail_band_escalation`); a MISP URL on an allow-listed host follows the domain subdomain rule (`https://good.test.evil.tld/` pushed, `https://cdn.good.test/` skipped) (Tasks 3, 2).

---

### Task 1: Shared allow-list helper and IP launch skip (email and web)

**Files:**
- Create: `settings/allow_lists.py`, `settings/tests/test_allow_lists.py`, `case_handler/tests/test_launch_allow_list.py`, `docs/operations/allow-lists.md`
- Modify: `ip_process/models.py`, `score_process/scoring/cortex_analyzers/allow_list.py` (IP branch), `mail_feeder/job_handler/artifacts/artifacts.py` (`_process_ip_artifact`, `_is_domain_allow_listed`), `case_handler/case_utils/case_handler.py` (`_handle_url_form`, `_handle_other_form`), `mail_feeder/job_handler/artifacts/tests.py`, `mkdocs.yml` (Operations nav), `docs/components/backend/settings.md`

**Interfaces:**
- Consumes: `settings.models.{AllowListIp, DenyListDomain, WatcherMonitoredDomain, CampaignDomainAllowList}`; `common.model_mixins.AllowListableMixin.update_allow_listed()` (sets score 0, confidence 100, level `SAFE-ALLOW_LISTED`).
- Produces: `settings.allow_lists.normalise_ip(address) -> str`, `is_ip_allow_listed(address) -> bool`, `overrides_allow_list(domain) -> bool` (True for a Domain row that is deny-listed, Watcher-monitored or a campaign domain; False for `None`). Task 2 imports `normalise_ip`.

- [ ] **Step 1: Failing helper tests** — `settings/tests/test_allow_lists.py`

```python
from django.contrib.auth import get_user_model
from django.test import TestCase

from domain_process.models import Domain
from ip_process.models import IP
from settings.allow_lists import is_ip_allow_listed, normalise_ip, overrides_allow_list
from settings.models import AllowListIp, CampaignDomainAllowList, DenyListDomain, WatcherMonitoredDomain


class AllowListHelpersTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="al_u", password="x")

    def test_normalise_ip(self):
        self.assertEqual(normalise_ip(" 2606:4700:4700:0:0:0:0:1111 "), "2606:4700:4700::1111")
        self.assertEqual((normalise_ip(" garbage "), normalise_ip(None)), ("garbage", ""))

    def test_ip_match_ignores_spelling(self):
        AllowListIp.objects.create(ip=IP.objects.create(address="2606:4700:4700::1111"), user=self.user)
        self.assertTrue(is_ip_allow_listed("2606:4700:4700:0:0:0:0:1111"))
        self.assertFalse(is_ip_allow_listed("8.8.4.4"))

    def test_overrides_allow_list(self):
        self.assertFalse(overrides_allow_list(None))
        self.assertFalse(overrides_allow_list(Domain.objects.create(value="plain.test")))
        deny, mon, camp = (Domain.objects.create(value=v) for v in ("deny.test", "mon.test", "camp.test"))
        DenyListDomain.objects.create(domain=deny, user=self.user)
        WatcherMonitoredDomain.objects.create(domain=mon)
        CampaignDomainAllowList.objects.create(domain=camp, user=self.user)
        for d in (deny, mon, camp):
            self.assertTrue(overrides_allow_list(d), d.value)
```

- [ ] **Step 2: Run, expect FAIL** — `ww test backend settings.tests.test_allow_lists` (no module `settings.allow_lists`).

- [ ] **Step 3: Implement** — `settings/allow_lists.py`

```python
"""Allow-list lookups shared by job launch, scoring and the MISP connector."""
import ipaddress

from settings.models import AllowListIp, CampaignDomainAllowList, DenyListDomain, WatcherMonitoredDomain


def normalise_ip(address) -> str:
    """Compressed form, so '0:0:0:0:0:0:0:1' and '::1' compare equal.
    Unparseable input comes back stripped (it simply will not match)."""
    value = (address or "").strip()
    try:
        return ipaddress.ip_address(value).compressed
    except ValueError:
        return value


def is_ip_allow_listed(address) -> bool:
    return AllowListIp.objects.filter(ip__address=normalise_ip(address)).exists()


def overrides_allow_list(domain) -> bool:
    """Deny-listed, Watcher-monitored and campaign domains are never treated as allow-listed."""
    if domain is None:
        return False
    return (DenyListDomain.objects.filter(domain=domain).exists()
            or WatcherMonitoredDomain.objects.filter(domain=domain).exists()
            or CampaignDomainAllowList.objects.filter(domain=domain).exists())
```

`ip_process/models.py`: `from common.model_mixins import AllowListableMixin`, `class IP(AllowListableMixin, models.Model):` (as `URL` and `Hash` do). `score_process/scoring/cortex_analyzers/allow_list.py`: add `from settings.allow_lists import is_ip_allow_listed`, drop `import ipaddress`, and make the IP branch `elif data_type == "ip": if is_ip_allow_listed(data): result.IpAllowList = "Safe IPW triggered"`.

- [ ] **Step 4: Run** — `ww test backend settings.tests.test_allow_lists score_process.tests.test_allow_list settings.tests.test_allowlist_ip` → PASS (existing IP-branch tests prove the refactor).

- [ ] **Step 5: Failing launch tests, email path.** In `mail_feeder/job_handler/artifacts/tests.py` keep the mocked class DB-free by patching the two new lookups in `ArtifactJobLauncherServiceTests.setUp`, add one mocked IP test, then append a DB class (the file already does `import django.test`).

```python
# ArtifactJobLauncherServiceTests.setUp, after self.service = ...
        for name in ("is_ip_allow_listed", "overrides_allow_list"):
            p = patch(f"mail_feeder.job_handler.artifacts.artifacts.{name}", return_value=False)
            p.start()
            self.addCleanup(p.stop)

    def test_ip_allow_listed_skips_cortex(self):
        ip = MagicMock(address="1.1.1.1")
        with patch("mail_feeder.job_handler.artifacts.artifacts.is_ip_allow_listed", return_value=True):
            service = self.service.process_artifacts([self._artifact("IP", artifactIsIp=MagicMock(ip=ip))])
        self.assertEqual(service.pending_dispatch_intents, [])
        ip.update_allow_listed.assert_called_once_with()
```

```python
class AllowListLaunchDbTests(django.test.TestCase):
    def setUp(self):
        from django.contrib.auth import get_user_model
        self.user = get_user_model().objects.create_user(username="al_launch", password="x")

    def _launch(self, kind, **kw):
        return ArtifactJobLauncherService().process_artifacts(
            [MagicMock(artifact_type=kind, **kw)]).pending_dispatch_intents

    def _domain(self, value):
        from domain_process.models import Domain
        d = Domain.objects.get_or_create(value=value)[0]
        return d, self._launch("Domain", artifactIsDomain=MagicMock(domain=d))

    def test_allow_listed_ip_is_skipped_in_any_spelling_and_others_launch(self):
        from ip_process.models import IP
        from settings.models import AllowListIp
        AllowListIp.objects.create(ip=IP.objects.create(address="2606:4700:4700::1111"), user=self.user)
        listed = IP.objects.create(address="2606:4700:4700:0000:0000:0000:0000:1111")
        self.assertEqual(self._launch("IP", artifactIsIp=MagicMock(ip=listed)), [])
        listed.refresh_from_db()
        self.assertEqual(listed.ioc_level, "SAFE-ALLOW_LISTED")
        other = IP.objects.create(address="8.8.4.4")
        self.assertEqual(self._launch("IP", artifactIsIp=MagicMock(ip=other)), [(other, "ip")])

    def test_only_the_exact_allow_listed_domain_is_skipped(self):
        from domain_process.models import Domain
        from settings.models import AllowListDomain
        AllowListDomain.objects.create(domain=Domain.objects.create(value="allowlisted.test"), user=self.user)
        self.assertEqual(self._domain("allowlisted.test")[1], [])
        for lookalike in ("sub.allowlisted.test", "allowlisted.test.evil.tld", "evil-allowlisted.test"):
            d, intents = self._domain(lookalike)
            self.assertEqual(intents, [(d, "domain")], lookalike)

    def test_deny_beats_allow_and_campaign_still_launches(self):
        from domain_process.models import Domain
        from settings.models import AllowListDomain, CampaignDomainAllowList, DenyListDomain
        both = Domain.objects.create(value="both.test")
        sim = Domain.objects.create(value="sim.test")
        for d in (both, sim):
            AllowListDomain.objects.create(domain=d, user=self.user)
        DenyListDomain.objects.create(domain=both, user=self.user)
        CampaignDomainAllowList.objects.create(domain=sim, user=self.user)
        self.assertEqual(self._domain("both.test")[1], [])
        both.refresh_from_db()
        self.assertEqual(both.ioc_level, "dangerous")
        self.assertEqual(self._domain("sim.test")[1], [(sim, "domain")])
```

- [ ] **Step 6: Run, expect FAIL** — `ww test backend mail_feeder.job_handler.artifacts.tests` (patch targets missing, then IP / precedence failures).

- [ ] **Step 7: Implement, email path** — `artifacts.py`: `from settings.allow_lists import is_ip_allow_listed, overrides_allow_list`.

```python
    def _process_ip_artifact(self, artifact):
        if artifact.artifactIsIp:
            ip_obj = artifact.artifactIsIp.ip
            if is_ip_allow_listed(ip_obj.address):
                fetch_mail_logger.info(f"IP {ip_obj.address} is allow-listed")
                ip_obj.update_allow_listed()
                return
            fetch_mail_logger.info(f"Processing IP: {ip_obj.address}")
            self._launch_cortex_jobs(ip_obj, "ip")
```

In `_is_domain_allow_listed` add the guard to the condition so the callers' existing `not allow and not deny` chain then reaches the deny handler (marks `dangerous`, skips) or falls through for campaign (launches):

```python
        if domain_obj and (
            AllowListDomain.objects.filter(domain=domain_obj).exists()
            or WatcherLegitDomain.objects.filter(domain=domain_obj).exists()
        ) and not overrides_allow_list(domain_obj):
```

- [ ] **Step 8: Web path, failing then green.** `case_handler/tests/test_launch_allow_list.py`:

```python
from unittest.mock import MagicMock

from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase

from case_handler.case_utils.case_handler import CaseHandler
from domain_process.models import Domain
from ip_process.models import IP
from settings.models import AllowListDomain, AllowListIp, CampaignDomainAllowList, DenyListDomain


class WebLaunchAllowListTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="web_al", password="x")

    def _handler(self, **filled):
        request = RequestFactory().post("/api/submit")
        request.user = self.user

        def form(key):
            f = MagicMock(**{"is_valid.return_value": key in filled})
            f.cleaned_data = {key: filled[key]} if key in filled else {}
            return f
        return CaseHandler(request, form("file"), form("url"), form("other"))

    def test_allow_listed_ip_gets_reason_and_no_job_unlisted_ip_launches(self):
        AllowListIp.objects.create(ip=IP.objects.create(address="2606:4700:4700::1111"), user=self.user)
        h = self._handler(other="2606:4700:4700:0:0:0:0:1111")
        res = h.validate_forms()
        self.assertTrue(res["allow_listed"])
        self.assertIn("allow-listed", res["allow_reason"])
        self.assertEqual(res["ip_instance"].ioc_level, "SAFE-ALLOW_LISTED")
        self.assertEqual(h.pending_dispatch_intents, [])
        h = self._handler(other="8.8.4.4")
        res = h.validate_forms()
        self.assertFalse(res["allow_listed"])
        self.assertEqual(h.pending_dispatch_intents, [(res["ip_instance"], "ip")])

    def test_allow_listed_url_domain_is_skipped_unless_deny_or_campaign(self):
        for value, model in (("allowed.test", None), ("denied.test", DenyListDomain),
                             ("sim.test", CampaignDomainAllowList)):
            d = Domain.objects.create(value=value)
            AllowListDomain.objects.create(domain=d, user=self.user)
            if model:
                model.objects.create(domain=d, user=self.user)
            h = self._handler(url=f"https://{value}/x")
            res = h.validate_forms()
            self.assertEqual(res["allow_listed"], model is None, value)
            self.assertEqual(len(h.pending_dispatch_intents), 0 if model is None else 1, value)
```

Run `ww test backend case_handler.tests.test_launch_allow_list` → FAIL. Implement in `case_handler.py` (`from settings.allow_lists import is_ip_allow_listed, overrides_allow_list`):

```python
            if url_inst and domain:
                listed = (AllowListDomain.objects.filter(domain=domain).exists()
                          or WatcherLegitDomain.objects.filter(domain=domain).exists())
                if not listed or overrides_allow_list(domain):
                    self._launch_analysis(url_inst, None, data_type="url")
                    return url_inst, False, ""
                url_inst.update_allow_listed()
                return url_inst, True, f"Domain '{domain}' is allow-listed."
```
```python
            if is_ip:
                ip_inst = IPHandler().handle_ip(other)
                if ip_inst:
                    if is_ip_allow_listed(ip_inst.address):
                        ip_inst.update_allow_listed()
                        return ip_inst, None, True, f"IP '{ip_inst.address}' is allow-listed."
                    self._launch_analysis(ip_inst, ip_inst, data_type="ip")
                return ip_inst, None, allow_listed, ""
```
If the URL test cannot find the `Domain` row (handler normalisation), print `Domain.objects.values_list("value", flat=True)` and align the test value, not the code.

- [ ] **Step 9: Docs.** Create `docs/operations/allow-lists.md`: the design section 1 table as reader prose (what each list means, verdict, jobs, MISP) and a "Job launch" section (IP skip in both paths, exact-domain matching with the `sites.google.com` example, precedence). Add `      - Allow lists: operations/allow-lists.md` after the Integrations line of `mkdocs.yml`. Add a short pointer paragraph to `docs/components/backend/settings.md`. Tasks 2 and 4 append sections.

- [ ] **Step 10: Run** — `ww test backend settings.tests case_handler.tests mail_feeder.job_handler.artifacts.tests score_process.tests.test_allow_list` → PASS.

- [ ] **Step 11: Commit** — `git add -A Suspicious docs mkdocs.yml && git commit -m "fix(launch): skip allow-listed IPs; an allow-list entry never beats deny, Watcher-monitored or campaign domains"` (plus the Co-Authored-By trailer).

---

### Task 2: MISP push skips

**Files:**
- Modify: `connectors/contrib/misp/internal.py`, `connectors/contrib/misp/service.py`, `docs/operations/allow-lists.md`
- Test: `connectors/contrib/misp/tests/test_misp_push.py`

**Interfaces:**
- Consumes: `settings.allow_lists.normalise_ip`; existing `internal.{company_domains, allow_listed_domains, is_company_domain, is_allow_listed, url_host}`; `MISPService._build_artifact_object`, `add_attachment_object`, `update_misp`.
- Produces: `internal.campaign_domains()`, `internal.allow_listed_ips()` (compressed strings), `internal.allow_listed_hashes()` (lower-case values), all `frozenset[str]`; `MISPService._shareable_ip(ip)`, `_shareable_hash(hash_obj)`; class-level defaults `_allow_listed_ips` / `_allow_listed_hashes = frozenset()` so tests that build the service via `__new__` and set only the old attributes keep passing.

- [ ] **Step 1: Failing tests.** Add imports to `test_misp_push.py`: `from django.contrib.auth import get_user_model`, `from django.utils import timezone`, `from case_handler.models import Case, CaseHasFileOrMail`, `from hash_process.models import Hash`, `from ip_process.models import IP`, `from mail_feeder.models import ArtifactIsIp, Mail, MailArtifact`, `from settings.models import CampaignDomainAllowList`. Append:

```python
class AllowListedAndCampaignIocsStayOutOfMispTest(SimpleTestCase):
    def _svc(self):
        svc = MISPService.__new__(MISPService)
        svc._company_domains = frozenset({"corp.example", "sim.test"})  # update_misp merges campaign domains in
        svc._allow_listed = frozenset({"good.test"})
        svc._allow_listed_ips = frozenset({"8.8.8.8", "2606:4700:4700::1111"})
        svc._allow_listed_hashes = frozenset({"ab" * 16})
        return svc

    def _build(self, artifact, ioc_type):
        return self._svc()._build_artifact_object(artifact, 1, "Dangerous", ioc_type)

    def test_campaign_domain_and_subdomains_skipped(self):
        self.assertIsNone(self._build(Domain(value="sim.test"), "domain"))
        self.assertIsNone(self._build(Domain(value="mail.sim.test"), "domain"))
        self.assertIsNotNone(self._build(Domain(value="notsim.test"), "domain"))

    def test_url_host_judged_after_credentials_are_stripped(self):
        self.assertIsNone(self._build(URL(address="https://corp.example@sim.test/x"), "url"))
        self.assertIsNotNone(self._build(URL(address="https://sim.test@evil.test/x"), "url"))

    def test_url_on_allow_listed_domain_skipped_lookalikes_pushed(self):
        self.assertIsNone(self._build(URL(address="https://good.test/a"), "url"))
        self.assertIsNone(self._build(URL(address="https://cdn.good.test/a"), "url"))
        self.assertIsNotNone(self._build(URL(address="https://good.test.evil.tld/a"), "url"))
        self.assertIsNotNone(self._build(URL(address="https://evil.test/?u=https://good.test/"), "url"))

    def test_allow_listed_ip_and_hash_skipped_others_pushed(self):
        self.assertIsNone(self._build(IP(address="2606:4700:4700:0:0:0:0:1111"), "ip"))
        self.assertIsNotNone(self._build(IP(address="8.8.4.4"), "ip"))
        self.assertIsNone(self._build(Hash(value="AB" * 16, hashtype="md5"), "hash"))
        self.assertIsNotNone(self._build(Hash(value="cd" * 16, hashtype="md5"), "hash"))

    def test_mail_artifact_ip_and_attachment_hash_filtered_too(self):
        svc = self._svc()
        art = SimpleNamespace(artifact_type="IP", artifactIsIp=SimpleNamespace(ip=IP(address="8.8.8.8")))
        self.assertIsNone(svc._build_artifact_object(art, 1, "Dangerous", None))
        att = SimpleNamespace(id=1, file=SimpleNamespace(linked_hash=Hash(value="ab" * 16, hashtype="md5")))
        with patch.object(MISPService, "_push") as push:
            svc.add_attachment_object("1", att, 1, "Dangerous")
        push.assert_not_called()

    def test_service_built_without_the_new_sets_still_works(self):
        svc = MISPService.__new__(MISPService)
        svc._company_domains, svc._allow_listed = frozenset(), frozenset()
        self.assertIsNotNone(svc._build_artifact_object(IP(address="8.8.8.8"), 1, "Dangerous", "ip"))


class CampaignSenderCaseStillSharesOtherIocsTest(TestCase):
    def test_campaign_domain_withheld_but_rest_of_case_pushed(self):
        user = get_user_model().objects.create_user(username="misp_camp", password="x")
        CampaignDomainAllowList.objects.create(domain=Domain.objects.create(value="sim.test"), user=user)
        mail = Mail.objects.create(subject="t", mail_from="hr@sim.test", date=timezone.now())
        art = MailArtifact.objects.create(mail=mail, artifact_type="IP", artifact_score=0, artifact_confidence=0)
        art.artifactIsIp = ArtifactIsIp.objects.create(ip=IP.objects.create(address="203.0.113.9"), artifact=art)
        art.save(update_fields=["artifactIsIp"])
        case = Case.objects.create(description="", reporter=user, results="Safe")
        case.fileOrMail = CaseHasFileOrMail.objects.create(case=case, mail=mail)
        case.save(update_fields=["fileOrMail"])
        with patch("connectors.contrib.misp.service.MISPEventManager") as mem, \
                patch("connectors.contrib.misp.service.MISPClient"), \
                patch("connectors.contrib.misp.service.build_email_object", return_value=None) as email, \
                patch("connectors.contrib.misp.service.build_ip_object", return_value=MagicMock()) as ip_obj, \
                patch("connectors.contrib.misp.service.finalize_misp_object"), \
                patch.object(MISPService, "_maybe_push_monthly"):
            mem.return_value.get_or_create_event.return_value = MagicMock(id=1)
            svc = MISPService.__new__(MISPService)
            svc.client, svc.primary = MagicMock(), True
            svc.update_misp(case)
        self.assertIn("sim.test", email.call_args.args[3])  # address objects drop the campaign sender
        ip_obj.assert_called_once()                          # no whole-case skip
```

- [ ] **Step 2: Run, expect FAIL** — `ww test backend connectors.contrib.misp.tests.test_misp_push`.

- [ ] **Step 3: Implement.** `internal.py`, below `allow_listed_domains`:

```python
def campaign_domains() -> frozenset[str]:
    """Authorised phishing-simulation domains: withheld from MISP like company
    domains (subdomains included) but still scored Dangerous."""
    from settings.models import CampaignDomainAllowList

    values = CampaignDomainAllowList.objects.values_list("domain__value", flat=True)
    return frozenset(v.strip().lower().rstrip(".") for v in values if v)


def allow_listed_ips() -> frozenset[str]:
    from settings.allow_lists import normalise_ip
    from settings.models import AllowListIp

    return frozenset(normalise_ip(a) for a in AllowListIp.objects.values_list("ip__address", flat=True) if a)


def allow_listed_hashes() -> frozenset[str]:
    from settings.models import AllowListFile

    values = AllowListFile.objects.values_list("linked_file_hash__value", flat=True)
    return frozenset(v.strip().lower() for v in values if v)
```

`service.py`: import the three functions and `from settings.allow_lists import normalise_ip`; add `_allow_listed_ips: frozenset = frozenset()` and `_allow_listed_hashes: frozenset = frozenset()` as class attributes; in `update_misp` replace the two set assignments with

```python
        # campaign simulations are withheld like company domains: domain, URL host
        # and email-address objects all go through this one set
        self._company_domains = company_domains() | campaign_domains()
        self._allow_listed = allow_listed_domains()
        self._allow_listed_ips = allow_listed_ips()
        self._allow_listed_hashes = allow_listed_hashes()
```

and replace `_shareable_url`, adding two helpers:

```python
    def _shareable_url(self, url: URL) -> bool:
        """A link on a company or allow-listed host is not an indicator."""
        host = url_host(url.address)
        return (not is_company_domain(host, self._company_domains)
                and not is_allow_listed(host, self._allow_listed))

    def _shareable_ip(self, ip: IP) -> bool:
        return normalise_ip(ip.address) not in self._allow_listed_ips

    def _shareable_hash(self, hash_obj: Hash) -> bool:
        return (hash_obj.value or "").strip().lower() not in self._allow_listed_hashes
```

In `_build_artifact_object` guard the four ip/hash branches (the two `ioc_type` ones and the two `artifact_type` ones) with `_shareable_ip` / `_shareable_hash`, returning `None` otherwise, as the url branch does. In `add_attachment_object`, after the `hash_obj is None` early return add `if not self._shareable_hash(hash_obj): return`.

- [ ] **Step 4: Run** — `ww test backend connectors.contrib.misp.tests connectors.tests.test_contrib_misp` → PASS (`test_update_misp_query_count` must still pass: the three new lookups are constant).

- [ ] **Step 5: Docs.** Append "MISP: what is not shared" to `docs/operations/allow-lists.md`: campaign domain / URL host / email-address objects; domains and URLs on allow-listed hosts (subdomains included); hashes on the file allow list; IPs on the IP allow list; per-IOC only, a campaign-sender case still shares its other IOCs; MISP matches subdomains while launch matches exact domains.

- [ ] **Step 6: Commit** — `git add -A Suspicious docs && git commit -m "fix(misp): keep campaign domains and allow-listed URLs, IPs and hashes out of shared events"` (plus trailer).

---

### Task 3: Majority rule in `score_case` (pure engine)

**Files:**
- Modify: `score_process/scoring/engine.py`, `score_process/scoring/explanation/compose.py` (`_RULE_TEMPLATES`)
- Test: `score_process/tests/test_engine.py`, `score_process/tests/test_explanation_compose.py`

**Interfaces:**
- Consumes: `CaseVerdict`, `Signal`, `AiSignal`, `Result`, `mail_band_escalation`.
- Produces: `engine.Vote(analyzer: str, weight: float, band: str, whitelisted: bool = False)` (frozen dataclass; `band` is `Result.SAFE | SUSPICIOUS | DANGEROUS`); `score_case(signals, ai=None, deny_listed=False, ai_missing=False, deny_reason="", votes=()) -> CaseVerdict`. Task 4 builds and passes the votes.

Rule: applies only when some vote is `whitelisted`, the normal result is not Safe/Failure and total vote weight is > 0. Safe weight is the sum over `band == SAFE` votes. Override iff `round(2 * safe - total, 9) > 0`: score 0, confidence 100, Safe, rule `allow-list-majority`, rationale line naming dissenters as `"<Band>: <analyzer>"`. Otherwise the verdict is unchanged apart from one rationale line with the percentage.

- [ ] **Step 1: Failing tests.** In `test_engine.py` extend the engine import with `Vote` and append:

```python
def vote(name, weight, band=Result.SAFE, wl=False):
    return Vote(analyzer=name, weight=weight, band=band, whitelisted=wl)


# a malicious signal elsewhere in the case: today this always means Dangerous
DANGEROUS_CASE = [sig(0, 100, src="url"), sig(0, 100, src="url"), sig(9, 90, mal=True, src="ip")]


class AllowListMajorityTest(SimpleTestCase):
    def test_baseline_is_dangerous_without_votes(self):
        self.assertEqual(score_case(DANGEROUS_CASE).result, Result.DANGEROUS)

    def test_majority_overrides_and_names_the_dissenter(self):
        votes = [vote("VT", 0.3, wl=True), vote("Urlscan", 0.3, wl=True),
                 vote("AIMailAnalyzer", 0.2, Result.DANGEROUS)]
        v = score_case(DANGEROUS_CASE, votes=votes)
        self.assertEqual((v.result, v.final_score, v.final_confidence, v.rule),
                         (Result.SAFE, 0, 100, "allow-list-majority"))
        self.assertIn("Dangerous: AIMailAnalyzer", v.rationale[-1])
        self.assertIn("75%", v.rationale[-1])

    def test_exactly_half_does_not_override_even_with_float_drift(self):
        for votes in ([vote("A", 0.5, wl=True), vote("B", 0.5, Result.DANGEROUS)],
                      [vote("A", 0.1, wl=True), vote("B", 0.2), vote("C", 0.3, Result.DANGEROUS)]):
            v = score_case(DANGEROUS_CASE, votes=votes)
            self.assertEqual(v.result, Result.DANGEROUS)
            self.assertIn("only 50%", v.rationale[-1])

    def test_minority_keeps_dangerous_and_says_why(self):
        votes = [vote("A", 0.2, wl=True), vote("B", 0.5, Result.DANGEROUS), vote("C", 0.3, Result.SUSPICIOUS)]
        v = score_case(DANGEROUS_CASE, votes=votes)
        self.assertEqual((v.result, v.rule), (Result.DANGEROUS, "weighted-consensus"))
        self.assertIn("only 20%", v.rationale[-1])

    def test_no_whitelisted_vote_is_identical_to_today(self):
        cases = [(DANGEROUS_CASE, None, False), ([sig(2, 95)], AiSignal(9, 10), False),
                 ([sig(1, 40)], AiSignal(9, 90), False), ([sig(5, 85), sig(5, 80)], AiSignal(6, 100), False),
                 ([sig(7, 40)], None, True)]
        plain = [vote("A", 1.0), vote("B", 1.0, Result.DANGEROUS)]
        for signals, ai, missing in cases:
            self.assertEqual(score_case(signals, ai, ai_missing=missing, votes=plain),
                             score_case(signals, ai, ai_missing=missing))

    def test_deny_list_zero_weight_and_already_safe_are_untouched(self):
        v = score_case(DANGEROUS_CASE, deny_listed=True, deny_reason="d", votes=[vote("A", 1, wl=True)])
        self.assertEqual((v.result, v.rule), (Result.DANGEROUS, "deny-listed"))
        self.assertEqual(score_case(DANGEROUS_CASE, votes=[vote("A", 0, wl=True)]).result, Result.DANGEROUS)
        self.assertEqual(score_case([sig(0, 100)], votes=[vote("A", 1, wl=True)]), score_case([sig(0, 100)]))

    def test_missing_ai_inconclusive_becomes_safe_on_majority(self):
        v = score_case([sig(0, 100)], ai_missing=True, votes=[vote("A", 1, wl=True)])
        self.assertEqual((v.result, v.rule), (Result.SAFE, "allow-list-majority"))

    def test_embedded_dangerous_ioc_still_raises_the_majority_verdict(self):
        from score_process.scoring.engine import mail_band_escalation
        from score_process.scoring.observable_engine import ObservableVerdict
        safe = score_case(DANGEROUS_CASE, votes=[vote("A", 1, wl=True)])
        out = mail_band_escalation(safe, [ObservableVerdict("Dangerous", 80, None, {}, [])])
        self.assertEqual((out.result, out.rule), (Result.DANGEROUS, "embedded-ioc-escalation"))
```

In `test_explanation_compose.py` add `def test_allow_list_majority_has_a_template(self): self.assertIn("allow-list-majority", RULE_KEYS)` (the existing loop test then checks it composes without placeholders).

- [ ] **Step 2: Run, expect FAIL** — `ww test backend score_process.tests.test_engine score_process.tests.test_explanation_compose` (ImportError `Vote`).

- [ ] **Step 3: Implement** in `engine.py`. Add `votes=()` as the last `score_case` parameter and wrap its final return: `return _allow_list_majority(CaseVerdict(...unchanged...), votes)`. Add after `AiSignal`:

```python
@dataclass(frozen=True)
class Vote:
    """One analyzer's say on a case: its weight, its worst band across the
    case's artifacts, and whether a Safe band came from an allow-list hit."""
    analyzer: str
    weight: float
    band: str
    whitelisted: bool = False


def _allow_list_majority(verdict, votes):
    """Allow-list is a vote, not an absolute override: a strict majority of Safe
    plus allow-listed weight makes the case Safe and records the dissent.
    Cases without a whitelisted vote, already-Safe cases and failures pass through."""
    if verdict.result in (Result.SAFE, Result.FAILURE) or not any(v.whitelisted for v in votes):
        return verdict
    total = sum(v.weight for v in votes)
    if total <= 0:
        return verdict
    safe = sum(v.weight for v in votes if v.band == Result.SAFE)
    pct = round(100 * safe / total)
    dissent = ", ".join(f"{v.band}: {v.analyzer}" for v in votes if v.band != Result.SAFE) or "none"
    if round(2 * safe - total, 9) <= 0:
        line = (f"Allow-listed, but only {pct}% of analyzer weight agrees "
                f"(dissent: {dissent}); verdict not overridden.")
        return replace(verdict, rationale=tuple(verdict.rationale) + (line,))
    line = (f"Allow-list majority: {pct}% of analyzer weight is Safe or allow-listed; "
            f"dissent overruled ({dissent}).")
    return replace(verdict, final_score=0, final_confidence=100, result=Result.SAFE,
                   rationale=tuple(verdict.rationale) + (line,), rule="allow-list-majority")
```

`compose.py`, in `_RULE_TEMPLATES` after `ai-classifier-decisive`:

```python
    "allow-list-majority": {
        "analyst": "Most of the analyzer weight is Safe or allow-listed, so this {data_type} is "
                   "{band}. Analyzers that disagreed are listed in the verdict rationale.",
        "reporter": "The checks that carry most weight for this item came back safe or allow-listed.",
    },
```

- [ ] **Step 4: Run** — `ww test backend score_process.tests.test_engine score_process.tests.test_explanation_compose score_process.tests.test_mail_escalation score_process.tests.test_explanation_engine_rules` → PASS.

- [ ] **Step 5: Commit** — `git add -A Suspicious && git commit -m "feat(scoring): weighted allow-list majority can override a lone Dangerous signal"` (plus trailer).

---

### Task 4: Build the votes and wire them into `get_report`

**Files:**
- Modify: `score_process/scoring/cortex_analyzers/allow_list.py` (markers), `score_process/scoring/collect.py` (`collect_votes`), `score_process/scoring/cortex_analyzers/reports.py` (`get_report`), `docs/operations/allow-lists.md`, `docs/components/backend/score_process.md`, `CHANGELOG.md`
- Test: `score_process/tests/test_collect.py`, `score_process/tests/test_get_report.py`

**Interfaces:**
- Consumes: `engine.{Vote, band, CONF_FLOOR, _BAND_RANK}`; `api.utils.analyzer_reports.reports_for_case` and `api.views.investigations._dedup_analyzer_reports` (the pair `get_report` already uses for the explanation); `cortex_job.cortex_utils.cortex_and_job_management._get_cortex_config`; `AnalyzerReport.{status, level, confidence, score, category, analyzer.weight}`.
- Produces: `allow_list.ALLOW_LIST_MARKERS` and `allow_list.is_allow_listed_category(category) -> bool`; `collect.collect_votes(case, ai=None) -> tuple[Vote, ...]`. `collect_signals` keeps its 5-tuple return (many tests unpack it).

Vote construction: the AI analyzer's report is not among the `reports_for_case` targets, so its vote comes from the `AiSignal` (weight from `Analyzer` named by `integrations.cortex.analyzers.ai`). One vote per analyzer name; band is the worst across its counted reports; `whitelisted` only if that worst band is Safe and at least one counted report has an allow-list marker in `category`. A report counts only if `status == "Success"`, `level != "info"`, `confidence >= CONF_FLOOR` and it is not the AI analyzer; weight-0 analyzers are dropped.

- [ ] **Step 1: Failing tests.** In `test_collect.py` add imports `from score_process.scoring.collect import collect_votes`, `from score_process.scoring.engine import AiSignal`, `from url_process.models import URL` and append:

```python
class CollectVotesTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="cv_u", password="x")
        self.url = URL.objects.create(address="https://a.test/1")
        self.url2 = URL.objects.create(address="https://b.test/2")
        self.url.analyzed_url = self.url2   # a case covers both URLs
        self.url.save()
        self.case = Case.objects.create(description="", reporter=self.user)
        self.case.nonFileIocs = CaseHasNonFileIocs.objects.create(case=self.case, url=self.url)
        self.case.save()

    def _report(self, name, weight=0.2, *, url=None, job="j", status="Success", level="safe",
                score=0, confidence=100, category=""):
        analyzer, _ = Analyzer.objects.get_or_create(
            name=name, defaults={"analyzer_cortex_id": name, "weight": weight})
        return AnalyzerReport.objects.create(
            cortex_job_id=f"{name}-{job}", type="url", status=status, analyzer=analyzer,
            url=url or self.url, level=level, score=score, confidence=confidence,
            category=category, report_summary={"x": 1}, report_taxonomy={}, report_full={})

    def _votes(self, ai=None):
        with patch("cortex_job.cortex_utils.cortex_and_job_management._get_cortex_config",
                   return_value={"analyzers": {"ai": "AIMailAnalyzer"}}):
            return {v.analyzer: v for v in collect_votes(self.case, ai)}

    def test_whitelisted_safe_and_dangerous_votes(self):
        self._report("WL", 0.3, category="Safe DW triggered")
        self._report("Clean", 0.2)
        self._report("Bad", 0.5, level="malicious", score=10)
        v = self._votes()
        self.assertEqual((v["WL"].band, v["WL"].whitelisted, v["WL"].weight), ("Safe", True, 0.3))
        self.assertEqual((v["Clean"].band, v["Clean"].whitelisted), ("Safe", False))
        self.assertEqual((v["Bad"].band, v["Bad"].whitelisted), ("Dangerous", False))

    def test_failed_pending_info_low_confidence_and_zero_weight_are_not_votes(self):
        self._report("Failed", status="Failure")
        self._report("Pending", status="InProgress")
        self._report("Info", level="info", score=2, confidence=50)
        self._report("Unsure", level="suspicious", score=7, confidence=49)
        self._report("Zero", 0)
        self.assertEqual(self._votes(), {})

    def test_analyzer_flagging_one_target_and_whitelisted_on_another_votes_dissent(self):
        self._report("Both", category="Safe DW triggered")
        self._report("Both", url=self.url2, level="malicious", score=10, job="2")
        vote = self._votes()["Both"]
        self.assertEqual((vote.band, vote.whitelisted), ("Dangerous", False))

    def test_a_newer_rerun_replaces_a_stale_dissent(self):
        self._report("Re", level="malicious", score=10, job="old")
        self._report("Re", job="new")
        self.assertEqual(self._votes()["Re"].band, "Safe")

    def test_ai_signal_votes_with_the_ai_analyzer_weight(self):
        Analyzer.objects.create(name="AIMailAnalyzer", analyzer_cortex_id="ai", weight=0.4)
        ai = self._votes(AiSignal(score=9, confidence=90))["AIMailAnalyzer"]
        self.assertEqual((ai.band, ai.weight), ("Dangerous", 0.4))
        self.assertNotIn("AIMailAnalyzer", self._votes(AiSignal(score=9, confidence=10)))
        self.assertNotIn("AIMailAnalyzer", self._votes(None))
```

In `test_get_report.py` add `from unittest.mock import patch` and `from score_process.scoring.engine import Vote`, then append:

```python
class GetReportVotesWiringTest(TestCase):
    def _malicious_ip_case(self):
        user = get_user_model().objects.create_user(username="gr_votes", password="x")
        ip = IP.objects.create(address="203.0.113.31")
        analyzer = Analyzer.objects.create(name="AbuseV", analyzer_cortex_id="AbuseV", weight=1)
        AnalyzerReport.objects.create(
            cortex_job_id="grv1", type="ip", status="Success", analyzer=analyzer, ip=ip,
            level="malicious", confidence=9, score=9,
            report_summary={"taxonomies": [{"level": "malicious", "value": "abuse"}]},
            report_taxonomy={}, report_full={})
        case = Case.objects.create(description="", reporter=user)
        case.nonFileIocs = CaseHasNonFileIocs.objects.create(case=case, ip=ip)
        case.save()
        return case

    def _result(self, **patch_kw):
        case = self._malicious_ip_case()
        with patch("score_process.scoring.collect.collect_votes", **patch_kw):
            CortexAnalyzerReports.get_report(case)
        case.refresh_from_db()
        return case

    def test_majority_votes_make_the_case_safe_and_persist_the_dissent(self):
        case = self._result(return_value=(Vote("WL", 0.6, "Safe", True), Vote("AbuseV", 0.2, "Dangerous")))
        self.assertEqual(case.results, Result.SAFE)
        self.assertIn("Dangerous: AbuseV", case.verdict_rationale[-1])

    def test_no_votes_keeps_dangerous_and_a_failing_collector_never_blocks_scoring(self):
        self.assertEqual(self._result(return_value=()).results, Result.DANGEROUS)
        self.assertEqual(self._result(side_effect=RuntimeError("boom")).results, Result.DANGEROUS)
```

- [ ] **Step 2: Run, expect FAIL** — `ww test backend score_process.tests.test_collect score_process.tests.test_get_report` (ImportError `collect_votes`).

- [ ] **Step 3: Markers** — in `cortex_analyzers/allow_list.py` define the five strings once, use them in `check_allow_list` (values unchanged) and add the predicate:

```python
SAFE_FW, SAFE_FTW = "Safe FW triggered", "Safe FTW triggered"
SAFE_DW, SAFE_WL, SAFE_IPW = "Safe DW triggered", "Safe WL triggered", "Safe IPW triggered"
ALLOW_LIST_MARKERS = frozenset({SAFE_FW, SAFE_FTW, SAFE_DW, SAFE_WL, SAFE_IPW})


def is_allow_listed_category(category) -> bool:
    """True for a stored AnalyzerReport.category produced by an allow-list hit."""
    text = category or ""
    return any(marker in text for marker in ALLOW_LIST_MARKERS)
```

- [ ] **Step 4: `collect_votes`** in `collect.py` (extend the engine import with `Vote, CONF_FLOOR, band, _BAND_RANK`):

```python
def collect_votes(case, ai=None) -> tuple:
    """One Vote per analyzer from the case's latest reports plus the AI signal.
    An analyzer's band is the worst across its reports, so a tool that flags one
    artifact and is allow-listed on another votes dissent, not safe."""
    from api.utils.analyzer_reports import reports_for_case
    from api.views.investigations import _dedup_analyzer_reports
    from cortex_job.cortex_utils.cortex_and_job_management import _get_cortex_config
    from cortex_job.models import Analyzer
    from score_process.scoring.cortex_analyzers.allow_list import is_allow_listed_category

    ai_name = _get_cortex_config().get("analyzers", {}).get("ai")
    seen: dict = {}   # analyzer name -> [weight, worst band, any allow-list hit]

    def add(name, weight, report_band, hit):
        cur = seen.setdefault(name, [weight, Result.SAFE, False])
        if _BAND_RANK[report_band] > _BAND_RANK[cur[1]]:
            cur[1] = report_band
        cur[2] = cur[2] or hit

    for r in _dedup_analyzer_reports(reports_for_case(case, defer_full=True)):
        if (r.status != "Success" or r.level == "info" or r.confidence < CONF_FLOOR
                or r.analyzer.name == ai_name):
            continue
        add(r.analyzer.name, r.analyzer.weight, band(r.score), is_allow_listed_category(r.category))

    if ai is not None and ai_name and ai.confidence >= CONF_FLOOR:
        weight = Analyzer.objects.filter(name=ai_name).values_list("weight", flat=True).first()
        if weight:
            add(ai_name, weight, band(ai.score), False)

    return tuple(Vote(n, w, b, hit and b == Result.SAFE) for n, (w, b, hit) in seen.items() if w > 0)
```

- [ ] **Step 5: Wire `get_report`** (`reports.py`): extend the local import to `from score_process.scoring.collect import collect_signals, collect_votes` and replace the `collect_signals` / `score_case` lines (`collect_signals` must run first: it persists the report scores and categories that `collect_votes` reads):

```python
            signals, ai, deny_listed, ai_missing, deny_reason = collect_signals(case)
            try:
                votes = collect_votes(case, ai)
            except Exception:
                update_cases_logger.exception("get_report: collect_votes failed for case %s", case.id)
                votes = ()
            verdict = score_case(signals, ai, deny_listed, ai_missing, deny_reason, votes=votes)
```

- [ ] **Step 6: Run** — `ww test backend score_process cortex_job case_handler connectors mail_feeder settings`; then the whole backend once: `ww test backend` → PASS.

- [ ] **Step 7: Docs and changelog.**
  - `docs/operations/allow-lists.md`: append "Scoring: an allow-list is a vote" (weighted per analyzer, worst band per analyzer, strict majority, rule `allow-list-majority` and the rationale lines, which reports do not vote, deny / campaign / Watcher-monitored never overridden, embedded-IOC escalation still applies afterwards).
  - `docs/components/backend/score_process.md`: one paragraph after the intro naming `Vote`, `collect_votes` and the rule, linking the operations page.
  - `CHANGELOG.md`, first `[Unreleased]` block only: first bullet under `### Fixed`: "Allow-listed IPs no longer launch Cortex jobs (email and web submit); an allow-list entry no longer silences a deny-listed, Watcher-monitored or campaign domain; MISP no longer receives campaign-domain indicators or allow-listed URLs, IPs and hashes." First bullet under `### Changed`: "Allow-lists are a weighted vote in `score_case`: a strict majority of Safe plus allow-listed analyzer weight now yields Safe (rule `allow-list-majority`) with dissenting analyzers named in the rationale."

- [ ] **Step 8: Commit** — `git add -A Suspicious docs CHANGELOG.md && git commit -m "feat(scoring): collect per-analyzer allow-list votes and feed them to score_case"` (plus trailer).

---

## Self-Review

- **Spec coverage:** 3.1 IP skip in both paths, exact domains, precedence (Task 1); 3.2 every skip type, per-IOC, subdomain rule (Task 2); 3.3 weighted strict majority, dissent in the reason, not-overridden reason, failed/pending excluded, no-whitelist unchanged (Tasks 3, 4); section 4: the Settings purpose line already exists at `suspicious-ui/src/features/settings/components/sections.tsx:50`, so no frontend change; docs and CHANGELOG in Tasks 1, 2, 4.
- **Deviations to confirm with the user:** (a) votes collapse to one per analyzer (worst band wins) instead of one per report; (b) MISP URLs on allow-listed domains follow the existing subdomain rule, as domain objects do; (c) the precedence fix also changes the email path: a domain on both allow and deny lists is now marked `dangerous`, not `SAFE-ALLOW_LISTED`.
- **Known limit:** because launch now skips allow-listed targets, whitelisted reports mostly come from lists edited after jobs ran and from Watcher-legit hits, so the majority rule is rarely exercised in production by design.
- **Placeholders:** none. Names are consistent across tasks: `normalise_ip`, `is_ip_allow_listed`, `overrides_allow_list`, `Vote`, `collect_votes`, `ALLOW_LIST_MARKERS`, `is_allow_listed_category`, rule `allow-list-majority`.
