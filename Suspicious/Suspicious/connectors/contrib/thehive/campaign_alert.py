"""The content of a campaign alert: observables, files, severity, description.

Pure functions over data already read from the database and MinIO, so the whole
alert can be built, tested and reviewed without a TheHive.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime

from connectors.contrib.thehive.campaign_iocs import Iocs
from connectors.contrib.thehive.campaign_material import MAX_FILE_BYTES, MailMaterial

TLP_AMBER = PAP_AMBER = 2
MAX_TOTAL_BYTES = 50 * 1024 * 1024
MAX_EML_SAMPLES = 3
MAX_URLS = 200
_TOP = 10
_BASE_TAGS = ["phishing", "email", "campaign", "suspicious",
              'enisa:nefarious-activity-abuse="phishing-attack"']


@dataclass
class MemberInfo:
    case_id: int
    reporter: str
    verdict: str
    malscore: float
    subject: str
    created_at: datetime


@dataclass
class MemberMaterial:
    info: MemberInfo
    material: MailMaterial
    kept: list
    skipped: list
    iocs: Iocs


@dataclass
class FilePart:
    filename: str
    data: bytes
    message: str
    tags: list[str]


@dataclass
class CampaignContent:
    title: str
    description: str
    severity: int
    tlp: int
    pap: int
    tags: list[str]
    source_ref: str
    observables: list[dict] = field(default_factory=list)
    files: list[FilePart] = field(default_factory=list)


def merge_iocs(parts) -> Iocs:
    merged = Iocs()
    for part in parts:
        for name in merged.__dataclass_fields__:
            target = getattr(merged, name)
            for value in getattr(part, name):
                if value not in target:
                    target.append(value)
    merged.urls = merged.urls[:MAX_URLS]
    return merged


def _obs(data_type: str, data: str, message: str, tags: list[str], *, ioc: bool) -> dict:
    return {
        "dataType": data_type, "data": data, "message": message,
        "tags": ["suspicious", "phishing"] + tags,
        "tlp": TLP_AMBER, "pap": PAP_AMBER, "ioc": ioc, "sighted": True,
    }


def build_observables(iocs: Iocs) -> list[dict]:
    out = [_obs("url", u, "URL in the mail body or an attachment", ["url"], ioc=True) for u in iocs.urls]
    out += [_obs("domain", d, "Domain of a URL or of a sender address", ["domain"], ioc=True) for d in iocs.domains]
    out += [_obs("ip", i, "Host of a URL or hop in the mail's network path", ["ip"], ioc=True) for i in iocs.ips]
    out += [_obs("mail", e, "Sender, Reply-To or Return-Path address", ["sender"], ioc=True) for e in iocs.emails]
    out += [_obs("hash", h, "SHA-256 of an attachment", ["attachment"], ioc=True) for h in iocs.hashes]
    out += [_obs("filename", n, "Attachment name", ["attachment"], ioc=False) for n in iocs.filenames]
    out += [_obs("mail-subject", s, "Mail subject", ["subject"], ioc=False) for s in iocs.subjects]
    out += [_obs("other", n, "Sender display name", ["display-name"], ioc=False) for n in iocs.display_names]
    out += [_obs("other", m, "Message-ID", ["message-id"], ioc=False) for m in iocs.message_ids]
    return out


def severity_for(verdicts, n_members: int) -> int:
    verdicts = list(verdicts)
    if "Dangerous" in verdicts:
        return 4 if n_members >= 10 else 3
    return 2 if "Suspicious" in verdicts else 1


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def _build_files(members: list[MemberMaterial]):
    """Relevant files, each hash once, within the upload budget.

    Returns (files, rows) where rows are (name, size, sha256, status, seen_in).
    """
    files: list[FilePart] = []
    rows: dict[str, list] = {}
    used, names = 0, set()

    def room(size: int) -> bool:
        return used + size <= MAX_TOTAL_BYTES

    samples = 0
    for m in members:
        if m.material.eml and samples < MAX_EML_SAMPLES and len(m.material.eml) <= MAX_FILE_BYTES \
                and room(len(m.material.eml)):
            files.append(FilePart(f"mail-source-case-{m.info.case_id}.eml", m.material.eml,
                                  f"Original reported mail (case {m.info.case_id})", ["mail-source"]))
            used += len(m.material.eml)
            samples += 1
        for att in m.kept:
            sha = att.sha256
            if sha in rows:
                rows[sha][4] += 1
                continue
            if not room(len(att.data)):
                rows[sha] = [att.name, len(att.data), sha, "not uploaded: campaign upload budget reached", 1]
                continue
            filename = att.name if att.name not in names else f"case{m.info.case_id}_{att.name}"
            names.add(filename)
            files.append(FilePart(filename, att.data, f"Attachment of case {m.info.case_id}", ["attachment"]))
            used += len(att.data)
            rows[sha] = [filename, len(att.data), sha, "uploaded", 1]
        for name, sha, size, reason in m.skipped:
            key = sha if size else f"empty:{name}"
            if key in rows:
                rows[key][4] += 1
            else:
                rows[key] = [name, size, sha if size else "", f"not uploaded: {reason}", 1]
    return files, list(rows.values())


def _list(values, limit=_TOP) -> str:
    shown = [f"`{v}`" for v in values[:limit]]
    extra = len(values) - limit
    return ", ".join(shown) + (f" and {extra} more" if extra > 0 else "") if shown else "none"


def build_description(campaign, members: list[MemberMaterial], iocs: Iocs, rows, ui_base: str) -> str:
    infos = [m.info for m in members]
    reporters = {i.reporter for i in infos}
    verdicts = Counter(i.verdict for i in infos)
    first, last = min(i.created_at for i in infos), max(i.created_at for i in infos)
    fmt = lambda d: d.strftime("%Y-%m-%d %H:%M UTC")
    subjects = Counter(i.subject for i in infos).most_common(_TOP)

    lines = [
        f"# Potential phishing campaign: {campaign.title}", "",
        "| | |", "|---|---|",
        f"| Campaign | `{campaign.ref}` |",
        f"| Reported | {_plural(len(infos), 'mail')} from {_plural(len(reporters), 'reporter')} |",
        f"| First / last reported | {fmt(first)} / {fmt(last)} |",
        f"| Verdicts | {', '.join(f'{v} x{n}' for v, n in verdicts.most_common())} |",
        f"| Highest AI malscore | {max(i.malscore for i in infos):.1f} |",
        f"| Email authentication | {', '.join(iocs.auth_failures) or 'no failure recorded'} |",
        "", "## Indicators",
        f"- **Sender domains / addresses:** {_list(iocs.emails)}",
        f"- **Domains:** {_list(iocs.domains)}",
        f"- **IP addresses:** {_list(iocs.ips)}",
        f"- **URLs:** {_list(iocs.urls)}",
        f"- **Sender display names:** {_list(iocs.display_names)}",
        "", "## Attachments",
    ]
    if rows:
        lines += ["| File | Size | SHA-256 | Status | Mails |", "|---|---|---|---|---|"]
        lines += [f"| {n} | {s} B | {'`' + h + '`' if h else ''} | {st} | {c} |" for n, s, h, st, c in rows]
    else:
        lines.append("No attachments.")
    lines += ["", "## Subjects"] + [f"- {s} (x{n})" for s, n in subjects]
    lines += ["", "## Suspicious cases"]
    lines += [f"- [#{i.case_id}]({ui_base}/investigation?open={i.case_id}) reported by {i.reporter} "
              f"({i.verdict})" for i in sorted(infos, key=lambda i: i.case_id)[:50]]
    example = (members[0].material.text or members[0].material.html or "")[:1500].replace("```", "'''")
    if example:
        lines += ["", "## Example mail body", "```", example, "```"]
    return "\n".join(lines)


def build_content(campaign, members: list[MemberMaterial], *, ui_base: str) -> CampaignContent:
    files, rows = _build_files(members)
    iocs = merge_iocs(m.iocs for m in members)
    return CampaignContent(
        title=f"Potential phishing campaign: {campaign.title}",
        description=build_description(campaign, members, iocs, rows, ui_base),
        severity=severity_for((m.info.verdict for m in members), len(members)),
        tlp=TLP_AMBER, pap=PAP_AMBER,
        tags=_BASE_TAGS + [campaign.ref],
        source_ref=campaign.ref,
        observables=build_observables(iocs),
        files=files,
    )
