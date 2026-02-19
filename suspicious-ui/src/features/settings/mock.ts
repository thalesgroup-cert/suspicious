import type { Analyzer, FeederStatus, ListItem, SettingsSection } from "./api";

export function mockList(section: SettingsSection): ListItem[] {
  const mk = (v: string): ListItem => ({ id: v, value: v });
  switch (section) {
    case "domains_allow":
      return ["thalesgroup.com", "microsoft.com", "paypal.com"].map(mk);
    case "domains_deny":
      return ["evil.tld", "phish.example", "bad-domain.io"].map(mk);
    case "campaign_domains_allow":
      return ["newsletter.company.com", "events.company.com"].map(mk);
    case "emails_files_allow":
      return ["sha256:aa...11", "sha256:bb...22", "incident.eml"].map(mk);
    case "filetypes_allow":
      return [".pdf", ".docx", ".eml", ".msg"].map(mk);
    case "ciso_users":
      return ["ciso.europe", "ciso.france", "ciso.def"].map(mk);
    default:
      return [];
  }
}

export function mockFeeder(): FeederStatus {
  return { enabled: true };
}

export function mockAnalyzers(): Analyzer[] {
  return [
    { id: "anl_virustotal", name: "VirusTotal", weight: 2.2 },
    { id: "anl_urlscan", name: "urlscan.io", weight: 1.4 },
    { id: "anl_cortex", name: "Cortex Analyzer", weight: 0.8 },
    { id: "anl_yara", name: "YARA", weight: 1.1 },
  ];
}
