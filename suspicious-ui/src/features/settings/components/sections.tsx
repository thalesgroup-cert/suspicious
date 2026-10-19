import * as React from "react";
import {
  BlockOutlined,
  CampaignOutlined,
  CheckCircleOutlined,
  ExtensionOutlined,
  GroupsOutlined,
  HubOutlined,
  InsertDriveFileOutlined,
  MailOutlined,
  TuneOutlined,
} from "@mui/icons-material";

import type { EditableListSection, SettingsSection } from "@/features/settings/api";
import { ConnectorsPanel } from "@/features/settings/components/ConnectorsPanel";
import { CisoUsersPanel } from "@/features/settings/components/CisoUsersPanel";
import { DomainPairPanel } from "@/features/settings/components/ReadOnlyListPanel";
import { EditableListPanel } from "@/features/settings/components/EditableListPanel";
import { FeederPanel } from "@/features/settings/components/FeederPanel";
import { ScoringPanel } from "@/features/settings/components/ScoringPanel";

export type SectionKind = "list" | "toggle" | "scoring" | "ciso_users" | "domain_pair" | "connectors";

/** Sidebar keys: backend settings sections plus UI-only panels. */
export type SectionKey = SettingsSection | "connectors";

export type SectionGroupKey = "lists" | "access" | "ingestion" | "scoring" | "integrations";

export type SectionMeta = {
  key: SectionKey;
  group: SectionGroupKey;
  title: string;
  subtitle: string;
  icon: React.ReactNode;
  kind: SectionKind;
  badge?: number;
};

export function SectionContent({ section }: { section: SectionMeta }) {
  switch (section.kind) {
    case "domain_pair":
      return (
        <DomainPairPanel
          editableSection={section.key as "domains_allow" | "domains_deny"}
        />
      );
    case "list":
      return (
        <EditableListPanel
          section={section.key as EditableListSection}
          placeholder="Paste values, one per line or comma-separated…"
        />
      );
    case "toggle":
      return <FeederPanel />;
    case "scoring":
      return <ScoringPanel />;
    case "ciso_users":
      return <CisoUsersPanel />;
    case "connectors":
      return <ConnectorsPanel />;
    default:
      return null;
  }
}

export const SECTIONS: SectionMeta[] = [
  {
    key: "domains_allow",
    group: "lists",
    title: "Domains allowlist",
    subtitle: "Manage local allowlist and Watcher legit domains.",
    icon: <CheckCircleOutlined />,
    kind: "domain_pair",
  },
  {
    key: "domains_deny",
    group: "lists",
    title: "Domains denylist",
    subtitle: "Manage local denylist and Watcher monitored domains.",
    icon: <BlockOutlined />,
    kind: "domain_pair",
  },
  {
    key: "campaign_domains_allow",
    group: "lists",
    title: "Campaign domains",
    subtitle: "Allow campaign or newsletter domains.",
    icon: <CampaignOutlined />,
    kind: "list",
  },
  {
    key: "emails_files_allow",
    group: "lists",
    title: "Files allowlist",
    subtitle: "Allow known safe file hashes.",
    icon: <InsertDriveFileOutlined />,
    kind: "list",
  },
  {
    key: "filetypes_allow",
    group: "lists",
    title: "Filetypes allowlist",
    subtitle: "Allow known safe file extensions.",
    icon: <ExtensionOutlined />,
    kind: "list",
  },
  {
    key: "ciso_users",
    group: "access",
    title: "CISO users",
    subtitle: "Review scoped CISO identities.",
    icon: <GroupsOutlined />,
    kind: "ciso_users",
  },
  {
    key: "email_feeder",
    group: "ingestion",
    title: "Email feeder",
    subtitle: "Enable or disable the feeder service.",
    icon: <MailOutlined />,
    kind: "toggle",
  },
  {
    key: "scoring",
    group: "scoring",
    title: "Analyzer scoring",
    subtitle: "Tune analyzer weights.",
    icon: <TuneOutlined />,
    kind: "scoring",
  },
  {
    key: "connectors",
    group: "integrations",
    title: "Connectors",
    subtitle: "Enable integrations and tune their config.",
    icon: <HubOutlined />,
    kind: "connectors",
  },
];

const GROUP_LABELS: [SectionGroupKey, string][] = [
  ["lists", "Detection lists"],
  ["access", "Access"],
  ["ingestion", "Ingestion"],
  ["scoring", "Scoring"],
  ["integrations", "Integrations"],
];

export const GROUPS: { key: SectionGroupKey; label: string; sections: SectionMeta[] }[] =
  GROUP_LABELS.map(([key, label]) => ({
    key,
    label,
    sections: SECTIONS.filter((s) => s.group === key),
  }));

/** URL param to section key; null when unknown so the caller can redirect. */
export function parseSection(raw: string | undefined): SectionKey | null {
  const key = raw?.replace(/\/+$/, "");
  return SECTIONS.find((s) => s.key === key)?.key ?? null;
}
