import {
  AssignmentTurnedInOutlined,
  CampaignOutlined,
  DashboardOutlined,
  HomeOutlined,
  InfoOutlined,
  ManageSearchOutlined,
  PersonOutlined,
  SettingsOutlined,
  UploadFileOutlined,
} from "@mui/icons-material";

import type { NavItemConfig } from "@/layouts/nav";

export const PRIMARY_NAV: NavItemConfig[] = [
  { to: "/",            label: "Home",            icon: <HomeOutlined /> },
  { to: "/submit",      label: "Submit",          icon: <UploadFileOutlined /> },
  { to: "/submissions", label: "My submissions",  icon: <AssignmentTurnedInOutlined /> },
];

export const WORKSPACE_NAV: NavItemConfig[] = [
  { to: "/campaigns",     label: "Campaigns",     icon: <CampaignOutlined /> },
  { to: "/dashboard",     label: "Dashboard",     icon: <DashboardOutlined /> },
  { to: "/investigation", label: "Investigation", icon: <ManageSearchOutlined />, elevatedOnly: true },
];

export const ACCOUNT_NAV: NavItemConfig[] = [
  { to: "/profile",  label: "Profile",  icon: <PersonOutlined /> },
  { to: "/settings", label: "Settings", icon: <SettingsOutlined />, elevatedOnly: true },
  { to: "/about",    label: "About",    icon: <InfoOutlined /> },
];

export const SECTIONS = [
  { label: "Primary",   items: PRIMARY_NAV },
  { label: "Workspace", items: WORKSPACE_NAV },
  { label: "Account",   items: ACCOUNT_NAV },
] as const;
