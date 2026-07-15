import EmailOutlined from "@mui/icons-material/EmailOutlined";
import ExtensionOutlined from "@mui/icons-material/ExtensionOutlined";
import HubOutlined from "@mui/icons-material/HubOutlined";
import ShareOutlined from "@mui/icons-material/ShareOutlined";
import VisibilityOutlined from "@mui/icons-material/VisibilityOutlined";
import type { SvgIconProps } from "@mui/material";
import type { ComponentType } from "react";

export type ConnectorIconType = ComponentType<SvgIconProps>;

export const CONNECTOR_ICONS: Record<string, ConnectorIconType> = {
  thehive: HubOutlined,
  misp: ShareOutlined,
  watcher: VisibilityOutlined,
  smtp_notify: EmailOutlined,
};

export const DEFAULT_CONNECTOR_ICON: ConnectorIconType = ExtensionOutlined;
