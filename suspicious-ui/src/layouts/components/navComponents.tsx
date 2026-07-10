import type { ReactElement } from "react";
import {
  Box,
  Divider,
  List,
  ListItemButton,
  Stack,
  Tooltip,
  Typography,
} from "@mui/material";
import { alpha, useTheme } from "@mui/material/styles";
import { HelpOutlineOutlined, LogoutOutlined } from "@mui/icons-material";
import { NavLink } from "react-router-dom";

import type { Me } from "@/api/auth";
import type { NavItemConfig } from "@/layouts/nav";
import { useHelpTour } from "@/features/help/useHelpTour";
import { UserAvatar } from "@/features/profile/components/UserAvatar";
import type { AvatarConfig } from "@/features/profile/avatar";

export function NavItem({
  to,
  label,
  icon,
  onClick,
  slim,
}: {
  to: string;
  label: string;
  icon: ReactElement;
  onClick?: () => void;
  slim: boolean;
}) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  const primary = theme.palette.primary.main;

  return (
    <Tooltip title={slim ? label : ""} placement="right" arrow>
      <ListItemButton
        component={NavLink}
        to={to}
        onClick={onClick}
        aria-label={label}
        sx={{
          minHeight: 44,
          borderRadius: 2.5,
          px: slim ? 0 : 1.25,
          py: 0.75,
          mb: 0.35,
          justifyContent: slim ? "center" : "flex-start",
          gap: slim ? 0 : 1.25,
          color: alpha(theme.palette.text.primary, isDark ? 0.72 : 0.75),
          border: "1px solid transparent",
          transition: theme.transitions.create(
            ["background", "border-color", "color", "transform", "box-shadow"],
            { duration: 150 }
          ),

          // ── Idle icon shell — matches SoftCard divider/bg system ────────
          "& .nav-icon": {
            width: 32,
            height: 32,
            borderRadius: 2,
            display: "grid",
            placeItems: "center",
            flexShrink: 0,
            border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.22 : 0.65)}`,
            background: isDark
              ? alpha("#fff", 0.03)
              : alpha(theme.palette.background.paper, 0.8),
            transition: theme.transitions.create(
              ["background", "border-color", "box-shadow"],
              { duration: 150 }
            ),
            "& svg": { fontSize: 17, transition: "color 150ms" },
          },

          // ── Label ────────────────────────────────────────────────────────
          "& .nav-label": {
            fontSize: 13.5,
            fontWeight: 700,
            letterSpacing: "-0.01em",
            whiteSpace: "nowrap",
            opacity: slim ? 0 : 1,
            maxWidth: slim ? 0 : 160,
            overflow: "hidden",
            transition: theme.transitions.create(["opacity", "max-width"], { duration: 200 }),
          },

          // ── Hover ────────────────────────────────────────────────────────
          "&:hover": {
            color: theme.palette.text.primary,
            background: alpha(primary, isDark ? 0.07 : 0.06),
            borderColor: alpha(primary, isDark ? 0.2 : 0.18),
            transform: slim ? "none" : "translateX(2px)",
            "& .nav-icon": {
              borderColor: alpha(primary, isDark ? 0.28 : 0.25),
              background: alpha(primary, isDark ? 0.1 : 0.08),
              "& svg": { color: primary },
            },
          },

          // ── Active — SoftCard glassmorphism treatment ────────────────────
          "&.active": {
            color: theme.palette.text.primary,
            background: isDark
              ? `linear-gradient(135deg, ${alpha(primary, 0.14)}, ${alpha(primary, 0.07)})`
              : `linear-gradient(135deg, ${alpha(primary, 0.09)}, ${alpha(primary, 0.04)})`,
            borderColor: alpha(primary, isDark ? 0.28 : 0.2),
            boxShadow: isDark
              ? `0 2px 8px ${alpha(primary, 0.12)}`
              : `0 2px 8px ${alpha(primary, 0.06)}`,
            "& .nav-icon": {
              borderColor: alpha(primary, isDark ? 0.32 : 0.25),
              background: isDark
                ? alpha(primary, 0.15)
                : `linear-gradient(135deg, ${alpha(primary, 0.12)}, ${alpha(primary, 0.06)})`,
              "& svg": { color: primary },
            },
          },

          "&:focus-visible": {
            outline: `2px solid ${alpha(primary, 0.7)}`,
            outlineOffset: 2,
          },
        }}
      >
        <Box className="nav-icon">{icon}</Box>
        {!slim && (
          <Typography className="nav-label" component="span">
            {label}
          </Typography>
        )}
      </ListItemButton>
    </Tooltip>
  );
}

export function NavSection({
  label,
  items,
  slim,
  onNavigate,
}: {
  label: string;
  items: NavItemConfig[];
  slim: boolean;
  onNavigate?: () => void;
}) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";

  return (
    <Box component="section">
      {slim ? (
        <Divider sx={{ mx: 1.5, mb: 1, opacity: isDark ? 0.15 : 0.35 }} />
      ) : (
        <Typography
          variant="overline"
          sx={{
            display: "block",
            px: 1.75,
            pb: 0.4,
            pt: 0.2,
            fontSize: 9.5,
            fontWeight: 700,
            letterSpacing: "0.1em",
            color: alpha(theme.palette.text.secondary, isDark ? 0.55 : 0.5),
          }}
        >
          {label}
        </Typography>
      )}

      <List disablePadding sx={{ px: 0.5 }}>
        {items.map((item) => (
          <NavItem
            key={item.to}
            to={item.to}
            label={item.label}
            icon={item.icon}
            onClick={onNavigate}
            slim={slim}
          />
        ))}
      </List>
    </Box>
  );
}

export function LogoutButton({ slim, onLogout }: { slim: boolean; onLogout: () => void }) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";

  if (slim) {
    return (
      <Tooltip title="Logout" placement="right" arrow>
        <Box
          onClick={onLogout}
          role="button"
          tabIndex={0}
          aria-label="Logout"
          onKeyDown={(e) => {
            if (e.key === "Enter" || e.key === " ") {
              e.preventDefault();
              onLogout();
            }
          }}
          sx={{
            cursor: "pointer",
            width: 38,
            height: 38,
            borderRadius: 2.5,
            display: "grid",
            placeItems: "center",
            mx: "auto",
            color: alpha(theme.palette.text.primary, isDark ? 0.7 : 0.75),
            border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.22 : 0.6)}`,
            background: isDark
              ? alpha("#fff", 0.03)
              : alpha(theme.palette.background.paper, 0.8),
            transition: theme.transitions.create(
              ["background", "border-color", "color"],
              { duration: 150 }
            ),
            "&:hover": {
              color: theme.palette.error.main,
              borderColor: alpha(theme.palette.error.main, isDark ? 0.28 : 0.22),
              background: alpha(theme.palette.error.main, isDark ? 0.12 : 0.09),
            },
            "&:focus-visible": {
              outline: `2px solid ${alpha(theme.palette.error.main, 0.6)}`,
              outlineOffset: 2,
            },
          }}
        >
          <LogoutOutlined sx={{ fontSize: 18 }} />
        </Box>
      </Tooltip>
    );
  }

  return (
    <ListItemButton
      onClick={onLogout}
      aria-label="Logout"
      sx={{
        minHeight: 44,
        borderRadius: 2.5,
        px: 1.25,
        py: 0.75,
        gap: 1.25,
        color: alpha(theme.palette.text.primary, isDark ? 0.65 : 0.7),
        border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.18 : 0.55)}`,
        background: isDark
          ? alpha("#fff", 0.025)
          : alpha(theme.palette.background.paper, 0.7),
        transition: theme.transitions.create(
          ["background", "border-color", "color"],
          { duration: 150 }
        ),

        "& .logout-icon": {
          width: 38,
          height: 38,
          borderRadius: 2.5,
          display: "grid",
          placeItems: "center",
          flexShrink: 0,
          border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.22 : 0.6)}`,
          background: isDark ? alpha("#fff", 0.03) : alpha(theme.palette.background.paper, 0.8),
          transition: theme.transitions.create(["background", "border-color"], { duration: 150 }),
          "& svg": { fontSize: 18 },
        },

        "&:hover": {
          color: theme.palette.error.main,
          background: alpha(theme.palette.error.main, isDark ? 0.09 : 0.07),
          borderColor: alpha(theme.palette.error.main, isDark ? 0.22 : 0.2),
          "& .logout-icon": {
            borderColor: alpha(theme.palette.error.main, isDark ? 0.28 : 0.22),
            background: alpha(theme.palette.error.main, isDark ? 0.12 : 0.09),
          },
        },

        "&:focus-visible": {
          outline: `2px solid ${alpha(theme.palette.error.main, 0.6)}`,
          outlineOffset: 2,
        },
      }}
    >
      <Box className="logout-icon">
        <LogoutOutlined />
      </Box>
      <Typography sx={{ fontSize: 13.5, fontWeight: 700, whiteSpace: "nowrap" }}>
        Logout
      </Typography>
    </ListItemButton>
  );
}

export function HelpButton({ slim }: { slim: boolean }) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  const { start } = useHelpTour();

  if (slim) {
    return (
      <Tooltip title="Help" placement="right" arrow>
        <Box
          data-tour="help"
          onClick={start}
          role="button"
          tabIndex={0}
          aria-label="Help"
          onKeyDown={(e) => {
            if (e.key === "Enter" || e.key === " ") { e.preventDefault(); start(); }
          }}
          sx={{
            cursor: "pointer", width: 38, height: 38, borderRadius: 2.5,
            display: "grid", placeItems: "center", mx: "auto",
            color: alpha(theme.palette.text.primary, isDark ? 0.7 : 0.75),
            border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.22 : 0.6)}`,
            background: isDark ? alpha("#fff", 0.03) : alpha(theme.palette.background.paper, 0.8),
            transition: theme.transitions.create(["background", "border-color", "color"], { duration: 150 }),
            "&:hover": {
              color: theme.palette.primary.main,
              borderColor: alpha(theme.palette.primary.main, isDark ? 0.28 : 0.22),
              background: alpha(theme.palette.primary.main, isDark ? 0.12 : 0.09),
            },
            "&:focus-visible": { outline: `2px solid ${alpha(theme.palette.primary.main, 0.6)}`, outlineOffset: 2 },
          }}
        >
          <HelpOutlineOutlined sx={{ fontSize: 18 }} />
        </Box>
      </Tooltip>
    );
  }

  return (
    <ListItemButton
      data-tour="help"
      onClick={start}
      aria-label="Help"
      sx={{
        minHeight: 44, borderRadius: 2.5, px: 1.25, py: 0.75, gap: 1.25,
        color: alpha(theme.palette.text.primary, isDark ? 0.65 : 0.7),
        border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.18 : 0.55)}`,
        background: isDark ? alpha("#fff", 0.025) : alpha(theme.palette.background.paper, 0.7),
        transition: theme.transitions.create(["background", "border-color", "color"], { duration: 150 }),
        "& .help-icon": {
          width: 38, height: 38, borderRadius: 2.5, display: "grid", placeItems: "center", flexShrink: 0,
          border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.22 : 0.6)}`,
          background: isDark ? alpha("#fff", 0.03) : alpha(theme.palette.background.paper, 0.8),
          "& svg": { fontSize: 18 },
        },
        "&:hover": {
          color: theme.palette.primary.main,
          background: alpha(theme.palette.primary.main, isDark ? 0.09 : 0.07),
          borderColor: alpha(theme.palette.primary.main, isDark ? 0.22 : 0.2),
          "& .help-icon": {
            borderColor: alpha(theme.palette.primary.main, isDark ? 0.28 : 0.22),
            background: alpha(theme.palette.primary.main, isDark ? 0.12 : 0.09),
          },
        },
        "&:focus-visible": { outline: `2px solid ${alpha(theme.palette.primary.main, 0.6)}`, outlineOffset: 2 },
      }}
    >
      <Box className="help-icon"><HelpOutlineOutlined /></Box>
      <Typography sx={{ fontSize: 13.5, fontWeight: 700, whiteSpace: "nowrap" }}>Help</Typography>
    </ListItemButton>
  );
}

export function UserCard({
  slim,
  me,
  avatar,
  isElevated,
  groups,
  onClick,
}: {
  slim: boolean;
  me: Me | undefined;
  avatar?: AvatarConfig | null;
  isElevated: boolean;
  groups: string[];
  onClick?: () => void;
}) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  const primary = theme.palette.primary.main;

  const initial = (me?.username?.[0] ?? "U").toUpperCase();
  const displayName = [me?.first_name, me?.last_name].filter(Boolean).join(" ") || me?.username || "User";
  const roleLabel = isElevated ? groups.filter((g) => ["CISO","CERT","Admin"].includes(g)).join(" · ") || "Elevated" : "Standard";

  if (slim) {
    return (
      <Tooltip title={displayName} placement="right" arrow>
        <Box
          onClick={onClick}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => {
            if (e.key === "Enter" || e.key === " ") onClick?.();
          }}
          sx={{
            cursor: onClick ? "pointer" : "default",
            width: 38,
            height: 38,
            borderRadius: 2.5,
            display: "grid",
            placeItems: "center",
            mx: "auto",
            background: isElevated
              ? alpha(primary, isDark ? 0.18 : 0.12)
              : alpha(theme.palette.text.primary, isDark ? 0.06 : 0.04),
            border: `1px solid ${isElevated
              ? alpha(primary, isDark ? 0.32 : 0.25)
              : alpha(theme.palette.divider, isDark ? 0.22 : 0.6)
            }`,
          }}
        >
          <UserAvatar avatar={avatar} initials={initial} sx={{ width: 30, height: 30, fontSize: 14, fontWeight: 950, bgcolor: "transparent", color: isElevated ? primary : "text.primary" }} />
        </Box>
      </Tooltip>
    );
  }

  return (
    <Box
      onClick={onClick}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") onClick?.();
      }}
      sx={{
        cursor: onClick ? "pointer" : "default",
        px: 1.25,
        py: 1,
        borderRadius: 2.5,
        border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.18 : 0.6)}`,
        background: isDark
          ? alpha("#fff", 0.03)
          : alpha(theme.palette.background.paper, 0.7),
        display: "flex",
        alignItems: "center",
        gap: 1.25,
      }}
    >
      <Box sx={{ position: "relative", flexShrink: 0 }}>
        {isElevated && (
          <Box
            sx={{
              position: "absolute",
              inset: -1.5,
              borderRadius: 99,
              background: `conic-gradient(${primary}, ${alpha(primary, 0.3)}, ${primary})`,
              zIndex: 0,
            }}
          />
        )}
        <UserAvatar
          avatar={avatar}
          initials={initial}
          sx={{
            width: 32,
            height: 32,
            fontSize: 13,
            fontWeight: 950,
            position: "relative",
            zIndex: 1,
            bgcolor: isElevated
              ? alpha(primary, isDark ? 0.2 : 0.12)
              : alpha(theme.palette.text.primary, isDark ? 0.07 : 0.05),
            color: isElevated ? primary : "text.primary",
            border: `1.5px solid ${isDark ? alpha("#0f172a", 0.9) : alpha("#fff", 0.9)}`,
          }}
        />
      </Box>

      <Box sx={{ flex: 1, minWidth: 0 }}>
        <Typography
          sx={{
            fontWeight: 800,
            fontSize: 13,
            lineHeight: 1.2,
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
          }}
        >
          {displayName}
        </Typography>
        <Stack direction="row" spacing={0.5} sx={{ alignItems: "center" }} >
          <Box
            sx={{
              width: 5,
              height: 5,
              borderRadius: 99,
              bgcolor: isElevated ? primary : alpha(theme.palette.text.secondary, 0.5),
              flexShrink: 0,
            }}
          />
          <Typography
            variant="caption"
            sx={{
              fontSize: 11,
              color: isElevated ? primary : "text.secondary",
              fontWeight: isElevated ? 700 : 500,
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
          >
            {roleLabel}
          </Typography>
        </Stack>
      </Box>
    </Box>
  );
}
