// src/layouts/AppLayout.tsx
import * as React from "react";
import {
  AppBar,
  Avatar,
  Box,
  Chip,
  Divider,
  Drawer,
  IconButton,
  List,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Stack,
  Toolbar,
  Tooltip,
  Typography,
  useMediaQuery,
} from "@mui/material";
import { alpha, useTheme } from "@mui/material/styles";
import {
  AssignmentTurnedInOutlined,
  CampaignOutlined,
  DashboardOutlined,
  HomeOutlined,
  InfoOutlined,
  LogoutOutlined,
  ManageSearchOutlined,
  MenuRounded,
  PersonOutline,
  PushPinOutlined,
  SettingsOutlined,
  UploadFileOutlined,
  ChevronRightOutlined,
} from "@mui/icons-material";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { getMe, logout, type Me } from "@/api/auth";
import { getAccessToken } from "@/api/client";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DRAWER_WIDE  = 256;
const DRAWER_SLIM  = 72;

// ---------------------------------------------------------------------------
// Nav item definitions
// ---------------------------------------------------------------------------

type NavItemConfig = {
  to: string;
  label: string;
  icon: React.ReactElement;
  elevatedOnly?: boolean;
};

const PRIMARY_NAV: NavItemConfig[] = [
  { to: "/",           label: "Home",           icon: <HomeOutlined /> },
  { to: "/submit",     label: "Submit",          icon: <UploadFileOutlined /> },
  { to: "/submissions",label: "My submissions",  icon: <AssignmentTurnedInOutlined /> },
];

const WORKSPACE_NAV: NavItemConfig[] = [
  { to: "/campaigns",    label: "Campaigns",     icon: <CampaignOutlined /> },
  { to: "/dashboard",    label: "Dashboard",     icon: <DashboardOutlined /> },
  { to: "/investigation",label: "Investigation", icon: <ManageSearchOutlined />, elevatedOnly: true },
];

const ACCOUNT_NAV: NavItemConfig[] = [
  { to: "/profile",  label: "Profile",  icon: <PersonOutline /> },
  { to: "/settings", label: "Settings", icon: <SettingsOutlined />, elevatedOnly: true },
  { to: "/about",    label: "About",    icon: <InfoOutlined /> },
];

const SECTIONS = [
  { label: "Primary",   items: PRIMARY_NAV },
  { label: "Workspace", items: WORKSPACE_NAV },
  { label: "Account",   items: ACCOUNT_NAV },
] as const;

function filterItems(items: NavItemConfig[], isElevated: boolean) {
  return items.filter((i) => !i.elevatedOnly || isElevated);
}

function getPageTitle(pathname: string, items: NavItemConfig[]) {
  return (
    items.find((i) => i.to !== "/" && pathname.startsWith(i.to))?.label ??
    items.find((i) => i.to === pathname)?.label ??
    "Workspace"
  );
}

// ---------------------------------------------------------------------------
// NavItem
// ---------------------------------------------------------------------------

function NavItem({
  to,
  label,
  icon,
  onClick,
  slim,
}: {
  to: string;
  label: string;
  icon: React.ReactElement;
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

          // ── Idle icon shell ─────────────────────────────────────────────
          "& .nav-icon": {
            width: 34,
            height: 34,
            borderRadius: 2,
            display: "grid",
            placeItems: "center",
            flexShrink: 0,
            border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.18 : 0.55)}`,
            background: isDark
              ? alpha("#fff", 0.025)
              : alpha(theme.palette.background.paper, 0.7),
            transition: theme.transitions.create(
              ["background", "border-color", "box-shadow"],
              { duration: 150 }
            ),
            "& svg": { fontSize: 18, transition: "color 150ms" },
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

          // ── Active ───────────────────────────────────────────────────────
          "&.active": {
            color: theme.palette.text.primary,
            background: isDark
              ? `linear-gradient(135deg, ${alpha(primary, 0.16)}, ${alpha(primary, 0.08)})`
              : `linear-gradient(135deg, ${alpha(primary, 0.1)}, ${alpha(primary, 0.05)})`,
            borderColor: alpha(primary, isDark ? 0.3 : 0.22),
            boxShadow: isDark
              ? `inset 0 1px 0 ${alpha("#fff", 0.06)}, 0 4px 12px ${alpha(primary, 0.14)}`
              : `inset 0 1px 0 ${alpha("#fff", 0.6)}, 0 4px 12px ${alpha(primary, 0.08)}`,
            "& .nav-icon": {
              borderColor: alpha(primary, isDark ? 0.32 : 0.26),
              background: alpha(primary, isDark ? 0.16 : 0.1),
              boxShadow: `0 0 0 3px ${alpha(primary, isDark ? 0.08 : 0.06)}`,
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

// ---------------------------------------------------------------------------
// NavSection
// ---------------------------------------------------------------------------

function NavSection({
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
        // slim: small divider with no label
        <Divider sx={{ mx: 1.5, mb: 1, opacity: isDark ? 0.15 : 0.35 }} />
      ) : (
        <Typography
          variant="overline"
          sx={{
            display: "block",
            px: 1.5,
            pb: 0.5,
            fontSize: 10,
            fontWeight: 800,
            letterSpacing: "0.12em",
            color: alpha(theme.palette.text.secondary, isDark ? 0.7 : 0.65),
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

// ---------------------------------------------------------------------------
// LogoutButton
// ---------------------------------------------------------------------------

function LogoutButton({
  slim,
  onLogout,
}: {
  slim: boolean;
  onLogout: () => void;
}) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";

  return (
    <Tooltip title={slim ? "Logout" : ""} placement="right" arrow>
      <ListItemButton
        onClick={onLogout}
        aria-label="Logout"
        sx={{
          minHeight: 44,
          borderRadius: 2.5,
          px: slim ? 0 : 1.25,
          py: 0.75,
          justifyContent: slim ? "center" : "flex-start",
          gap: slim ? 0 : 1.25,
          color: alpha(theme.palette.text.primary, isDark ? 0.65 : 0.7),
          border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.18 : 0.55)}`,
          background: isDark ? alpha("#fff", 0.025) : alpha(theme.palette.background.paper, 0.7),
          transition: theme.transitions.create(
            ["background", "border-color", "color"],
            { duration: 150 }
          ),

          "& .logout-icon": {
            width: 34,
            height: 34,
            borderRadius: 2,
            display: "grid",
            placeItems: "center",
            flexShrink: 0,
            border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.18 : 0.55)}`,
            background: "transparent",
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
        {!slim && (
          <Typography sx={{ fontSize: 13.5, fontWeight: 700, whiteSpace: "nowrap" }}>
            Logout
          </Typography>
        )}
      </ListItemButton>
    </Tooltip>
  );
}

// ---------------------------------------------------------------------------
// UserCard — bottom of sidebar
// ---------------------------------------------------------------------------

function UserCard({
  slim,
  me,
  isElevated,
  groups,
}: {
  slim: boolean;
  me: Me | undefined;
  isElevated: boolean;
  groups: string[];
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
          sx={{
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
          <Typography sx={{ fontWeight: 950, fontSize: 14, color: isElevated ? primary : "text.primary" }}>
            {initial}
          </Typography>
        </Box>
      </Tooltip>
    );
  }

  return (
    <Box
      sx={{
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
      {/* Avatar with elevation ring */}
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
        <Avatar
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
        >
          {initial}
        </Avatar>
      </Box>

      {/* Name + role */}
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
        <Stack direction="row" spacing={0.5} alignItems="center">
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

// ---------------------------------------------------------------------------
// AppLayout
// ---------------------------------------------------------------------------

export default function AppLayout() {
  const theme = useTheme();
  const navigate = useNavigate();
  const location = useLocation();
  const queryClient = useQueryClient();
  const isDesktop = useMediaQuery(theme.breakpoints.up("md"));
  const isDark = theme.palette.mode === "dark";
  const primary = theme.palette.primary.main;

  const token = getAccessToken();

  const meQuery = useQuery<Me>({
    queryKey: ["me"],
    queryFn: getMe,
    retry: false,
    enabled: !!token,
  });

  const me = meQuery.data;
  const groups: string[] = (me as any)?.groups ?? [];
  const isElevated = groups.includes("CISO") || groups.includes("CERT") || groups.includes("Admin");

  const [mobileOpen, setMobileOpen] = React.useState(false);
  const [hovered,    setHovered]    = React.useState(false);
  const [pinned,     setPinned]     = React.useState(false);

  // Close mobile drawer on navigation
  React.useEffect(() => { setMobileOpen(false); }, [location.pathname]);
  React.useEffect(() => { if (!isDesktop) setHovered(false); }, [isDesktop]);

  // Filtered nav items
  const primaryItems   = React.useMemo(() => filterItems(PRIMARY_NAV,   isElevated), [isElevated]);
  const workspaceItems = React.useMemo(() => filterItems(WORKSPACE_NAV, isElevated), [isElevated]);
  const accountItems   = React.useMemo(() => filterItems(ACCOUNT_NAV,   isElevated), [isElevated]);

  const allItems = React.useMemo(
    () => [...primaryItems, ...workspaceItems, ...accountItems],
    [primaryItems, workspaceItems, accountItems]
  );

  const pageTitle = getPageTitle(location.pathname, allItems);

  const isSlim = isDesktop && !pinned && !hovered;
  const drawerW = isDesktop ? (isSlim ? DRAWER_SLIM : DRAWER_WIDE) : DRAWER_WIDE;

  async function handleLogout() {
    try { await logout(); } finally {
      queryClient.removeQueries({ queryKey: ["me"] });
      navigate("/login", { replace: true });
    }
  }

  // ── Sidebar background — fully theme-aware ──────────────────────────────
  const sidebarBg = isDark
    ? `radial-gradient(ellipse 140% 60% at 0% 0%, ${alpha(primary, 0.1)}, transparent 55%),
       radial-gradient(ellipse 100% 40% at 100% 100%, ${alpha(primary, 0.06)}, transparent 50%),
       linear-gradient(180deg, ${alpha(theme.palette.background.paper, 0.97)}, ${alpha(theme.palette.background.default, 0.99)})`
    : `radial-gradient(ellipse 140% 60% at 0% 0%, ${alpha(primary, 0.07)}, transparent 55%),
       radial-gradient(ellipse 100% 40% at 100% 100%, ${alpha(primary, 0.04)}, transparent 50%),
       linear-gradient(180deg, ${alpha("#fff", 0.98)}, ${alpha(theme.palette.grey[50], 0.99)})`;

  // ── Shell background ─────────────────────────────────────────────────────
  const shellBg = isDark
    ? `radial-gradient(ellipse 80% 50% at 15% 5%, ${alpha(primary, 0.07)}, transparent 50%),
       ${theme.palette.background.default}`
    : `radial-gradient(ellipse 80% 50% at 15% 5%, ${alpha(primary, 0.05)}, transparent 50%),
       ${theme.palette.background.default}`;

  // ── Sidebar border ───────────────────────────────────────────────────────
  const sidebarBorder = `1px solid ${alpha(theme.palette.divider, isDark ? 0.28 : 0.85)}`;

  // ─────────────────────────────────────────────────────────────────────────
  // Drawer content
  // ─────────────────────────────────────────────────────────────────────────

  const drawerContent = (
    <Box
      sx={{
        height: "100%",
        display: "flex",
        flexDirection: "column",
        background: sidebarBg,
        overflowX: "hidden",
      }}
    >
      {/* ── Logo + pin ─────────────────────────────────────────────────── */}
      <Box
        sx={{
          px: isSlim ? 1 : 1.75,
          pt: 1.75,
          pb: 1.5,
          display: "flex",
          alignItems: "center",
          justifyContent: isSlim ? "center" : "space-between",
          minHeight: 68,
        }}
      >
        {/* Brand */}
        <Stack direction="row" spacing={isSlim ? 0 : 1.25} alignItems="center">
          <Avatar
            variant="rounded"
            src="/icons/suspicious-logo.png"
            alt="Suspicious"
            sx={{
              width: 36,
              height: 36,
              borderRadius: 2,
              flexShrink: 0,
              border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.22 : 0.6)}`,
              "& img": { objectFit: "contain" },
            }}
          />

          {!isSlim && (
            <Box>
              <Typography
                sx={{
                  fontWeight: 950,
                  fontSize: 15,
                  letterSpacing: "-0.03em",
                  lineHeight: 1.1,
                  color: "text.primary",
                }}
              >
                Suspicious
              </Typography>

            </Box>
          )}
        </Stack>

        {/* Pin button — only in wide mode on desktop */}
        {!isSlim && isDesktop && (
          <Tooltip title={pinned ? "Unpin sidebar" : "Pin sidebar"} placement="right">
            <IconButton
              size="small"
              onClick={() => setPinned((p) => !p)}
              aria-label={pinned ? "Unpin sidebar" : "Pin sidebar"}
              sx={{
                width: 28,
                height: 28,
                borderRadius: 2,
                border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.28 : 0.65)}`,
                background: pinned
                  ? alpha(primary, isDark ? 0.14 : 0.1)
                  : alpha(theme.palette.text.primary, isDark ? 0.03 : 0.02),
                color: pinned ? primary : alpha(theme.palette.text.primary, 0.55),
                "&:hover": {
                  background: pinned
                    ? alpha(primary, isDark ? 0.2 : 0.15)
                    : alpha(theme.palette.text.primary, isDark ? 0.06 : 0.04),
                },
              }}
            >
              <PushPinOutlined
                sx={{
                  fontSize: 15,
                  transform: pinned ? "rotate(0deg)" : "rotate(45deg)",
                  transition: "transform 200ms ease",
                }}
              />
            </IconButton>
          </Tooltip>
        )}
      </Box>

      <Divider sx={{ borderColor: alpha(theme.palette.divider, isDark ? 0.22 : 0.7) }} />

      {/* ── Nav sections ───────────────────────────────────────────────── */}
      <Box
        component="nav"
        aria-label="Primary navigation"
        sx={{ flex: 1, overflowY: "auto", overflowX: "hidden", py: 1.5, px: 0.5 }}
      >
        <Stack spacing={isSlim ? 0.5 : 1.5}>
          <NavSection
            label="Primary"
            items={primaryItems}
            slim={isSlim}
            onNavigate={!isDesktop ? () => setMobileOpen(false) : undefined}
          />
          <NavSection
            label="Workspace"
            items={workspaceItems}
            slim={isSlim}
            onNavigate={!isDesktop ? () => setMobileOpen(false) : undefined}
          />
          <NavSection
            label="Account"
            items={accountItems}
            slim={isSlim}
            onNavigate={!isDesktop ? () => setMobileOpen(false) : undefined}
          />
        </Stack>
      </Box>

      {/* ── Footer: user card + logout ─────────────────────────────────── */}
      <Box
        sx={{
          px: isSlim ? 1 : 1.25,
          pt: 1,
          pb: 1.5,
        }}
      >
        <Divider sx={{ mb: 1.25, borderColor: alpha(theme.palette.divider, isDark ? 0.22 : 0.7) }} />

        <Stack spacing={0.75}>
          {/* User identity */}
          <UserCard slim={isSlim} me={me} isElevated={isElevated} groups={groups} />

          {/* Logout */}
          <List disablePadding>
            <LogoutButton slim={isSlim} onLogout={handleLogout} />
          </List>
        </Stack>
      </Box>
    </Box>
  );

  // ─────────────────────────────────────────────────────────────────────────
  // Render
  // ─────────────────────────────────────────────────────────────────────────

  return (
    <Box sx={{ display: "flex", minHeight: "100vh", background: shellBg }}>

      {/* ── Mobile top AppBar ─────────────────────────────────────────── */}
      <AppBar
        position="fixed"
        elevation={0}
        color="transparent"
        sx={{
          display: { xs: "flex", md: "none" },
          zIndex: (t) => t.zIndex.drawer + 1,
          backdropFilter: "blur(20px)",
          WebkitBackdropFilter: "blur(20px)",
          background: isDark
            ? alpha(theme.palette.background.paper, 0.75)
            : alpha(theme.palette.background.paper, 0.85),
          borderBottom: `1px solid ${alpha(theme.palette.divider, isDark ? 0.25 : 0.75)}`,
          boxShadow: isDark
            ? `0 4px 24px ${alpha("#000", 0.3)}`
            : `0 4px 24px ${alpha(theme.palette.primary.main, 0.06)}`,
        }}
      >
        <Toolbar sx={{ minHeight: 60, px: 2 }}>
          <Stack
            direction="row"
            alignItems="center"
            justifyContent="space-between"
            sx={{ width: "100%" }}
          >
            <IconButton
              edge="start"
              aria-label="Open navigation"
              onClick={() => setMobileOpen(true)}
              sx={{
                width: 36,
                height: 36,
                borderRadius: 2,
                border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.25 : 0.65)}`,
                background: alpha(theme.palette.text.primary, isDark ? 0.04 : 0.02),
                "&:hover": {
                  background: alpha(theme.palette.text.primary, isDark ? 0.08 : 0.05),
                },
              }}
            >
              <MenuRounded sx={{ fontSize: 20 }} />
            </IconButton>

            <Typography sx={{ fontWeight: 850, fontSize: 15, letterSpacing: "-0.02em" }}>
              {pageTitle}
            </Typography>

            {/* Right spacer to balance the hamburger */}
            <Box sx={{ width: 36 }} />
          </Stack>
        </Toolbar>
      </AppBar>

      {/* ── Sidebar ───────────────────────────────────────────────────── */}
      <Box
        component="aside"
        aria-label="Sidebar navigation"
        onMouseEnter={isDesktop && !pinned ? () => setHovered(true)  : undefined}
        onMouseLeave={isDesktop && !pinned ? () => setHovered(false) : undefined}
        sx={{
          width: { md: drawerW },
          flexShrink: { md: 0 },
          transition: theme.transitions.create("width", {
            duration: theme.transitions.duration.standard,
            easing: theme.transitions.easing.easeInOut,
          }),
        }}
      >
        {/* Mobile: temporary drawer */}
        {!isDesktop ? (
          <Drawer
            variant="temporary"
            open={mobileOpen}
            onClose={() => setMobileOpen(false)}
            ModalProps={{ keepMounted: true }}
            PaperProps={{
              sx: {
                width: DRAWER_WIDE,
                border: "none",
                borderRight: sidebarBorder,
                background: "transparent",
                boxShadow: isDark
                  ? `4px 0 40px ${alpha("#000", 0.45)}`
                  : `4px 0 40px ${alpha(primary, 0.08)}`,
              },
            }}
          >
            {drawerContent}
          </Drawer>
        ) : (
          /* Desktop: permanent drawer with animated width */
          <Drawer
            variant="permanent"
            open
            PaperProps={{
              sx: {
                width: drawerW,
                overflowX: "hidden",
                border: "none",
                borderRight: sidebarBorder,
                background: "transparent",
                boxShadow: "none",
                transition: theme.transitions.create("width", {
                  duration: theme.transitions.duration.standard,
                  easing: theme.transitions.easing.easeInOut,
                }),
              },
            }}
          >
            {drawerContent}
          </Drawer>
        )}
      </Box>

      {/* ── Main content ──────────────────────────────────────────────── */}
      <Box
        component="main"
        sx={{
          flexGrow: 1,
          minWidth: 0,
          width: { md: `calc(100% - ${drawerW}px)` },
          transition: theme.transitions.create(["width"], {
            duration: theme.transitions.duration.standard,
            easing: theme.transitions.easing.easeInOut,
          }),
        }}
      >
        {/* Spacer for mobile AppBar */}
        <Box sx={{ height: { xs: 60, md: 0 } }} />

        <Box
          sx={{
            px: { xs: 2, md: isSlim ? 5 : 3 },
            py: { xs: 2, md: 3 },
            maxWidth: { md: isSlim ? 1600 : 1440 },
            mx: "auto",
            width: "100%",
            transition: theme.transitions.create(["max-width", "padding"], {
              duration: theme.transitions.duration.standard,
              easing: theme.transitions.easing.easeInOut,
            }),
          }}
        >
          <Outlet />
        </Box>
      </Box>
    </Box>
  );
}