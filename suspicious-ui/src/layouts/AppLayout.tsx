import * as React from "react";
import {
  AppBar,
  Avatar,
  Box,
  Chip,
  Divider,
  Drawer,
  IconButton,
  Stack,
  Toolbar,
  Tooltip,
  Typography,
  useMediaQuery,
} from "@mui/material";
import { alpha, useTheme } from "@mui/material/styles";
import {
  ChevronRightOutlined,
  MenuRounded,
  PushPinOutlined,
} from "@mui/icons-material";
import { Outlet, useLocation, useNavigate } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { getMe, logout, type Me } from "@/api/auth";
import { getProfile, updatePreferences } from "@/features/profile/api";
import { useThemeMode } from "@/styles/ThemeStore";

import {
  DRAWER_SLIM,
  DRAWER_WIDE,
  filterItems,
  getPageTitle,
  type NavItemConfig,
} from "@/layouts/nav";
import { ACCOUNT_NAV, PRIMARY_NAV, SECTIONS, WORKSPACE_NAV } from "@/layouts/navConfig";
import { HelpButton, LogoutButton, NavItem, NavSection, UserCard } from "@/layouts/components/navComponents";
import { HelpTourProvider } from "@/features/help/HelpTourProvider";

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

  const meQuery = useQuery<Me>({
    queryKey: ["me"],
    queryFn: getMe,
    retry: false,
  });

  const me = meQuery.data;
  const profileQuery = useQuery({
    queryKey: ["profile"],
    queryFn: getProfile,
    enabled: !!me,
    retry: false,
  });
  const groups: string[] = (me as any)?.groups ?? [];
  const isElevated = groups.includes("CISO") || groups.includes("CERT") || groups.includes("Admin");

  const [mobileOpen, setMobileOpen] = React.useState(false);
  const [hovered,    setHovered]    = React.useState(false);

  const { capabilities } = useThemeMode();
  const { effects } = capabilities;

  const logoClass = React.useMemo(() => {
    if (effects.hasHeatEffect)     return "sun-orb";
    if (effects.hasSeasonalLights) return "christmas-lights";
    if (effects.hasBloomEffect)    return "dew-pulse";
    if (effects.hasEmberEffect)    return "leaf-sway";
    if (effects.hasPortalEffect)   return "fennec";
    return undefined;
  }, [effects]);

  const brandClass = effects.hasPortalEffect ? "temporal-glitch" : undefined;

  const sidebarGlow = React.useMemo(() => {
    if (effects.hasNeonEffect)
      return `4px 0 40px rgba(0,0,0,.6), 0 0 28px rgba(0,229,255,.07), inset -1px 0 0 rgba(0,229,255,.18)`;
    if (effects.hasSolarEffect)
      return `4px 0 40px rgba(0,0,0,.5), 0 0 28px rgba(201,164,76,.08), inset -1px 0 0 rgba(201,164,76,.2)`;
    if (effects.hasContaminationEffect)
      return `4px 0 40px rgba(0,0,0,.6), 0 0 20px rgba(92,184,92,.05), inset -1px 0 0 rgba(92,184,92,.15)`;
    return undefined;
  }, [effects]);

  const [pinned, setPinned] = React.useState<boolean>(() => {
    try { return localStorage.getItem("suspicious.sidebar.pinned") === "1"; }
    catch { return false; }
  });

  React.useEffect(() => {
    try { localStorage.setItem("suspicious.sidebar.pinned", pinned ? "1" : "0"); }
    catch { /* localStorage blocked in this env */ }
  }, [pinned]);

  // localStorage is browser-scoped and gets wiped when the app runs inside a
  // portal iframe with storage partitioning — the profile field is the
  // source of truth once it loads, same as theme/colors.
  const hydratedPinFromServer = React.useRef(false);
  React.useEffect(() => {
    if (hydratedPinFromServer.current) return;
    if (profileQuery.data?.sidebar_pinned === undefined) return;
    hydratedPinFromServer.current = true;
    setPinned(profileQuery.data.sidebar_pinned);
  }, [profileQuery.data]);

  function togglePinned() {
    setPinned((p) => {
      const next = !p;
      updatePreferences({ sidebar_pinned: next }).catch(() => {
        /* best-effort — localStorage still covers this browser */
      });
      return next;
    });
  }

  const [prevPathname, setPrevPathname] = React.useState(location.pathname);
  if (location.pathname !== prevPathname) {
    setPrevPathname(location.pathname);
    setMobileOpen(false);
  }

  const [prevIsDesktop, setPrevIsDesktop] = React.useState(isDesktop);
  if (isDesktop !== prevIsDesktop) {
    setPrevIsDesktop(isDesktop);
    if (!isDesktop) setHovered(false);
  }

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
    ? `linear-gradient(180deg, ${alpha("#fff", 0.04)} 0%, ${alpha("#fff", 0.02)} 100%)`
    : `linear-gradient(180deg, ${alpha("#fff", 0.92)} 0%, ${alpha(theme.palette.grey[50], 0.97)} 100%)`;

  // ── Shell background ─────────────────────────────────────────────────────
  const shellBg = isDark
    ? `radial-gradient(ellipse 80% 50% at 15% 5%, ${alpha(primary, 0.07)}, transparent 50%),
       ${theme.palette.background.default}`
    : `radial-gradient(ellipse 80% 50% at 15% 5%, ${alpha(primary, 0.05)}, transparent 50%),
       ${theme.palette.background.default}`;

  // ── Sidebar border ───────────────────────────────────────────────────────
  const sidebarBorder = `1px solid ${alpha(theme.palette.divider, isDark ? 0.28 : 0.9)}`;

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
          px: isSlim ? 1 : 1.5,
          pt: 1.5,
          pb: 1.25,
          display: "flex",
          alignItems: "center",
          justifyContent: isSlim ? "center" : "space-between",
          minHeight: 68,
        }}
      >
        <Stack direction="row" spacing={isSlim ? 0 : 1.25} sx={{ alignItems: "center" }} >
          <Avatar
            variant="rounded"
            src="/icons/suspicious-logo.png"
            alt="Suspicious"
            className={logoClass}
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
                className={brandClass}
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

        {!isSlim && isDesktop && (
          <Tooltip title={pinned ? "Unpin sidebar" : "Pin sidebar"} placement="right">
            <IconButton
              size="small"
              onClick={togglePinned}
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
        data-tour="nav-primary"
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
          <Box data-tour="nav-workspace">
            <NavSection
              label="Workspace"
              items={workspaceItems}
              slim={isSlim}
              onNavigate={!isDesktop ? () => setMobileOpen(false) : undefined}
            />
          </Box>
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
        <Divider
          sx={{
            mb: 1.25,
            borderColor: alpha(theme.palette.divider, isDark ? 0.22 : 0.7),
          }}
        />
      
        <Stack spacing={0.75} sx={{ alignItems: isSlim ? "center" : "stretch" }}>
          <Box data-tour="user-card" sx={{ width: isSlim ? "auto" : "100%" }}>
            <UserCard
              slim={isSlim}
              me={me}
              avatar={profileQuery.data?.avatar}
              isElevated={isElevated}
              groups={groups}
              onClick={() => navigate("/profile")}
            />
          </Box>
          <HelpButton slim={isSlim} />
          <LogoutButton slim={isSlim} onLogout={handleLogout} />
        </Stack>
      </Box>
    </Box>
  );

  // ─────────────────────────────────────────────────────────────────────────
  // Render
  // ─────────────────────────────────────────────────────────────────────────

  return (
    <HelpTourProvider>
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
            sx={{ width: "100%", alignItems: "center", justifyContent: "space-between" }}
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
        {!isDesktop ? (
          <Drawer
            variant="temporary"
            open={mobileOpen}
            onClose={() => setMobileOpen(false)}
            slotProps={{
              root: { keepMounted: true },
              paper: {
                sx: {
                  width: DRAWER_WIDE,
                  border: "none",
                  borderRight: sidebarBorder,
                  background: "transparent",
                  boxShadow: isDark
                    ? `4px 0 40px ${alpha("#000", 0.45)}`
                    : `4px 0 40px ${alpha(primary, 0.08)}`,
                },
              },
            }}
          >
            {drawerContent}
          </Drawer>
        ) : (
          <Drawer
            variant="permanent"
            open
            slotProps={{
              paper: {
                sx: {
                  width: drawerW,
                  overflowX: "hidden",
                  border: "none",
                  borderRight: sidebarBorder,
                  background: "transparent",
                  boxShadow: sidebarGlow ?? "none",
                  transition: theme.transitions.create("width", {
                    duration: theme.transitions.duration.standard,
                    easing: theme.transitions.easing.easeInOut,
                  }),
                },
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
    </HelpTourProvider>
  );
}