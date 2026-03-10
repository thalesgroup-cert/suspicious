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
} from "@mui/icons-material";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { getMe, logout, type Me } from "@/api/auth";
import { getAccessToken } from "@/api/client";

const drawerWidth = 304;
const collapsedDrawerWidth = 88;

type NavItemConfig = {
  to: string;
  label: string;
  icon: React.ReactElement;
  elevatedOnly?: boolean;
};

const primaryNavItems: NavItemConfig[] = [
  { to: "/", label: "Home", icon: <HomeOutlined /> },
  { to: "/submit", label: "Submit", icon: <UploadFileOutlined /> },
  {
    to: "/submissions",
    label: "My submissions",
    icon: <AssignmentTurnedInOutlined />,
  },
];

const workspaceNavItems: NavItemConfig[] = [
  { to: "/campaigns", label: "Campaigns", icon: <CampaignOutlined /> },
  { to: "/dashboard", label: "Dashboard", icon: <DashboardOutlined /> },
  {
    to: "/investigation",
    label: "Investigation",
    icon: <ManageSearchOutlined />,
    elevatedOnly: true,
  },
];

const secondaryNavItems: NavItemConfig[] = [
  { to: "/profile", label: "Profile", icon: <PersonOutline /> },
  {
    to: "/settings",
    label: "Settings",
    icon: <SettingsOutlined />,
    elevatedOnly: true,
  },
  { to: "/about", label: "About", icon: <InfoOutlined /> },
];

function filterNavItems(items: NavItemConfig[], isElevated: boolean) {
  return items.filter((item) => !item.elevatedOnly || isElevated);
}

function getPageTitle(
  pathname: string,
  items: NavItemConfig[],
  fallback = "Workspace",
) {
  const matched =
    items.find((item) => item.to !== "/" && pathname.startsWith(item.to)) ??
    items.find((item) => item.to === pathname);

  return matched?.label ?? fallback;
}

function NavSection(props: {
  title: string;
  items: NavItemConfig[];
  onNavigate?: () => void;
  isDark: boolean;
  collapsed?: boolean;
  showIconChrome?: boolean;
}) {
  const {
    title,
    items,
    onNavigate,
    isDark,
    collapsed = false,
    showIconChrome = true,
  } = props;

  return (
    <Box component="section" aria-labelledby={`nav-section-${title}`}>
      {!collapsed ? (
        <Typography
          id={`nav-section-${title}`}
          variant="overline"
          sx={(theme) => ({
            display: "block",
            px: 2.25,
            pb: 0.75,
            color: theme.palette.text.secondary,
            letterSpacing: "0.14em",
            fontWeight: 800,
            lineHeight: 1.8,
            opacity: isDark ? 0.9 : 0.8,
            whiteSpace: "nowrap",
          })}
        >
          {title}
        </Typography>
      ) : (
        <Box sx={{ height: 16 }} />
      )}

      <List disablePadding sx={{ px: 1 }}>
        {items.map((item) => (
          <SidebarNavItem
            key={item.to}
            to={item.to}
            label={item.label}
            icon={item.icon}
            onClick={onNavigate}
            collapsed={collapsed}
            showIconChrome={showIconChrome}
          />
        ))}
      </List>
    </Box>
  );
}

function SidebarNavItem(props: {
  to: string;
  label: string;
  icon: React.ReactElement;
  onClick?: () => void;
  collapsed?: boolean;
  showIconChrome?: boolean;
}) {
  const {
    to,
    label,
    icon,
    onClick,
    collapsed = false,
    showIconChrome = true,
  } = props;

  return (
    <ListItemButton
      component={NavLink}
      to={to}
      onClick={onClick}
      aria-label={label}
      title={collapsed ? label : undefined}
      sx={(theme) => {
        const isDark = theme.palette.mode === "dark";
        const primary = theme.palette.primary.main;
        const minimalCollapsed = collapsed && !showIconChrome;

        return {
          minHeight: 52,
          px: collapsed ? 1 : 1.25,
          py: 0.625,
          mb: 0.5,
          borderRadius: 3,
          color: alpha(theme.palette.text.primary, isDark ? 0.78 : 0.82),
          justifyContent: collapsed ? "center" : "flex-start",
          transition: theme.transitions.create(
            [
              "background-color",
              "border-color",
              "transform",
              "color",
              "box-shadow",
              "padding",
            ],
            {
              duration: theme.transitions.duration.shorter,
            },
          ),
          border: minimalCollapsed
            ? "1px solid transparent"
            : `1px solid ${alpha(theme.palette.divider, isDark ? 0.28 : 0.9)}`,
          backgroundColor: minimalCollapsed ? "transparent" : "transparent",
          boxShadow: "none",
          "& .MuiListItemIcon-root": {
            minWidth: 0,
            mr: collapsed ? 0 : 1.5,
            color: "inherit",
            justifyContent: "center",
          },
          "& .MuiListItemText-root": {
            opacity: collapsed ? 0 : 1,
            width: collapsed ? 0 : "auto",
            overflow: "hidden",
            transition: theme.transitions.create(["opacity", "width"], {
              duration: theme.transitions.duration.shorter,
            }),
          },
          "& .MuiListItemText-primary": {
            fontSize: 14,
            fontWeight: 700,
            letterSpacing: "-0.01em",
            whiteSpace: "nowrap",
          },
          "&:hover": {
            backgroundColor: alpha(primary, isDark ? 0.08 : 0.06),
            borderColor: alpha(primary, isDark ? 0.24 : 0.2),
            color: theme.palette.text.primary,
            transform: collapsed ? "none" : "translateX(2px)",
          },
          "&:hover .nav-icon-shell": {
            borderColor: alpha(primary, isDark ? 0.22 : 0.18),
            backgroundColor: alpha(primary, isDark ? 0.12 : 0.08),
          },
          "&.active": minimalCollapsed
            ? {
                color: theme.palette.text.primary,
                background: "transparent",
                borderColor: "transparent",
                boxShadow: "none",
              }
            : {
                color: theme.palette.text.primary,
                background: `linear-gradient(180deg, ${alpha(primary, isDark ? 0.18 : 0.12)} 0%, ${alpha(
                  primary,
                  isDark ? 0.1 : 0.06,
                )} 100%)`,
                borderColor: alpha(primary, isDark ? 0.32 : 0.26),
                boxShadow: isDark
                  ? `inset 0 1px 0 ${alpha(theme.palette.common.white, 0.08)}, 0 8px 24px ${alpha(
                      "#020617",
                      0.28,
                    )}`
                  : `inset 0 1px 0 ${alpha(theme.palette.common.white, 0.5)}, 0 8px 24px ${alpha(
                      primary,
                      0.08,
                    )}`,
              },
          "&.active .nav-icon-shell": {
            backgroundColor: alpha(primary, isDark ? 0.18 : 0.12),
            borderColor: alpha(primary, isDark ? 0.26 : 0.2),
          },
          "&:focus-visible": {
            outline: `2px solid ${alpha(primary, 0.72)}`,
            outlineOffset: 2,
          },
        };
      }}
    >
      <ListItemIcon>
        <Box
          className="nav-icon-shell"
          sx={(theme) => ({
            width: 34,
            height: 34,
            borderRadius: 2.25,
            display: "grid",
            placeItems: "center",
            border: showIconChrome
              ? `1px solid ${alpha(theme.palette.divider, 0.7)}`
              : "1px solid transparent",
            backgroundColor: showIconChrome
              ? alpha(
                  theme.palette.text.primary,
                  theme.palette.mode === "dark" ? 0.03 : 0.02,
                )
              : "transparent",
            transition: theme.transitions.create(
              ["background-color", "border-color"],
              {
                duration: theme.transitions.duration.shorter,
              },
            ),
            "& svg": {
              fontSize: 20,
            },
          })}
        >
          {icon}
        </Box>
      </ListItemIcon>

      <ListItemText primary={label} />
    </ListItemButton>
  );
}

export default function AppLayout() {
  const theme = useTheme();
  const navigate = useNavigate();
  const location = useLocation();
  const queryClient = useQueryClient();
  const isDesktop = useMediaQuery(theme.breakpoints.up("md"));
  const isDark = theme.palette.mode === "dark";

  const token = getAccessToken();

  const meQuery = useQuery<Me>({
    queryKey: ["me"],
    queryFn: getMe,
    retry: false,
    enabled: !!token,
  });

  const me = meQuery.data;
  const groups = me?.groups ?? [];
  const isElevated = groups.includes("CISO") || groups.includes("CERT");

  const [mobileOpen, setMobileOpen] = React.useState(false);
  const [sidebarHovered, setSidebarHovered] = React.useState(false);
  const [sidebarPinned, setSidebarPinned] = React.useState(false);

  React.useEffect(() => {
    setMobileOpen(false);
  }, [location.pathname]);

  React.useEffect(() => {
    if (!isDesktop) {
      setSidebarHovered(false);
    }
  }, [isDesktop]);

  const visiblePrimaryItems = React.useMemo(
    () => filterNavItems(primaryNavItems, isElevated),
    [isElevated],
  );
  const visibleWorkspaceItems = React.useMemo(
    () => filterNavItems(workspaceNavItems, isElevated),
    [isElevated],
  );
  const visibleSecondaryItems = React.useMemo(
    () => filterNavItems(secondaryNavItems, isElevated),
    [isElevated],
  );

  const allVisibleItems = React.useMemo(
    () => [
      ...visiblePrimaryItems,
      ...visibleWorkspaceItems,
      ...visibleSecondaryItems,
    ],
    [visiblePrimaryItems, visibleWorkspaceItems, visibleSecondaryItems],
  );

  const currentPageTitle = getPageTitle(location.pathname, allVisibleItems);

  async function onLogout() {
    try {
      await logout();
    } finally {
      queryClient.removeQueries({ queryKey: ["me"] });
      navigate("/login", { replace: true });
    }
  }

  const isSidebarCollapsed = isDesktop && !sidebarPinned && !sidebarHovered;
  const showSidebarIconChrome = !isSidebarCollapsed;
  const effectiveDrawerWidth = isDesktop
    ? isSidebarCollapsed
      ? collapsedDrawerWidth
      : drawerWidth
    : drawerWidth;

  const shellBackground = isDark
    ? `
      radial-gradient(circle at top left, ${alpha(theme.palette.primary.main, 0.08)}, transparent 24%),
      linear-gradient(180deg, #0b1120 0%, #0a1020 100%)
    `
    : `
      radial-gradient(circle at top left, ${alpha(theme.palette.primary.main, 0.07)}, transparent 24%),
      linear-gradient(180deg, ${theme.palette.background.default} 0%, ${alpha(
        theme.palette.primary.light,
        0.08,
      )} 100%)
    `;

  const sidebarBackground = isDark
    ? `
      radial-gradient(circle at top left, ${alpha(theme.palette.primary.light, 0.1)}, transparent 28%),
      radial-gradient(circle at bottom right, ${alpha(theme.palette.primary.main, 0.08)}, transparent 22%),
      linear-gradient(180deg, rgba(15,23,42,0.94) 0%, rgba(10,15,30,0.98) 100%)
    `
    : `
      radial-gradient(circle at top left, ${alpha(theme.palette.primary.light, 0.1)}, transparent 28%),
      radial-gradient(circle at bottom right, ${alpha(theme.palette.primary.main, 0.06)}, transparent 22%),
      linear-gradient(180deg, ${alpha(theme.palette.background.paper, 0.96)} 0%, ${alpha(
        theme.palette.background.default,
        0.98,
      )} 100%)
    `;

  const sidebarText = theme.palette.text.primary;
  const sidebarSubtleText = alpha(
    theme.palette.text.secondary,
    isDark ? 0.9 : 1,
  );

  const drawerContent = (
    <Box
      sx={{
        height: "100%",
        display: "flex",
        flexDirection: "column",
        color: sidebarText,
        background: sidebarBackground,
        overflowX: "hidden",
      }}
    >
      <Box sx={{ px: isSidebarCollapsed ? 1.25 : 2, pt: 2, pb: 1.5 }}>
        <Stack spacing={1.25}>
          <Box
            sx={{
              display: "flex",
              alignItems: "center",
              justifyContent: isSidebarCollapsed ? "center" : "space-between",
              gap: 1,
            }}
          >
            <Stack
              direction="row"
              spacing={isSidebarCollapsed ? 0 : 1.25}
              alignItems="center"
              minWidth={0}
              sx={{
                width: "100%",
                justifyContent: isSidebarCollapsed ? "center" : "flex-start",
              }}
            >
              <Avatar
                variant="rounded"
                src="/icons/suspicious-logo.png"
                alt="Suspicious"
                sx={{
                  width: 44,
                  height: 44,
                  "& img": {
                    objectFit: "contain",
                  },
                }}
              />

              {!isSidebarCollapsed && (
                <Box minWidth={0}>
                  <Typography
                    variant="subtitle1"
                    sx={{
                      fontWeight: 900,
                      letterSpacing: "-0.03em",
                      lineHeight: 1.1,
                      color: sidebarText,
                    }}
                  >
                    Suspicious
                  </Typography>
                </Box>
              )}
            </Stack>

            {!isSidebarCollapsed && (
              <Stack direction="row" spacing={1} alignItems="center">
                {isDesktop && (
                  <Tooltip
                    title={sidebarPinned ? "Unpin sidebar" : "Pin sidebar"}
                  >
                    <IconButton
                      size="small"
                      aria-label={
                        sidebarPinned ? "Unpin sidebar" : "Pin sidebar"
                      }
                      onClick={() => setSidebarPinned((prev) => !prev)}
                      sx={{
                        width: 30,
                        height: 30,
                        border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.5 : 1)}`,
                        backgroundColor: sidebarPinned
                          ? alpha(
                              theme.palette.primary.main,
                              isDark ? 0.14 : 0.1,
                            )
                          : alpha(
                              theme.palette.text.primary,
                              isDark ? 0.04 : 0.02,
                            ),
                        color: sidebarPinned
                          ? theme.palette.primary.main
                          : alpha(theme.palette.text.primary, 0.8),
                        "&:hover": {
                          backgroundColor: sidebarPinned
                            ? alpha(
                                theme.palette.primary.main,
                                isDark ? 0.18 : 0.14,
                              )
                            : alpha(
                                theme.palette.text.primary,
                                isDark ? 0.08 : 0.05,
                              ),
                        },
                        "&:focus-visible": {
                          outline: `2px solid ${alpha(theme.palette.primary.main, 0.72)}`,
                          outlineOffset: 2,
                        },
                      }}
                    >
                      <PushPinOutlined
                        sx={{
                          fontSize: 18,
                          transform: sidebarPinned
                            ? "rotate(0deg)"
                            : "rotate(45deg)",
                          transition: theme.transitions.create("transform", {
                            duration: theme.transitions.duration.shorter,
                          }),
                        }}
                      />
                    </IconButton>
                  </Tooltip>
                )}
              </Stack>
            )}
          </Box>
        </Stack>
      </Box>

      <Divider
        sx={{ borderColor: alpha(theme.palette.divider, isDark ? 0.5 : 1) }}
      />

      <Box
        component="nav"
        aria-label="Primary navigation"
        sx={{
          flex: 1,
          overflowY: "auto",
          px: 0.5,
          py: 1.5,
        }}
      >
        <Stack spacing={2}>
          <NavSection
            title="Primary"
            items={visiblePrimaryItems}
            onNavigate={!isDesktop ? () => setMobileOpen(false) : undefined}
            isDark={isDark}
            collapsed={isSidebarCollapsed}
            showIconChrome={showSidebarIconChrome}
          />

          <NavSection
            title="Workspace"
            items={visibleWorkspaceItems}
            onNavigate={!isDesktop ? () => setMobileOpen(false) : undefined}
            isDark={isDark}
            collapsed={isSidebarCollapsed}
            showIconChrome={showSidebarIconChrome}
          />

          <NavSection
            title="Account"
            items={visibleSecondaryItems}
            onNavigate={!isDesktop ? () => setMobileOpen(false) : undefined}
            isDark={isDark}
            collapsed={isSidebarCollapsed}
            showIconChrome={showSidebarIconChrome}
          />
        </Stack>
      </Box>

      <Box sx={{ p: isSidebarCollapsed ? 1 : 1.25 }}>
        <Divider
          sx={{
            mb: 1.25,
            borderColor: alpha(theme.palette.divider, isDark ? 0.5 : 1),
          }}
        />

        {!isSidebarCollapsed && (
          <Box
            sx={{
              p: 1,
              mb: 1,
              borderRadius: 3,
              border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.5 : 1)}`,
              backgroundColor: alpha(
                theme.palette.text.primary,
                isDark ? 0.03 : 0.02,
              ),
            }}
          >
            <Stack direction="row" spacing={1.25} alignItems="center">
              <Avatar
                sx={{
                  width: 32,
                  height: 32,
                  fontSize: 13,
                  fontWeight: 800,
                  bgcolor: alpha(
                    theme.palette.text.primary,
                    isDark ? 0.08 : 0.06,
                  ),
                  color: sidebarText,
                }}
              >
                {isElevated ? "E" : "U"}
              </Avatar>

              <Box minWidth={0}>
                <Typography
                  variant="body2"
                  sx={{ fontWeight: 700, color: sidebarText, lineHeight: 1.2 }}
                >
                  {isElevated ? "Elevated access" : "Standard access"}
                </Typography>
                <Typography variant="caption" sx={{ color: sidebarSubtleText }}>
                  {groups.length > 0
                    ? groups.join(" • ")
                    : "Authenticated session"}
                </Typography>
              </Box>
            </Stack>
          </Box>
        )}

        <List disablePadding sx={{ px: 0 }}>
          <ListItemButton
            onClick={onLogout}
            aria-label="Logout"
            title={isSidebarCollapsed ? "Logout" : undefined}
            sx={(theme) => {
              const minimalCollapsed =
                isSidebarCollapsed && !showSidebarIconChrome;

              return {
                minHeight: 52,
                px: isSidebarCollapsed ? 1 : 1.25,
                borderRadius: 3,
                color: alpha(theme.palette.text.primary, isDark ? 0.82 : 0.88),
                border: minimalCollapsed
                  ? "1px solid transparent"
                  : `1px solid ${alpha(theme.palette.divider, isDark ? 0.5 : 1)}`,
                backgroundColor: minimalCollapsed
                  ? "transparent"
                  : "transparent",
                justifyContent: isSidebarCollapsed ? "center" : "flex-start",
                "& .MuiListItemIcon-root": {
                  minWidth: 0,
                  mr: isSidebarCollapsed ? 0 : 1.5,
                  color: "inherit",
                },
                "& .MuiListItemText-root": {
                  opacity: isSidebarCollapsed ? 0 : 1,
                  width: isSidebarCollapsed ? 0 : "auto",
                  overflow: "hidden",
                },
                "& .MuiListItemText-primary": {
                  fontSize: 14,
                  fontWeight: 800,
                  whiteSpace: "nowrap",
                },
                "&:hover": {
                  backgroundColor: alpha(
                    theme.palette.error.main,
                    isDark ? 0.1 : 0.08,
                  ),
                  borderColor: alpha(
                    theme.palette.error.main,
                    isDark ? 0.16 : 0.14,
                  ),
                  color: isDark ? "#fecaca" : theme.palette.error.dark,
                },
                "&:hover .logout-icon-shell": {
                  borderColor: alpha(
                    theme.palette.error.main,
                    isDark ? 0.22 : 0.18,
                  ),
                  backgroundColor: alpha(
                    theme.palette.error.main,
                    isDark ? 0.12 : 0.08,
                  ),
                },
                "&:focus-visible": {
                  outline: `2px solid ${alpha(theme.palette.primary.main, 0.72)}`,
                  outlineOffset: 2,
                },
              };
            }}
          >
            <ListItemIcon>
              <Box
                className="logout-icon-shell"
                sx={{
                  width: 34,
                  height: 34,
                  borderRadius: 2.25,
                  display: "grid",
                  placeItems: "center",
                  border: showSidebarIconChrome
                    ? `1px solid ${alpha(theme.palette.divider, isDark ? 0.5 : 1)}`
                    : "1px solid transparent",
                  backgroundColor: showSidebarIconChrome
                    ? alpha(theme.palette.text.primary, isDark ? 0.03 : 0.02)
                    : "transparent",
                  transition: theme.transitions.create(
                    ["background-color", "border-color"],
                    {
                      duration: theme.transitions.duration.shorter,
                    },
                  ),
                }}
              >
                <LogoutOutlined sx={{ fontSize: 20 }} />
              </Box>
            </ListItemIcon>

            <ListItemText primary="Logout" />
          </ListItemButton>
        </List>
      </Box>
    </Box>
  );

  return (
    <Box
      sx={{
        display: "flex",
        minHeight: "100vh",
        background: shellBackground,
        color: theme.palette.text.primary,
      }}
    >
      <AppBar
        position="fixed"
        elevation={0}
        color="transparent"
        sx={{
          display: { xs: "block", md: "none" },
          zIndex: (t) => t.zIndex.drawer + 1,
          backdropFilter: "blur(16px)",
          backgroundColor: alpha(
            theme.palette.background.paper,
            isDark ? 0.72 : 0.82,
          ),
          borderBottom: `1px solid ${alpha(theme.palette.divider, isDark ? 0.5 : 1)}`,
          boxShadow: isDark
            ? `0 8px 32px ${alpha("#020617", 0.22)}`
            : `0 8px 32px ${alpha(theme.palette.primary.main, 0.06)}`,
        }}
      >
        <Toolbar sx={{ minHeight: 72, px: 2 }}>
          <Stack
            direction="row"
            alignItems="center"
            justifyContent="space-between"
            sx={{ width: "100%" }}
          >
            <IconButton
              edge="start"
              color="inherit"
              aria-label="Open navigation menu"
              onClick={() => setMobileOpen(true)}
              sx={{
                border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.5 : 1)}`,
                backgroundColor: alpha(
                  theme.palette.text.primary,
                  isDark ? 0.04 : 0.02,
                ),
                "&:hover": {
                  backgroundColor: alpha(
                    theme.palette.text.primary,
                    isDark ? 0.08 : 0.05,
                  ),
                },
                "&:focus-visible": {
                  outline: `2px solid ${alpha(theme.palette.primary.main, 0.72)}`,
                  outlineOffset: 2,
                },
              }}
            >
              <MenuRounded />
            </IconButton>

            <Typography sx={{ fontWeight: 800, letterSpacing: "-0.02em" }}>
              {currentPageTitle}
            </Typography>

            <Box sx={{ width: 40 }} />
          </Stack>
        </Toolbar>
      </AppBar>

      <Box
        component="aside"
        aria-label="Sidebar"
        onMouseEnter={
          isDesktop && !sidebarPinned
            ? () => setSidebarHovered(true)
            : undefined
        }
        onMouseLeave={
          isDesktop && !sidebarPinned
            ? () => setSidebarHovered(false)
            : undefined
        }
        sx={{
          width: { md: effectiveDrawerWidth },
          flexShrink: { md: 0 },
          transition: (theme) =>
            theme.transitions.create("width", {
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
            ModalProps={{ keepMounted: true }}
            PaperProps={{
              sx: {
                width: drawerWidth,
                borderRight: `1px solid ${alpha(theme.palette.divider, isDark ? 0.5 : 1)}`,
                backgroundColor: "transparent",
                boxShadow: isDark
                  ? `0 24px 80px ${alpha("#020617", 0.5)}`
                  : `0 24px 80px ${alpha(theme.palette.primary.main, 0.08)}`,
              },
            }}
          >
            {drawerContent}
          </Drawer>
        ) : (
          <Drawer
            variant="permanent"
            open
            PaperProps={{
              sx: {
                width: effectiveDrawerWidth,
                overflowX: "hidden",
                transition: theme.transitions.create("width", {
                  duration: theme.transitions.duration.standard,
                  easing: theme.transitions.easing.easeInOut,
                }),
                borderRight: `1px solid ${alpha(theme.palette.divider, isDark ? 0.5 : 1)}`,
                backgroundColor: "transparent",
                boxShadow: "none",
              },
            }}
          >
            {drawerContent}
          </Drawer>
        )}
      </Box>

      <Box
        component="main"
        sx={{
          flexGrow: 1,
          minWidth: 0,
          width: { md: `calc(100% - ${effectiveDrawerWidth}px)` },
          transition: (theme) =>
            theme.transitions.create(["width", "margin", "padding"], {
              duration: theme.transitions.duration.standard,
              easing: theme.transitions.easing.easeInOut,
            }),
        }}
      >
        <Box sx={{ height: { xs: 72, md: 0 } }} />
        <Box
          sx={{
            px: {
              xs: 2,
              md: isSidebarCollapsed ? 5 : 3,
            },
            py: { xs: 2, md: 3 },
            maxWidth: {
              md: isSidebarCollapsed ? "1600px" : "1440px",
            },
            mx: "auto",
            width: "100%",
            transition: (theme) =>
              theme.transitions.create(["max-width", "padding"], {
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
