import * as React from "react";
import {
  AppBar,
  Avatar,
  Box,
  Divider,
  Drawer,
  IconButton,
  List,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Toolbar,
  Typography,
  useMediaQuery,
} from "@mui/material";
import {
  Menu as MenuIcon,
  HomeOutlined,
  DashboardOutlined,
  CampaignOutlined,
  UploadFileOutlined,
  AssignmentTurnedInOutlined,
  ManageSearchOutlined,
  PersonOutline,
  SettingsOutlined,
  InfoOutlined,
  LogoutOutlined,
} from "@mui/icons-material";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { getMe, type Me } from "@/api/auth";

const drawerWidth = 280;

function initials(first?: string, last?: string) {
  const f = (first ?? "").trim()[0] ?? "";
  const l = (last ?? "").trim()[0] ?? "";
  return (f + l).toUpperCase() || "U";
}

function NavItem(props: {
  to: string;
  icon: React.ReactNode;
  label: string;
  onClick?: () => void;
}) {
  return (
    <ListItemButton
      component={NavLink}
      to={props.to}
      onClick={props.onClick}
      sx={{
        borderRadius: 2.5,
        mx: 1,
        my: 0.5,
        "&.active": {
          backgroundColor: "rgba(255,255,255,.08)",
          "& .MuiListItemIcon-root": { opacity: 1 },
        },
      }}
    >
      <ListItemIcon sx={{ minWidth: 42, opacity: 0.9 }}>{props.icon}</ListItemIcon>
      <ListItemText
        primary={props.label}
        primaryTypographyProps={{ fontWeight: 900 }}
      />
    </ListItemButton>
  );
}

export default function AppLayout() {
  const navigate = useNavigate();
  const location = useLocation();
  const isDesktop = useMediaQuery("(min-width: 900px)");

  const useMockMe = import.meta.env.VITE_USE_MOCK_ME === "true";
  const meQuery = useQuery<Me>({
    queryKey: ["me"],
    queryFn: getMe,
    retry: false,
    enabled: !useMockMe,
  });

  const me: Me | undefined = useMockMe
    ? ({
        id: 1,
        username: "mockuser",
        first_name: "Mock",
        last_name: "User",
        email: "mockuser@example.com",
        groups: ["CISO", "CERT"],
        ciso_scope: "EU",
      } as any)
    : meQuery.data;

  const groups = me?.groups ?? [];
  const isElevated = groups.includes("CISO") || groups.includes("CERT");

  const [mobileOpen, setMobileOpen] = React.useState(false);
  React.useEffect(() => setMobileOpen(false), [location.pathname]);

  function onLogout() {
    // If session-based, call backend logout then go login:
    // api.post("/auth/logout/").finally(() => navigate("/login", { replace: true }));
    navigate("/login", { replace: true });
  }

  const drawer = (
    <Box sx={{ height: "100%", display: "flex", flexDirection: "column" }}>
      <Box sx={{ px: 2, py: 2 }}>
        <Typography fontWeight={950} letterSpacing={-0.2}>
          Suspicious
        </Typography>
      </Box>

      <Divider sx={{ opacity: 0.25 }} />

      <List sx={{ px: 0.5, py: 1 }}>
        <NavItem to="/" icon={<HomeOutlined />} label="Home" />
        <NavItem to="/submit" icon={<UploadFileOutlined />} label="Submit" />
        <NavItem to="/submissions" icon={<AssignmentTurnedInOutlined />} label="My submissions" />
        <NavItem to="/campaigns" icon={<CampaignOutlined />} label="Campaigns" />
        <NavItem to="/dashboard" icon={<DashboardOutlined />} label="Dashboard" />
        {isElevated ? (
          <NavItem to="/investigation" icon={<ManageSearchOutlined />} label="Investigation" />
        ) : null}
        <NavItem to="/profile" icon={<PersonOutline />} label="Profile" />
        {isElevated ? (
          <NavItem to="/settings" icon={<SettingsOutlined />} label="Settings" />
        ) : null}
        <NavItem to="/about" icon={<InfoOutlined />} label="About" />
      </List>

      <Box sx={{ flex: 1 }} />

      <Divider sx={{ opacity: 0.25 }} />
      <List sx={{ px: 0.5, py: 1 }}>
        <ListItemButton
          onClick={onLogout}
          sx={{ borderRadius: 2.5, mx: 1, my: 0.5 }}
        >
          <ListItemIcon sx={{ minWidth: 42, opacity: 0.9 }}>
            <LogoutOutlined />
          </ListItemIcon>
          <ListItemText primary="Logout" primaryTypographyProps={{ fontWeight: 900 }} />
        </ListItemButton>
      </List>
    </Box>
  );

  return (
    <Box sx={{ display: "flex", minHeight: "100vh" }}>
      <AppBar
        position="fixed"
        elevation={0}
        sx={{
          backdropFilter: "blur(14px)",
          backgroundColor: "rgba(11,16,32,.75)",
          borderBottom: "1px solid rgba(255,255,255,.08)",
          zIndex: (t) => t.zIndex.drawer + 1,
        }}
      >
      </AppBar>

      {/* Drawer */}
      <Box component="nav" sx={{ width: { md: drawerWidth }, flexShrink: { md: 0 } }}>
        {!isDesktop ? (
          <Drawer
            variant="temporary"
            open={mobileOpen}
            onClose={() => setMobileOpen(false)}
            ModalProps={{ keepMounted: true }}
            sx={{
              "& .MuiDrawer-paper": {
                width: drawerWidth,
                borderRight: "1px solid rgba(255,255,255,.08)",
                backgroundColor: "rgba(16,24,51,.92)",
                backdropFilter: "blur(12px)",
              },
            }}
          >
            {drawer}
          </Drawer>
        ) : (
          <Drawer
            variant="permanent"
            open
            sx={{
              "& .MuiDrawer-paper": {
                width: drawerWidth,
                borderRight: "1px solid rgba(255,255,255,.08)",
                backgroundColor: "rgba(16,24,51,.70)",
                backdropFilter: "blur(12px)",
              },
            }}
          >
            {drawer}
          </Drawer>
        )}
      </Box>

      {/* Main */}
      <Box
        component="main"
        sx={{
          flexGrow: 1,
          width: { md: `calc(100% - ${drawerWidth}px)` },
          pt: 9, // AppBar height
        }}
      >
        <Outlet />
      </Box>
    </Box>
  );
}
