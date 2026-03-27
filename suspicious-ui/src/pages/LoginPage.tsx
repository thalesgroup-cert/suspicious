// src/pages/LoginPage.tsx
import * as React from "react";
import {
  Alert,
  Box,
  Button,
  CircularProgress,
  Divider,
  IconButton,
  InputAdornment,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import { alpha, useTheme } from "@mui/material/styles";
import {
  SecurityOutlined,
  Visibility,
  VisibilityOff,
  ArrowForwardOutlined,
  ShieldOutlined,
  LockOutlined
} from "@mui/icons-material";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { getMe, login, hydrateColorsAfterSso } from "@/api/auth";
import { setAccessToken } from "@/api/client";

// ---------------------------------------------------------------------------
// Env config
// ---------------------------------------------------------------------------

const COMPANY_NAME        = import.meta.env.VITE_COMPANY_NAME        ?? "Company";
const COMPANY_LINK        = import.meta.env.VITE_COMPANY_LINK        ?? "/";
const COMPANY_LOGO_BASE64 = import.meta.env.VITE_COMPANY_LOGO_BASE64 as string | undefined;
const COMPANY_LOGO_URL    = import.meta.env.VITE_COMPANY_LOGO_URL    as string | undefined;

// ---------------------------------------------------------------------------
// Ambient background — animated radial orbs, fully theme-aware
// ---------------------------------------------------------------------------

function AmbientBackground() {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  const p = theme.palette.primary.main;
  const s = (theme.palette as any).secondary?.main ?? p;
  const success = theme.palette.success?.main ?? "#22C55E";

  return (
    <Box
      aria-hidden
      sx={{
        position: "fixed",
        inset: 0,
        zIndex: 0,
        overflow: "hidden",
        pointerEvents: "none",
        bgcolor: "background.default",
      }}
    >
      {/* Radial orbs */}
      <Box
        sx={{
          position: "absolute",
          inset: 0,
          background: isDark
            ? `radial-gradient(ellipse 900px 600px at 15% 10%, ${alpha(p, 0.28)}, transparent 55%),
               radial-gradient(ellipse 700px 500px at 85% 25%, ${alpha(s, 0.2)}, transparent 55%),
               radial-gradient(ellipse 800px 600px at 50% 95%, ${alpha(success, 0.1)}, transparent 55%)`
            : `radial-gradient(ellipse 900px 600px at 15% 10%, ${alpha(p, 0.14)}, transparent 55%),
               radial-gradient(ellipse 700px 500px at 85% 25%, ${alpha(s, 0.1)}, transparent 55%),
               radial-gradient(ellipse 800px 600px at 50% 95%, ${alpha(success, 0.07)}, transparent 55%)`,
          filter: "saturate(130%)",
        }}
      />

      {/* Noise overlay */}
      <Box
        sx={{
          position: "absolute",
          inset: 0,
          // inline SVG noise
          backgroundImage: `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='200' height='200'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.85' numOctaves='4' stitchTiles='stitch'/%3E%3CfeColorMatrix type='saturate' values='0'/%3E%3C/filter%3E%3Crect width='200' height='200' filter='url(%23n)' opacity='${isDark ? ".22" : ".08"}'/%3E%3C/svg%3E")`,
          mixBlendMode: isDark ? "overlay" : "multiply",
          opacity: 0.35,
        }}
      />

      {/* Subtle grid lines — dark only */}
      {isDark && (
        <Box
          sx={{
            position: "absolute",
            inset: 0,
            backgroundImage: `
              repeating-linear-gradient(0deg, ${alpha("#fff", 0.015)}, ${alpha("#fff", 0.015)} 1px, transparent 1px, transparent 40px),
              repeating-linear-gradient(90deg, ${alpha("#fff", 0.015)}, ${alpha("#fff", 0.015)} 1px, transparent 1px, transparent 40px)
            `,
          }}
        />
      )}
    </Box>
  );
}

// ---------------------------------------------------------------------------
// Decorative side panel (desktop only)
// ---------------------------------------------------------------------------

function SidePanel() {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  const p = theme.palette.primary.main;

  const features = [
    { icon: <ShieldOutlined sx={{ fontSize: 16 }} />, text: "Automated threat analysis" },
    { icon: <LockOutlined sx={{ fontSize: 16 }} />,   text: "Secure artifact triage" },
    { icon: <SecurityOutlined sx={{ fontSize: 16 }} />, text: "Multi-vector detection" },
  ];

  return (
    <Box
      sx={{
        flex: "0 0 340px",
        display: "flex",
        flexDirection: "column",
        justifyContent: "center",
        px: 5,
        py: 6,
        position: "relative",
        overflow: "hidden",
      }}
    >
      {/* Vertical rule between panels */}
      <Box
        sx={{
          position: "absolute",
          top: "10%",
          bottom: "10%",
          right: 0,
          width: 1,
          background: `linear-gradient(180deg, transparent, ${alpha(theme.palette.divider, isDark ? 0.35 : 0.6)}, transparent)`,
        }}
      />

      <Stack spacing={4}>
        {/* Wordmark */}
        <Stack spacing={1}>
          <Box
            component="img"
            src="/icons/suspicious-logo.png"
            alt="Suspicious"
            sx={{
              width: 52,
              height: 52,
              objectFit: "contain",
              mb: 0.5,
              filter: isDark
                ? `drop-shadow(0 4px 16px ${alpha(p, 0.5)})`
                : `drop-shadow(0 4px 12px ${alpha(p, 0.3)})`,
            }}
          />

          <Typography
            sx={{
              fontWeight: 950,
              fontSize: 26,
              letterSpacing: "-0.04em",
              lineHeight: 1.05,
              color: "text.primary",
            }}
          >
            Suspicious
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ fontSize: 13.5, lineHeight: 1.6 }}>
            Security intake and automated analysis for emails, files, URLs, IPs, and hashes.
          </Typography>
        </Stack>

        {/* Feature list */}
        <Stack spacing={1.5}>
          {features.map((f) => (
            <Stack key={f.text} direction="row" spacing={1.25} alignItems="center">
              <Box
                sx={{
                  width: 30,
                  height: 30,
                  borderRadius: 2,
                  display: "grid",
                  placeItems: "center",
                  background: alpha(p, isDark ? 0.12 : 0.08),
                  border: `1px solid ${alpha(p, isDark ? 0.22 : 0.18)}`,
                  color: p,
                  flexShrink: 0,
                }}
              >
                {f.icon}
              </Box>
              <Typography variant="body2" sx={{ fontWeight: 600, fontSize: 13, color: "text.secondary" }}>
                {f.text}
              </Typography>
            </Stack>
          ))}
        </Stack>

        {/* Company link */}
        {COMPANY_LOGO_BASE64 || COMPANY_LOGO_URL ? (
          <Box
            component="a"
            href={COMPANY_LINK}
            target="_blank"
            rel="noreferrer"
            sx={{ display: "inline-flex", alignItems: "center", textDecoration: "none", width: "fit-content" }}
          >
            <Box
              component="img"
              src={COMPANY_LOGO_BASE64 || COMPANY_LOGO_URL}
              alt={COMPANY_NAME}
              sx={{
                height: 28,
                width: "auto",
                opacity: isDark ? 0.7 : 0.85,
                filter: isDark ? "brightness(1.2)" : "none",
                transition: "opacity .2s",
                "&:hover": { opacity: 1 },
              }}
            />
          </Box>
        ) : (
          <Typography variant="caption" color="text.disabled" sx={{ fontWeight: 700, letterSpacing: "0.05em", textTransform: "uppercase", fontSize: 11 }}>
            {COMPANY_NAME}
          </Typography>
        )}
      </Stack>
    </Box>
  );
}

// ---------------------------------------------------------------------------
// Login form card
// ---------------------------------------------------------------------------

function LoginCard({
  onSubmit,
  loading,
  error,
  username,
  setUsername,
  password,
  setPassword,
  showPassword,
  setShowPassword,
  onSSO,
}: {
  onSubmit: (e: React.FormEvent) => void;
  loading: boolean;
  error: string | null;
  username: string;
  setUsername: (v: string) => void;
  password: string;
  setPassword: (v: string) => void;
  showPassword: boolean;
  setShowPassword: (v: boolean) => void;
  onSSO: () => void;
}) {
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  const p = theme.palette.primary.main;

  return (
    <Box
      sx={{
        width: "100%",
        maxWidth: 420,
        mx: "auto",

        // Card shell — adapts to theme
        borderRadius: 4,
        border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.28 : 0.9)}`,
        background: isDark
          ? `linear-gradient(180deg, ${alpha("#fff", 0.05)}, ${alpha("#fff", 0.03)})`
          : `linear-gradient(180deg, ${alpha("#fff", 0.95)}, ${alpha(theme.palette.grey[50], 0.98)})`,
        backdropFilter: "blur(24px)",
        WebkitBackdropFilter: "blur(24px)",
        boxShadow: isDark
          ? `0 24px 80px ${alpha("#000", 0.45)}, 0 0 0 1px ${alpha(p, 0.06)}`
          : `0 24px 80px ${alpha("#000", 0.1)}, 0 0 0 1px ${alpha(p, 0.04)}`,
        p: { xs: 3, sm: 3.5 },
      }}
    >
      <Stack spacing={2.75}>
        {/* Header */}
        <Stack spacing={1.5} alignItems="center" sx={{ textAlign: "center" }}>
          {/* Logo badge */}
          <Box
            component="img"
            src="/icons/suspicious-logo.png"
            alt="Suspicious"
            sx={{
              width: 56,
              height: 56,
              objectFit: "contain",
              mb: 0.5,
              filter: isDark
                ? `drop-shadow(0 6px 20px ${alpha(p, 0.55)})`
                : `drop-shadow(0 4px 14px ${alpha(p, 0.32)})`,
            }}
          />

          <Box>
            <Typography variant="h5" fontWeight={950} letterSpacing={-0.5} sx={{ lineHeight: 1.15 }}>
              Sign in
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mt: 0.4, fontSize: 13.5 }}>
              Access the Suspicious platform
            </Typography>
          </Box>

          {/* Company logo — mobile only (side panel shows it on desktop) */}
          {(COMPANY_LOGO_BASE64 || COMPANY_LOGO_URL) && (
            <Box
              component="a"
              href={COMPANY_LINK}
              target="_blank"
              rel="noreferrer"
              sx={{
                display: { xs: "inline-flex", lg: "none" },
                alignItems: "center",
                textDecoration: "none",
              }}
            >
              <Box
                component="img"
                src={COMPANY_LOGO_BASE64 || COMPANY_LOGO_URL}
                alt={COMPANY_NAME}
                sx={{ height: 24, width: "auto", opacity: 0.8 }}
              />
            </Box>
          )}
        </Stack>

        {/* Error */}
        {error ? (
          <Alert
            severity="error"
            sx={{
              borderRadius: 2.5,
              "& .MuiAlert-message": { fontSize: 13 },
            }}
          >
            {error}
          </Alert>
        ) : null}

        {/* Form */}
        <Box component="form" onSubmit={onSubmit} noValidate>
          <Stack spacing={1.5}>
            {/* Username */}
            <Box>
              <Typography
                variant="caption"
                sx={{
                  display: "block",
                  fontWeight: 700,
                  fontSize: 11.5,
                  textTransform: "uppercase",
                  letterSpacing: "0.07em",
                  color: "text.secondary",
                  mb: 0.6,
                  pl: 0.25,
                }}
              >
                Username
              </Typography>
              <TextField
                autoComplete="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Enter your username"
                required
                fullWidth
                autoFocus
                sx={{
                  "& .MuiOutlinedInput-root": {
                    borderRadius: 2.5,
                    fontSize: 14,
                  },
                }}
              />
            </Box>

            {/* Password */}
            <Box>
              <Typography
                variant="caption"
                sx={{
                  display: "block",
                  fontWeight: 700,
                  fontSize: 11.5,
                  textTransform: "uppercase",
                  letterSpacing: "0.07em",
                  color: "text.secondary",
                  mb: 0.6,
                  pl: 0.25,
                }}
              >
                Password
              </Typography>
              <TextField
                autoComplete="current-password"
                type={showPassword ? "text" : "password"}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter your password"
                required
                fullWidth
                sx={{
                  "& .MuiOutlinedInput-root": {
                    borderRadius: 2.5,
                    fontSize: 14,
                  },
                }}
                InputProps={{
                  endAdornment: (
                    <InputAdornment position="end">
                      <IconButton
                        aria-label={showPassword ? "Hide password" : "Show password"}
                        onClick={() => setShowPassword(!showPassword)}
                        edge="end"
                        size="small"
                        sx={{ mr: 0.25 }}
                      >
                        {showPassword
                          ? <VisibilityOff sx={{ fontSize: 18 }} />
                          : <Visibility sx={{ fontSize: 18 }} />}
                      </IconButton>
                    </InputAdornment>
                  ),
                }}
              />
            </Box>

            {/* Sign in button */}
            <Button
              type="submit"
              size="large"
              variant="contained"
              disabled={loading || !username.trim() || !password}
              endIcon={
                loading
                  ? <CircularProgress size={16} color="inherit" />
                  : <ArrowForwardOutlined sx={{ fontSize: "18px !important" }} />
              }
              sx={{
                mt: 0.5,
                height: 46,
                borderRadius: 2.5,
                textTransform: "none",
                fontWeight: 900,
                fontSize: 14.5,
                letterSpacing: "-0.01em",
                // Gradient on contained primary
                background: `linear-gradient(135deg, ${p}, ${alpha(p, 0.8)})`,
                boxShadow: `0 4px 16px ${alpha(p, isDark ? 0.35 : 0.28)}`,
                "&:hover": {
                  background: `linear-gradient(135deg, ${alpha(p, 0.92)}, ${alpha(p, 0.72)})`,
                  boxShadow: `0 6px 22px ${alpha(p, isDark ? 0.45 : 0.35)}`,
                  transform: "translateY(-1px)",
                },
                "&:active": {
                  transform: "translateY(0)",
                },
                "&:disabled": {
                  background: alpha(theme.palette.text.primary, isDark ? 0.08 : 0.06),
                  boxShadow: "none",
                  color: alpha(theme.palette.text.primary, 0.35),
                },
                transition: theme.transitions.create(
                  ["background", "box-shadow", "transform"],
                  { duration: 150 }
                ),
              }}
            >
              {loading ? "Signing in…" : "Sign in"}
            </Button>

            {/* Divider */}
            <Stack direction="row" alignItems="center" spacing={1.5}>
              <Box sx={{ flex: 1, height: 1, bgcolor: alpha(theme.palette.divider, isDark ? 0.3 : 0.6) }} />
              <Typography variant="caption" color="text.disabled" sx={{ fontWeight: 600, fontSize: 11 }}>
                OR
              </Typography>
              <Box sx={{ flex: 1, height: 1, bgcolor: alpha(theme.palette.divider, isDark ? 0.3 : 0.6) }} />
            </Stack>

            {/* SSO button */}
            <Button
              variant="outlined"
              size="large"
              onClick={onSSO}
              startIcon={<SecurityOutlined sx={{ fontSize: "18px !important" }} />}
              sx={{
                height: 46,
                borderRadius: 2.5,
                textTransform: "none",
                fontWeight: 800,
                fontSize: 14,
                borderColor: alpha(theme.palette.divider, isDark ? 0.35 : 0.8),
                background: isDark
                  ? alpha("#fff", 0.04)
                  : alpha(theme.palette.background.paper, 0.8),
                color: "text.primary",
                "&:hover": {
                  borderColor: alpha(p, isDark ? 0.45 : 0.4),
                  background: isDark ? alpha("#fff", 0.07) : alpha(p, 0.05),
                  transform: "translateY(-1px)",
                },
                "&:active": { transform: "translateY(0)" },
                transition: theme.transitions.create(
                  ["background", "border-color", "transform"],
                  { duration: 150 }
                ),
              }}
            >
              Continue with SSO
            </Button>
          </Stack>
        </Box>

        {/* Footer note */}
        <Typography
          variant="caption"
          sx={{
            textAlign: "center",
            color: alpha(theme.palette.text.secondary, 0.6),
            fontSize: 11.5,
            fontWeight: 500,
          }}
        >
          {COMPANY_NAME} — Internal security platform
        </Typography>
      </Stack>
    </Box>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function LoginPage() {
  const navigate = useNavigate();
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";

  const [username, setUsername]         = React.useState("");
  const [password, setPassword]         = React.useState("");
  const [showPassword, setShowPassword] = React.useState(false);
  const [loading, setLoading]           = React.useState(false);
  const [error, setError]               = React.useState<string | null>(null);
  const [ssoLoading, setSsoLoading]     = React.useState(false);

  const { data: me, isLoading: meLoading } = useQuery({
    queryKey: ["me"],
    queryFn: getMe,
    retry: false,
  });

  // ── SSO callback handler ──────────────────────────────────────────────
  // The Django callback view redirects to:
  //   /login?sso=1#token=<knox>&expiry=<iso>     on success
  //   /login?sso_error=<reason>                  on failure
  //
  // The token is in the fragment so it never appears in server logs.
  // We consume it once, store it, clear the fragment, then navigate to /.
  React.useEffect(() => {
    const searchParams = new URLSearchParams(window.location.search);

    // ── SSO error from provider ──
    const ssoError = searchParams.get("sso_error");
    if (ssoError) {
      const messages: Record<string, string> = {
        provider_unavailable:    "SSO provider is currently unavailable.",
        state_mismatch:          "SSO session expired or invalid. Please try again.",
        nonce_mismatch:          "SSO response could not be verified. Please try again.",
        token_exchange_failed:   "SSO authentication failed. Please try again.",
        userinfo_failed:         "Could not retrieve your account details from SSO.",
        user_resolution_failed:  "Could not link your SSO account. Contact your administrator.",
        account_disabled:        "Your account is disabled. Contact your administrator.",
      };
      setError(messages[ssoError] ?? `SSO error: ${ssoError}`);
      // Clean up the URL
      window.history.replaceState({}, "", "/login");
      return;
    }

    // ── SSO success — token in fragment ──
    const isSsoCallback = searchParams.get("sso") === "1";
    if (!isSsoCallback) return;

    setSsoLoading(true);
    const fragment = new URLSearchParams(window.location.hash.slice(1));
    const token    = fragment.get("token");
    const expiry   = fragment.get("expiry") ?? null;

    // Immediately wipe the fragment from the browser URL bar
    window.history.replaceState({}, "", "/login");

    if (!token) {
      setError("SSO login failed — no token received. Please try again.");
      setSsoLoading(false);
      return;
    }

    // Store the token (same mechanism as password login)
    setAccessToken(token);

    // Hydrate semantic colors from the server now that we have a valid token
    hydrateColorsAfterSso();

    navigate("/", { replace: true });
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Already authenticated — redirect home
  React.useEffect(() => {
    if (me) navigate("/", { replace: true });
  }, [me, navigate]);

  function onSSO() {
    window.location.assign("/api/oidc/login/");
  }

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      await login(username, password);
      navigate("/", { replace: true });
    } catch (err: any) {
      const msg =
        err?.response?.data?.detail ||
        err?.response?.data?.non_field_errors?.[0] ||
        "Login failed. Check your credentials or contact your administrator.";
      setError(msg);
    } finally {
      setLoading(false);
    }
  }

  if (meLoading || ssoLoading) {
    return (
      <Box
        sx={{
          minHeight: "100vh",
          display: "grid",
          placeItems: "center",
          bgcolor: "background.default",
        }}
      >
        <CircularProgress />
      </Box>
    );
  }

  if (me) return null;

  return (
    <Box
      sx={{
        minHeight: "100vh",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        position: "relative",
        px: { xs: 2, sm: 3 },
        py: 4,
      }}
    >
      {/* Animated ambient background */}
      <AmbientBackground />

      {/* Outer card — wraps side panel + login form */}
      <Box
        sx={{
          position: "relative",
          zIndex: 1,
          width: "100%",
          maxWidth: { xs: 440, lg: 800 },
          borderRadius: 5,
          overflow: "hidden",
          border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.25 : 0.8)}`,
          background: isDark
            ? alpha(theme.palette.background.paper, 0.55)
            : alpha(theme.palette.background.paper, 0.75),
          backdropFilter: "blur(32px)",
          WebkitBackdropFilter: "blur(32px)",
          boxShadow: isDark
            ? `0 32px 100px ${alpha("#000", 0.5)}, 0 0 0 1px ${alpha(theme.palette.primary.main, 0.08)}`
            : `0 32px 100px ${alpha("#000", 0.12)}, 0 0 0 1px ${alpha(theme.palette.primary.main, 0.06)}`,
          display: "flex",
        }}
      >

        {/* Right: login form */}
        <Box
          sx={{
            flex: 1,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            p: { xs: 3, sm: 4 },
            // Subtle inner separator on desktop
            borderLeft: {
              lg: `1px solid ${alpha(theme.palette.divider, isDark ? 0.22 : 0.6)}`,
            },
          }}
        >
          <LoginCard
            onSubmit={onSubmit}
            loading={loading}
            error={error}
            username={username}
            setUsername={setUsername}
            password={password}
            setPassword={setPassword}
            showPassword={showPassword}
            setShowPassword={setShowPassword}
            onSSO={onSSO}
          />
        </Box>
      </Box>
    </Box>
  );
}