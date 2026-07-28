import * as React from "react";
import {
  Alert,
  Box,
  Button,
  CircularProgress,
  IconButton,
  InputAdornment,
  Link,
  Stack,
  TextField,
  Typography,
  useMediaQuery,
} from "@mui/material";
import { alpha, useTheme } from "@mui/material/styles";
import {
  SecurityOutlined,
  Visibility,
  VisibilityOff,
  ArrowForwardOutlined,
  KeyboardCapslockOutlined,
  ShieldOutlined,
  BoltOutlined,
  HubOutlined,
} from "@mui/icons-material";
import { useNavigate } from "react-router";
import { useQuery } from "@tanstack/react-query";
import {
  motion,
  AnimatePresence,
  useReducedMotion,
  type Variants,
} from "framer-motion";
import { getMe, login, hydrateColorsAfterSso } from "@/api/auth";

import {
  COMPANY_LINK,
  COMPANY_LOGO_BASE64,
  COMPANY_LOGO_URL,
  COMPANY_NAME,
  SUPPORT_EMAIL,
  initialSsoError,
} from "@/features/login/config";
import {
  Background,
  BrandStamp,
  FeatureMosaic,
  StatusPill,
} from "@/features/login/components/decor";

const MotionBox = motion(Box);

// ─── Visually hidden helper ────────────────────────────────────────────────

const srOnly: React.CSSProperties = {
  position: "absolute",
  width: 1,
  height: 1,
  padding: 0,
  margin: -1,
  overflow: "hidden",
  clip: "rect(0, 0, 0, 0)",
  whiteSpace: "nowrap",
  border: 0,
};

// ─── Main page ────────────────────────────────────────────────────────────

export default function LoginPage() {
  const navigate = useNavigate();
  const theme = useTheme();
  const isDark = theme.palette.mode === "dark";
  const reduce = useReducedMotion();
  const isDesktop = useMediaQuery(theme.breakpoints.up("md"));

  const [username, setUsername]         = React.useState("");
  const [password, setPassword]         = React.useState("");
  const [showPassword, setShowPassword] = React.useState(false);
  const [loading, setLoading]           = React.useState(false);
  const [error, setError]               = React.useState<string | null>(initialSsoError);
  const [ssoLoading, setSsoLoading]     = React.useState(
    () => new URLSearchParams(window.location.search).get("sso") === "1"
  );

  const [passwordMode, setPasswordMode] = React.useState(false);

  const [capsLock, setCapsLock] = React.useState(false);
  const onPasswordKey = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (typeof e.getModifierState === "function") {
      setCapsLock(e.getModifierState("CapsLock"));
    }
  };

  const { data: me, isLoading: meLoading } = useQuery({
    queryKey: ["me"],
    queryFn: getMe,
    retry: false,
  });

  React.useEffect(() => {
    const searchParams = new URLSearchParams(window.location.search);

    const ssoError = searchParams.get("sso_error");
    if (ssoError) {
      window.history.replaceState({}, "", "/login");
      return;
    }

    const isSsoCallback = searchParams.get("sso") === "1";
    if (!isSsoCallback) return;

    window.history.replaceState({}, "", "/login");
    hydrateColorsAfterSso().finally(() => {
      navigate("/", { replace: true });
      setSsoLoading(false);
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  React.useEffect(() => {
    if (me) navigate("/", { replace: true });
  }, [me, navigate]);

  function onSSO() {
    setSsoLoading(true);
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
      const upstream =
        err?.response?.data?.detail ||
        err?.response?.data?.non_field_errors?.[0];
      setError(
        upstream && /disabled|locked|inactive/i.test(upstream)
          ? upstream
          : "Sign-in failed. Check your credentials and try again."
      );
    } finally {
      setLoading(false);
    }
  }

  const stagger: Variants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        staggerChildren: reduce ? 0 : 0.06,
        delayChildren: reduce ? 0 : 0.08,
      },
    },
  };
  const item: Variants = {
    hidden: reduce ? { opacity: 0 } : { opacity: 0, y: 10 },
    visible: reduce
      ? { opacity: 1 }
      : {
          opacity: 1,
          y: 0,
          transition: { type: "spring", stiffness: 280, damping: 24 },
        },
  };

  // ─── Loading & redirect guards ──────────────────────────────────────────

  if (meLoading || (ssoLoading && !error)) {
    return (
      <Box
        sx={{
          minHeight: "100vh",
          display: "grid",
          placeItems: "center",
          bgcolor: "background.default",
        }}
        role="status"
        aria-live="polite"
      >
        <CircularProgress aria-label="Loading" />
        <span style={srOnly}>
          {ssoLoading ? "Signing in via SSO…" : "Loading…"}
        </span>
      </Box>
    );
  }
  if (me) return null;

  // ─── Render ─────────────────────────────────────────────────────────────

  const p = theme.palette.primary.main;
  const errorId = "signin-error";
  const headingId = "signin-heading";
  const capsId = "signin-capslock";

  return (
    <Box
      component="main"
      sx={{
        minHeight: "100vh",
        display: "flex",
        flexDirection: "column",
        position: "relative",
        px: { xs: 2.5, sm: 4 },
        py: { xs: 3, sm: 4 },
      }}
    >
      <h1 style={srOnly}>Sign in to {COMPANY_NAME} Suspicious</h1>

      <Background />

      {/* ── Top bar ──────────────────────────────────────────────────── */}
      <MotionBox
        initial={reduce ? { opacity: 1 } : { opacity: 0, y: -8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
        sx={{
          position: "relative",
          zIndex: 1,
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          mb: { xs: 3, md: 0 },
        }}
      >
        <BrandStamp size="lg" />
        <StatusPill />
      </MotionBox>

      {/* ── Main content ────────────────────────────────────────────── */}
      <Box
        sx={{
          flex: 1,
          position: "relative",
          zIndex: 1,
          display: "grid",
          gridTemplateColumns: { xs: "1fr", md: "1fr 1fr" },
          alignItems: "center",
          justifyItems: "center",
          gap: { xs: 4, md: 6 },
          maxWidth: 1240,
          width: "100%",
          mx: "auto",
          py: { xs: 2, md: 4 },
        }}
      >
        {isDesktop && (
          <MotionBox
            variants={stagger}
            initial="hidden"
            animate="visible"
            sx={{ width: "100%", maxWidth: 520 }}
          >
            <MotionBox variants={item}>
              <Typography
                component="p"
                sx={{
                  fontWeight: 700,
                  fontSize: 12,
                  letterSpacing: "0.22em",
                  textTransform: "uppercase",
                  color: p,
                  mb: 2,
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 1,
                  "&::before": {
                    content: '""',
                    width: 22,
                    height: 2,
                    bgcolor: p,
                    borderRadius: 1,
                  },
                }}
              >
                Phishing &amp; Threat Check
              </Typography>
            </MotionBox>

            <MotionBox variants={item}>
              <Typography
                component="h2"
                sx={{
                  fontWeight: 950,
                  fontSize: { md: 40, lg: 48 },
                  lineHeight: 1.05,
                  letterSpacing: "-0.035em",
                  color: "text.primary",
                  mb: 2,
                }}
              >
                Seen something suspicious?<br />
                <Box
                  component="span"
                  sx={{
                    background: `linear-gradient(135deg, ${p}, ${alpha(p, 0.55)})`,
                    WebkitBackgroundClip: "text",
                    WebkitTextFillColor: "transparent",
                    backgroundClip: "text",
                  }}
                >
                  Let us check it for you.
                </Box>
              </Typography>
            </MotionBox>

            <MotionBox variants={item}>
              <Typography
                sx={{
                  fontSize: 15,
                  lineHeight: 1.6,
                  color: "text.secondary",
                  maxWidth: 460,
                  mb: 4,
                }}
              >
                Forward a doubtful email, paste a link you're not sure about,
                or drop in a file. We'll analyze it and tell you whether
                it's safe.
              </Typography>
            </MotionBox>

            <FeatureMosaic itemVariants={item} />
          </MotionBox>
        )}

        <MotionBox
          variants={stagger}
          initial="hidden"
          animate="visible"
          sx={{ width: "100%", maxWidth: 520 }}
        >
          <MotionBox
            variants={item}
            sx={{
              position: "relative",
              borderRadius: 4,
              p: { xs: 3, sm: 5 },
              border: `1px solid ${alpha(theme.palette.divider, isDark ? 0.22 : 0.7)}`,
              background: isDark
                ? `linear-gradient(180deg, ${alpha(theme.palette.background.paper, 0.7)}, ${alpha(theme.palette.background.paper, 0.55)})`
                : `linear-gradient(180deg, ${alpha("#fff", 0.92)}, ${alpha("#fff", 0.85)})`,
              backdropFilter: "blur(24px)",
              WebkitBackdropFilter: "blur(24px)",
              boxShadow: isDark
                ? `0 32px 80px ${alpha("#000", 0.45)}, inset 0 1px 0 ${alpha("#fff", 0.04)}`
                : `0 32px 80px ${alpha(p, 0.1)}, 0 1px 0 ${alpha("#fff", 0.6)} inset`,
              overflow: "hidden",
              "&::after": {
                content: '""',
                position: "absolute",
                top: -80,
                right: -80,
                width: 240,
                height: 240,
                borderRadius: "50%",
                background: `radial-gradient(circle, ${alpha(p, isDark ? 0.25 : 0.15)} 0%, transparent 60%)`,
                pointerEvents: "none",
              },
            }}
          >
            <Stack spacing={0.75} sx={{ mb: 3 }}>
              <Typography
                id={headingId}
                component="h2"
                sx={{
                  fontWeight: 950,
                  fontSize: 28,
                  letterSpacing: "-0.025em",
                  lineHeight: 1.1,
                }}
              >
                Welcome back
              </Typography>
              <Typography
                sx={{
                  fontSize: 14.5,
                  color: "text.secondary",
                  lineHeight: 1.5,
                }}
              >
                Sign in with your work account to get started.
              </Typography>
            </Stack>

            <Box
              id={errorId}
              role={error ? "alert" : undefined}
              aria-live="polite"
              aria-atomic="true"
              sx={{ mb: error ? 2.5 : 0 }}
            >
              <AnimatePresence>
                {error ? (
                  <MotionBox
                    key="err"
                    initial={{ opacity: 0, y: -6, height: 0 }}
                    animate={{ opacity: 1, y: 0, height: "auto" }}
                    exit={{ opacity: 0, height: 0 }}
                    transition={{ duration: 0.22 }}
                  >
                    <Alert
                      severity="error"
                      variant="outlined"
                      sx={{
                        borderRadius: 2.5,
                        background: alpha(
                          theme.palette.error.main,
                          isDark ? 0.08 : 0.05
                        ),
                        "& .MuiAlert-message": { fontSize: 13.5 },
                      }}
                    >
                      {error}
                    </Alert>
                  </MotionBox>
                ) : null}
              </AnimatePresence>
            </Box>

            <MotionBox
              whileHover={reduce ? undefined : { y: -1 }}
              whileTap={reduce ? undefined : { y: 0, scale: 0.995 }}
            >
              <Button
                onClick={onSSO}
                disabled={ssoLoading}
                aria-busy={ssoLoading}
                size="large"
                fullWidth
                startIcon={
                  ssoLoading ? (
                    <CircularProgress size={18} color="inherit" aria-hidden />
                  ) : (
                    <SecurityOutlined sx={{ fontSize: "20px !important" }} />
                  )
                }
                endIcon={
                  !ssoLoading && (
                    <ArrowForwardOutlined sx={{ fontSize: "18px !important" }} />
                  )
                }
                sx={{
                  height: 56,
                  borderRadius: 3,
                  textTransform: "none",
                  fontWeight: 800,
                  fontSize: 15.5,
                  letterSpacing: "-0.01em",
                  color: theme.palette.primary.contrastText,
                  background: `linear-gradient(135deg, ${p} 0%, ${alpha(p, 0.78)} 100%)`,
                  boxShadow: `0 8px 24px ${alpha(p, isDark ? 0.4 : 0.3)}, 0 1px 0 ${alpha("#fff", 0.2)} inset`,
                  "&:hover": {
                    background: `linear-gradient(135deg, ${alpha(p, 0.95)} 0%, ${alpha(p, 0.7)} 100%)`,
                    boxShadow: `0 12px 32px ${alpha(p, isDark ? 0.5 : 0.4)}, 0 1px 0 ${alpha("#fff", 0.25)} inset`,
                  },
                  "&:disabled": {
                    background: alpha(theme.palette.text.primary, isDark ? 0.1 : 0.08),
                    color: alpha(theme.palette.text.primary, 0.4),
                    boxShadow: "none",
                  },
                  transition: theme.transitions.create(
                    ["background", "box-shadow"],
                    { duration: 180 }
                  ),
                  "& .MuiButton-endIcon": { transition: "transform 0.2s" },
                  "&:hover .MuiButton-endIcon": { transform: "translateX(3px)" },
                }}
              >
                {ssoLoading ? "Redirecting…" : "Continue with SSO"}
              </Button>
            </MotionBox>

            <Typography
              sx={{
                mt: 1.25,
                textAlign: "center",
                fontSize: 12,
                color: "text.secondary",
              }}
            >
              Same login you use for other {COMPANY_NAME} apps.
            </Typography>

            <Box
              role="separator"
              aria-orientation="horizontal"
              sx={{
                my: 2.5,
                display: "flex",
                alignItems: "center",
                gap: 1.5,
              }}
            >
              <Box
                aria-hidden
                sx={{
                  flex: 1,
                  height: 1,
                  bgcolor: alpha(theme.palette.divider, isDark ? 0.3 : 0.6),
                }}
              />
              <Typography
                variant="caption"
                sx={{
                  fontWeight: 600,
                  fontSize: 10.5,
                  letterSpacing: "0.18em",
                  textTransform: "uppercase",
                  color: alpha(theme.palette.text.secondary, 0.7),
                }}
              >
                Or
              </Typography>
              <Box
                aria-hidden
                sx={{
                  flex: 1,
                  height: 1,
                  bgcolor: alpha(theme.palette.divider, isDark ? 0.3 : 0.6),
                }}
              />
            </Box>

            <AnimatePresence initial={false} mode="wait">
              {!passwordMode ? (
                <MotionBox
                  key="trigger"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  transition={{ duration: 0.18 }}
                >
                  <Button
                    onClick={() => setPasswordMode(true)}
                    variant="text"
                    fullWidth
                    aria-expanded={false}
                    aria-controls="password-panel"
                    sx={{
                      height: 48,
                      borderRadius: 2.5,
                      textTransform: "none",
                      fontWeight: 700,
                      fontSize: 14,
                      color: "text.secondary",
                      border: `1px dashed ${alpha(theme.palette.divider, isDark ? 0.4 : 0.7)}`,
                      "&:hover": {
                        background: alpha(p, isDark ? 0.08 : 0.04),
                        borderColor: alpha(p, 0.5),
                        color: "text.primary",
                      },
                    }}
                  >
                    Sign in with username and password
                  </Button>
                </MotionBox>
              ) : (
                <MotionBox
                  key="panel"
                  id="password-panel"
                  initial={reduce ? { opacity: 0 } : { opacity: 0, height: 0 }}
                  animate={reduce ? { opacity: 1 } : { opacity: 1, height: "auto" }}
                  exit={reduce ? { opacity: 0 } : { opacity: 0, height: 0 }}
                  transition={{ duration: 0.28, ease: [0.22, 0.61, 0.36, 1] }}
                  sx={{ overflow: "hidden", paddingTop: 0.5, mt: 0.5 }}
                >
                  <Box
                    component="form"
                    onSubmit={onSubmit}
                    noValidate
                    aria-labelledby={headingId}
                    aria-describedby={error ? errorId : undefined}
                  >
                    <Stack spacing={1.75}>
                      <TextField
                        id="login-username"
                        label="Username"
                        autoComplete="username"
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        placeholder="your.email@company.com"
                        required
                        fullWidth
                        autoFocus
                        slotProps={{
                          htmlInput: {
                            autoCapitalize: "off",
                            autoCorrect: "off",
                            spellCheck: false,
                            "aria-required": true,
                          },
                        }}
                        sx={{
                          "& .MuiOutlinedInput-root": {
                            borderRadius: 2.5,
                            fontSize: 15,
                            height: 54,
                          },
                        }}
                      />

                      <TextField
                        id="login-password"
                        label="Password"
                        autoComplete="current-password"
                        type={showPassword ? "text" : "password"}
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        onKeyDown={onPasswordKey}
                        onKeyUp={onPasswordKey}
                        placeholder="••••••••"
                        required
                        fullWidth
                        helperText={
                          capsLock ? (
                            <Box
                              id={capsId}
                              component="span"
                              sx={{
                                display: "inline-flex",
                                alignItems: "center",
                                gap: 0.5,
                              }}
                            >
                              <KeyboardCapslockOutlined sx={{ fontSize: 14 }} />
                              Caps Lock is on
                            </Box>
                          ) : undefined
                        }
                        slotProps={{
                          htmlInput: {
                            "aria-required": true,
                            "aria-describedby": capsLock ? capsId : undefined,
                          },
                          input: {
                            endAdornment: (
                              <InputAdornment position="end">
                                <IconButton
                                  aria-label={
                                    showPassword
                                      ? "Hide password"
                                      : "Show password"
                                  }
                                  aria-pressed={showPassword}
                                  onClick={() => setShowPassword(!showPassword)}
                                  edge="end"
                                  size="small"
                                  sx={{ mr: 0.25 }}
                                >
                                  {showPassword ? (
                                    <VisibilityOff sx={{ fontSize: 19 }} />
                                  ) : (
                                    <Visibility sx={{ fontSize: 19 }} />
                                  )}
                                </IconButton>
                              </InputAdornment>
                            ),
                          },
                        }}
                        sx={{
                          "& .MuiOutlinedInput-root": {
                            borderRadius: 2.5,
                            fontSize: 15,
                            height: 54,
                          },
                        }}
                      />

                      <MotionBox
                        whileHover={reduce ? undefined : { y: -1 }}
                        whileTap={reduce ? undefined : { scale: 0.995 }}
                      >
                        <Button
                          type="submit"
                          size="large"
                          variant="contained"
                          fullWidth
                          disabled={loading || !username.trim() || !password}
                          aria-busy={loading}
                          endIcon={
                            loading ? (
                              <CircularProgress
                                size={16}
                                color="inherit"
                                aria-hidden
                              />
                            ) : (
                              <ArrowForwardOutlined
                                sx={{ fontSize: "18px !important" }}
                              />
                            )
                          }
                          sx={{
                            height: 52,
                            borderRadius: 2.5,
                            textTransform: "none",
                            fontWeight: 800,
                            fontSize: 15,
                            mt: 0.5,
                            background: theme.palette.text.primary,
                            color: theme.palette.background.paper,
                            "&:hover": {
                              background: alpha(theme.palette.text.primary, 0.88),
                            },
                            "&:disabled": {
                              background: alpha(
                                theme.palette.text.primary,
                                isDark ? 0.12 : 0.08
                              ),
                              color: alpha(theme.palette.text.primary, 0.4),
                            },
                          }}
                        >
                          {loading ? "Signing in…" : "Sign in"}
                        </Button>
                      </MotionBox>

                      <Button
                        type="button"
                        variant="text"
                        size="small"
                        onClick={() => {
                          setPasswordMode(false);
                          setPassword("");
                        }}
                        aria-expanded
                        aria-controls="password-panel"
                        sx={{
                          textTransform: "none",
                          fontSize: 12.5,
                          fontWeight: 600,
                          color: "text.secondary",
                          alignSelf: "center",
                          "&:hover": {
                            background: "transparent",
                            color: "text.primary",
                            textDecoration: "underline",
                          },
                        }}
                      >
                        ← Back to SSO
                      </Button>
                    </Stack>
                  </Box>
                </MotionBox>
              )}
            </AnimatePresence>
          </MotionBox>

          <MotionBox
            variants={item}
            sx={{
              mt: 2.5,
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              flexWrap: "wrap",
              gap: 1,
              px: 1,
            }}
          >
            <Typography sx={{ fontSize: 12.5, color: "text.secondary" }}>
              Trouble signing in?{" "}
              <Link
                href={`mailto:${SUPPORT_EMAIL}`}
                underline="hover"
                sx={{ fontWeight: 700, color: "text.primary" }}
              >
                Get Help
              </Link>
            </Typography>
            {(COMPANY_LOGO_BASE64 || COMPANY_LOGO_URL) && (
              <Box
                component="a"
                href={COMPANY_LINK}
                target="_blank"
                rel="noopener noreferrer"
                aria-label={COMPANY_NAME}
                sx={{
                  display: "inline-flex",
                  alignItems: "center",
                  opacity: 0.7,
                  transition: "opacity .2s",
                  "&:hover, &:focus-visible": { opacity: 1 },
                  "&:focus-visible": {
                    outline: `2px solid ${p}`,
                    outlineOffset: 4,
                    borderRadius: 1,
                  },
                }}
              >
                <Box
                  component="img"
                  src={COMPANY_LOGO_BASE64 || COMPANY_LOGO_URL}
                  alt={COMPANY_NAME}
                  sx={{
                    height: 20,
                    width: "auto",
                    filter: isDark ? "brightness(1.3)" : "none",
                  }}
                />
              </Box>
            )}
          </MotionBox>
        </MotionBox>
      </Box>

      {/* ── Footer ─────────────────────────────────────────────────────── */}
      <MotionBox
        initial={reduce ? { opacity: 1 } : { opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.5, duration: 0.4 }}
        sx={{
          position: "relative",
          zIndex: 1,
          mt: { xs: 3, md: 0 },
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexWrap: "wrap",
          gap: 1,
        }}
      >
        <Typography
          variant="caption"
          sx={{
            fontSize: 11,
            fontWeight: 600,
            letterSpacing: "0.08em",
            textTransform: "uppercase",
            color: alpha(theme.palette.text.secondary, 0.55),
          }}
        >
          © {new Date().getFullYear()} {COMPANY_NAME}
        </Typography>
        <Typography
          variant="caption"
          sx={{
            fontSize: 11,
            fontWeight: 600,
            letterSpacing: "0.08em",
            textTransform: "uppercase",
            color: alpha(theme.palette.text.secondary, 0.55),
          }}
        >
          Internal · Authorized access only
        </Typography>
      </MotionBox>
    </Box>
  );
}