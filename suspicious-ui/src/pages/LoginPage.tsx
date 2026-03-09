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
import {
  LockOutlined,
  SecurityOutlined,
  Visibility,
  VisibilityOff,
} from "@mui/icons-material";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { getMe, login } from "@/api/auth";

const COMPANY_NAME = import.meta.env.VITE_COMPANY_NAME ?? "Company";
const COMPANY_LINK = import.meta.env.VITE_COMPANY_LINK ?? "/";
const COMPANY_LOGO_BASE64 = import.meta.env.VITE_COMPANY_LOGO_BASE64 as
  | string
  | undefined;
const COMPANY_LOGO_URL = import.meta.env.VITE_COMPANY_LOGO_URL as
  | string
  | undefined;

function BrandHeader() {
  const logoSrc = COMPANY_LOGO_BASE64 || COMPANY_LOGO_URL;

  return (
    <Stack spacing={1.1} alignItems="center">
      <Box
        component="a"
        href={COMPANY_LINK}
        target="_blank"
        rel="noreferrer"
        sx={{
          display: "inline-flex",
          alignItems: "center",
          gap: 1.25,
          textDecoration: "none",
          px: 1,
          py: 0.5,
          borderRadius: 2,
          "&:hover": { bgcolor: "rgba(255,255,255,.04)" },
        }}
      >
        {logoSrc ? (
          <Box
            component="img"
            src={logoSrc}
            alt={`${COMPANY_NAME} logo`}
            sx={{
              height: 34,
              width: "auto",
              display: "block",
              filter: "drop-shadow(0 6px 14px rgba(0,0,0,.25))",
            }}
          />
        ) : null}
      </Box>

      <Box
        sx={{
          width: 54,
          height: 54,
          borderRadius: 16,
          display: "grid",
          placeItems: "center",
          background:
            "linear-gradient(135deg, rgba(56,189,248,.25), rgba(120,119,198,.25))",
          border: "1px solid rgba(255,255,255,.16)",
        }}
      >
        <LockOutlined />
      </Box>

      <Stack spacing={0.25} alignItems="center">
        <Typography variant="h5" fontWeight={750}>
          Sign in
        </Typography>
        <Typography variant="body2" color="text.secondary">
          Access the Suspicious app
        </Typography>
      </Stack>
    </Stack>
  );
}

export default function LoginPage() {
  const navigate = useNavigate();

  const [username, setUsername] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [showPassword, setShowPassword] = React.useState(false);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  const { data: me, isLoading: meLoading } = useQuery({
    queryKey: ["me"],
    queryFn: getMe,
    retry: false,
  });

  React.useEffect(() => {
    if (me) navigate("/", { replace: true });
  }, [me, navigate]);

  function onSSO() {
    window.location.assign("/oidc/login/");
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
        "Login failed. Check credentials or server configuration.";
      setError(msg);
    } finally {
      setLoading(false);
    }
  }

  if (meLoading) {
    return (
      <Box sx={{ minHeight: "100vh", display: "grid", placeItems: "center" }}>
        <CircularProgress />
      </Box>
    );
  }

  if (me) return null;

  return (
    <Box
      sx={{
        minHeight: "100vh",
        display: "grid",
        placeItems: "center",
        px: 2,
        position: "relative",
        overflow: "hidden",
        bgcolor: "background.default",
      }}
    >
      <Box
        aria-hidden
        sx={{
          position: "absolute",
          inset: 0,
          background:
            "radial-gradient(1200px 600px at 20% 10%, rgba(120,119,198,.35), transparent 60%)," +
            "radial-gradient(900px 500px at 80% 30%, rgba(56,189,248,.25), transparent 60%)," +
            "radial-gradient(1000px 700px at 50% 90%, rgba(34,197,94,.12), transparent 60%)",
          filter: "saturate(120%)",
          transform: "scale(1.05)",
        }}
      />
      <Box
        aria-hidden
        sx={{
          position: "absolute",
          inset: 0,
          backgroundImage:
            "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='240' height='240'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.8' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='240' height='240' filter='url(%23n)' opacity='.18'/%3E%3C/svg%3E\")",
          opacity: 0.25,
          mixBlendMode: "overlay",
          pointerEvents: "none",
        }}
      />

      <Box
        sx={{
          width: "100%",
          maxWidth: 440,
          position: "relative",
          borderRadius: 4,
          p: 3.5,
          boxShadow: "0 24px 80px rgba(0,0,0,.35)",
          border: "1px solid",
          borderColor: "rgba(255,255,255,.12)",
          background:
            "linear-gradient(180deg, rgba(255,255,255,.10), rgba(255,255,255,.06))",
          backdropFilter: "blur(18px)",
        }}
      >
        <Stack spacing={2.25}>
          <BrandHeader />

          {error && <Alert severity="error">{error}</Alert>}

          <Box component="form" onSubmit={onSubmit} noValidate>
            <Stack spacing={1.6}>
              <TextField
                label="Username"
                autoComplete="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                fullWidth
              />

              <TextField
                label="Password"
                autoComplete="current-password"
                type={showPassword ? "text" : "password"}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                fullWidth
                InputProps={{
                  endAdornment: (
                    <InputAdornment position="end">
                      <IconButton
                        aria-label={showPassword ? "Hide password" : "Show password"}
                        onClick={() => setShowPassword((v) => !v)}
                        edge="end"
                      >
                        {showPassword ? <VisibilityOff /> : <Visibility />}
                      </IconButton>
                    </InputAdornment>
                  ),
                }}
              />

              <Button
                type="submit"
                size="large"
                variant="contained"
                disabled={loading || !username || !password}
                sx={{
                  py: 1.2,
                  borderRadius: 3,
                  textTransform: "none",
                  fontWeight: 750,
                }}
              >
                {loading ? (
                  <Stack direction="row" spacing={1} alignItems="center">
                    <CircularProgress size={18} />
                    <span>Signing in…</span>
                  </Stack>
                ) : (
                  "Sign in"
                )}
              </Button>

              <Divider sx={{ opacity: 0.35 }} />

              <Button
                variant="outlined"
                size="large"
                onClick={onSSO}
                startIcon={<SecurityOutlined />}
                sx={{
                  py: 1.1,
                  borderRadius: 3,
                  textTransform: "none",
                  fontWeight: 750,
                  borderColor: "rgba(255,255,255,.18)",
                  bgcolor: "rgba(255,255,255,.04)",
                  "&:hover": {
                    bgcolor: "rgba(255,255,255,.07)",
                    borderColor: "rgba(255,255,255,.28)",
                  },
                }}
              >
                Continue with SSO
              </Button>

              <Typography
                variant="caption"
                color="text.secondary"
                sx={{ textAlign: "center" }}
              >
                {COMPANY_NAME}
              </Typography>
            </Stack>
          </Box>
        </Stack>
      </Box>
    </Box>
  );
}