import { type ReactNode } from "react";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createTheme, ThemeProvider } from "@mui/material/styles";
import { CssBaseline } from "@mui/material";
import { SnackbarProvider } from "notistack";
import { render, type RenderOptions } from "@testing-library/react";

const testTheme = createTheme();

export function createTestQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: 0, staleTime: 0 },
      mutations: { retry: false },
    },
  });
}

function AllProviders({
  children,
  initialPath = "/",
}: {
  children: ReactNode;
  initialPath?: string;
}) {
  const qc = createTestQueryClient();
  return (
    <QueryClientProvider client={qc}>
      <ThemeProvider theme={testTheme}>
        <CssBaseline />
        <SnackbarProvider maxSnack={3}>
          <MemoryRouter initialEntries={[initialPath]}>{children}</MemoryRouter>
        </SnackbarProvider>
      </ThemeProvider>
    </QueryClientProvider>
  );
}

export function renderWithProviders(
  ui: React.ReactElement,
  {
    initialPath,
    ...options
  }: { initialPath?: string } & RenderOptions = {}
) {
  const queryClient = createTestQueryClient();
  return render(ui, {
    wrapper: ({ children }) => (
      <QueryClientProvider client={queryClient}>
        <ThemeProvider theme={testTheme}>
          <CssBaseline />
          <SnackbarProvider maxSnack={3}>
            <MemoryRouter initialEntries={[initialPath ?? "/"]}>
              {children}
            </MemoryRouter>
          </SnackbarProvider>
        </ThemeProvider>
      </QueryClientProvider>
    ),
    ...options,
  });
}

export const mockMe = {
  id: 1,
  username: "alice",
  email: "alice@example.com",
  first_name: "Alice",
  last_name: "Smith",
  groups: ["CERT"],
  semantic_colors: undefined,
  theme: undefined,
  auto_seasonal: false,
} as const;

export const mockMeBasic = {
  ...mockMe,
  groups: [],
} as const;
