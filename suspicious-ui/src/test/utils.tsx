import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { CssBaseline } from "@mui/material";
import { SnackbarProvider } from "notistack";
import { render, type RenderOptions } from "@testing-library/react";
import { AppThemeProvider } from "@/styles/ThemeStore";

export function createTestQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: 0, staleTime: 0 },
      mutations: { retry: false },
    },
  });
}

export function renderWithProviders(
  ui: React.ReactElement,
  {
    initialPath,
    queryClient = createTestQueryClient(),
    ...options
  }: { initialPath?: string; queryClient?: QueryClient } & RenderOptions = {}
) {
  return render(ui, {
    wrapper: ({ children }) => (
      <QueryClientProvider client={queryClient}>
        <AppThemeProvider>
          <CssBaseline />
          <SnackbarProvider maxSnack={3}>
            <MemoryRouter initialEntries={[initialPath ?? "/"]}>
              {children}
            </MemoryRouter>
          </SnackbarProvider>
        </AppThemeProvider>
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
};
