import { MemoryRouter, RouterProvider, createMemoryRouter } from "react-router";
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

/**
 * `routePath` switches to a data router (needed by useBlocker, which a plain
 * MemoryRouter cannot host) and mounts `ui` on that route pattern. The router
 * is returned so tests can assert on the URL and drive history.
 */
export function renderWithProviders(
  ui: React.ReactElement,
  {
    initialPath,
    routePath,
    queryClient = createTestQueryClient(),
    ...options
  }: { initialPath?: string; routePath?: string; queryClient?: QueryClient } & RenderOptions = {}
) {
  const router = routePath
    ? createMemoryRouter([{ path: routePath, element: ui }], { initialEntries: [initialPath ?? "/"] })
    : null;
  const result = render(ui, {
    wrapper: ({ children }) => (
      <QueryClientProvider client={queryClient}>
        <AppThemeProvider>
          <CssBaseline />
          <SnackbarProvider maxSnack={3}>
            {router ? (
              <RouterProvider router={router} />
            ) : (
              <MemoryRouter initialEntries={[initialPath ?? "/"]}>{children}</MemoryRouter>
            )}
          </SnackbarProvider>
        </AppThemeProvider>
      </QueryClientProvider>
    ),
    ...options,
  });
  return Object.assign(result, { router });
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
