import axios from "axios";

let accessToken: string | null = null;
export function setAccessToken(token: string | null) {
  accessToken = token;
}

const baseURL = import.meta.env.VITE_API_BASE ?? "/api";

export const api = axios.create({
  baseURL,
  withCredentials: true
});

api.interceptors.request.use((config) => {
  if (accessToken) config.headers.Authorization = `Bearer ${accessToken}`;
  return config;
});

let refreshing: Promise<void> | null = null;

api.interceptors.response.use(
  (r) => r,
  async (error) => {
    const original = error.config;
    if (error.response?.status !== 401 || original?._retry) throw error;

    original._retry = true;

    if (!refreshing) {
      refreshing = api
        .post("/auth/refresh/")
        .then((res) => setAccessToken(res.data.access))
        .finally(() => {
          refreshing = null;
        });
    }

    await refreshing;
    return api(original);
  }
);
