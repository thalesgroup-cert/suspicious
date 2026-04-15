import axios from "axios";

const baseURL = import.meta.env.VITE_API_BASE ?? "/api";

// withCredentials ensures the httpOnly knox_token cookie is included on every
// request. The token is never stored in localStorage or JS memory.
export const api = axios.create({
  baseURL,
  withCredentials: true,
});

