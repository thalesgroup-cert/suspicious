import axios from "axios";

let accessToken: string | null = localStorage.getItem("token");

export function setAccessToken(token: string | null) {
  accessToken = token;

  if (token) {
    localStorage.setItem("token", token);
  } else {
    localStorage.removeItem("token");
  }
}

export function getAccessToken() {
  return accessToken;
}

const baseURL = import.meta.env.VITE_API_BASE ?? "/api";

export const api = axios.create({
  baseURL,
  withCredentials: true,
});

api.interceptors.request.use((config) => {
  if (accessToken) {
    config.headers.Authorization = `Token ${accessToken}`;
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    if (error.response?.status === 401) {
      setAccessToken(null);
    }
    throw error;
  }
);