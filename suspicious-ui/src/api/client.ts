import axios from "axios";
import { env } from "@/lib/runtimeEnv";

const baseURL = env("VITE_API_BASE") ?? "/api";

export const api = axios.create({
  baseURL,
  withCredentials: true,
});

