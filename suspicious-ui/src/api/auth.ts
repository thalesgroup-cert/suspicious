import { api, setAccessToken } from "@/api/client";
import { endpoints } from "@/api/endpoints";

export type Me = {
  id: number;
  username: string;
  email: string;
  first_name?: string;
  last_name?: string;
  groups: string[];
  ciso_scope?: string;
};

export type LoginResponse = {
  token: string;
  expiry: string | null;
  user: {
    id: number;
    username: string;
    email: string;
    first_name?: string;
    last_name?: string;
    groups: string[];
  };
};

export async function login(username: string, password: string): Promise<LoginResponse> {
  const res = await api.post<LoginResponse>(endpoints.login, {
    username,
    password,
  });

  setAccessToken(res.data.token);
  return res.data;
}

export async function logout(): Promise<void> {
  try {
    await api.post(endpoints.logout);
  } finally {
    setAccessToken(null);
  }
}

export async function getMe(): Promise<Me> {
  const res = await api.get<Me>(endpoints.me);
  return res.data;
}