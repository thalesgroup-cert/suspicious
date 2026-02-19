import { api } from "./client";

export type Me = {
  id: number;
  username: string;
  email?: string;
  first_name?: string;
  last_name?: string;
  groups?: string[];
  ciso_scope?: string;
};

export async function getMe(): Promise<Me> {
  const res = await api.get("/auth/me/");
  return res.data as Me;
}


export async function login(input: {
  username: string;
  password: string;
}): Promise<{ access?: string }> {
  const res = await api.post("/auth/login/", input);
  return res.data;
}
