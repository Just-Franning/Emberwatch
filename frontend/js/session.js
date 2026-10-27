// The signed-in account (name, role) and the sign-in mode. The server checks the role of every request (auth.allowed);
// here the interface only hides what a viewer ("read access") cannot use: body.role-viewer and isAdmin().
import { api } from "./util.js";

export const me = { mode: "password", name: null, role: "admin" };

export async function loadSession() {
  const s = await api("api/auth/status");
  me.mode = s.mode;
  me.name = s.user?.name || null;
  me.role = s.user?.role === "viewer" ? "viewer" : "admin";
  document.body.classList.toggle("role-viewer", me.role === "viewer");
  document.body.classList.toggle("role-admin", me.role === "admin");
  document.body.classList.toggle("accounts-on", me.mode === "password");
  return me;
}

export const isAdmin = () => me.role === "admin";
export const accounts = () => me.mode === "password";
