import type { Response } from "express";
import { env, refreshTokenLifetimeMs } from "../config/env.js";

export const REFRESH_COOKIE = "refreshToken";

export function refreshCookieOptions(remember: boolean) {
  return {
    httpOnly: true,
    secure: env.NODE_ENV === "production",
    sameSite: "lax" as const,
    path: "/api/auth",
    maxAge: remember ? refreshTokenLifetimeMs : undefined,
  };
}

export function setRefreshCookie(res: Response, token: string, remember: boolean) {
  res.cookie(REFRESH_COOKIE, token, refreshCookieOptions(remember));
}

export function clearRefreshCookie(res: Response) {
  res.clearCookie(REFRESH_COOKIE, refreshCookieOptions(false));
}
