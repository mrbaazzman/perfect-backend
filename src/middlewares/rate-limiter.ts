import rateLimit from "express-rate-limit";

export const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 100,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  // Page-load bootstrap (`/auth/session`) is a cheap, cookie-gated read that
  // only returns the caller's own data — exempt so refresh-spam can't trip it.
  skip: (req) => req.path === "/auth/session",
  message: { error: "Too many requests, please try again later.", code: "RATE_LIMITED" },
});

// Stricter throttle for auth endpoints (login/register brute-force mitigation).
export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "Too many attempts, please try again later.", code: "RATE_LIMITED" },
});
