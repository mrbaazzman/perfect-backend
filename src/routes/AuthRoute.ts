import { Router } from "express";
import * as auth from "../controllers/AuthController.js";
import { clearRefreshCookie, REFRESH_COOKIE, setRefreshCookie } from "../middlewares/cookies.js";
import { ApiError } from "../middlewares/error-handler.js";
import { registerSchema, credentialsSchema } from "../schemas/authSchemas.js";

const router = Router();

router.post("/register", async (req, res) => {
  const body = registerSchema.parse(req.body);
  const result = await auth.register(body);
  setRefreshCookie(res, result.refreshToken, result.remember);
  res.status(201).json({ user: result.user, accessToken: result.accessToken });
});

router.post("/login", async (req, res) => {
  const body = credentialsSchema.parse(req.body);
  const result = await auth.login(body);
  setRefreshCookie(res, result.refreshToken, result.remember);
  res.json({ user: result.user, accessToken: result.accessToken });
});

router.post("/refresh", async (req, res) => {
  const refreshToken = req.cookies?.[REFRESH_COOKIE];
  if (!refreshToken) {
    throw new ApiError(401, "No refresh token", "NO_REFRESH_TOKEN");
  }
  const result = await auth.refresh(refreshToken);
  setRefreshCookie(res, result.refreshToken, result.remember);
  res.json({ user: result.user, accessToken: result.accessToken });
});

router.post("/logout", async (req, res) => {
  await auth.logout(req.cookies?.[REFRESH_COOKIE]);
  clearRefreshCookie(res);
  res.status(204).end();
});

router.get("/session", async (req, res) => {
  const result = await auth.session(req.cookies?.[REFRESH_COOKIE]);
  res.json(result);
});

export const authRouter = router;
