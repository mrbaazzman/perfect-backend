import { Router } from "express";
import { authController } from "../controllers/AuthController.js";
import { userController } from "../controllers/UserController.js";
import { ApiError } from "../middlewares/error-handler.js";
import { requireAuth } from "../middlewares/auth.js";
import { clearRefreshCookie, REFRESH_COOKIE, setRefreshCookie } from "../middlewares/cookies.js";
import {
  registerSchema,
  credentialsSchema,
  updateProfileSchema,
  changePasswordSchema,
  currentPasswordSchema,
} from "../schemas/authSchemas.js";

const router = Router();

router.post("/register", async (req, res) => {
  const body = registerSchema.parse(req.body);
  const result = await authController.register(body);
  setRefreshCookie(res, result.refreshToken, result.remember);
  res.status(201).json({ user: result.user, accessToken: result.accessToken });
});

router.post("/login", async (req, res) => {
  const body = credentialsSchema.parse(req.body);
  const result = await authController.login(body);
  setRefreshCookie(res, result.refreshToken, result.remember);
  res.json({ user: result.user, accessToken: result.accessToken });
});

router.post("/refresh", async (req, res) => {
  const refreshToken = req.cookies?.[REFRESH_COOKIE];
  if (!refreshToken) {
    throw new ApiError(401, "No refresh token", "NO_REFRESH_TOKEN");
  }
  const result = await authController.refresh(refreshToken);
  setRefreshCookie(res, result.refreshToken, result.remember);
  res.json({ user: result.user, accessToken: result.accessToken });
});

router.post("/logout", async (req, res) => {
  await authController.logout(req.cookies?.[REFRESH_COOKIE]);
  clearRefreshCookie(res);
  res.status(204).end();
});

router.get("/session", async (req, res) => {
  const result = await authController.session(req.cookies?.[REFRESH_COOKIE]);
  res.json(result);
});

router.get("/me", requireAuth, async (req, res) => {
  const result = await userController.me(req.user!.id);
  res.json(result);
});

router.patch("/me", requireAuth, async (req, res) => {
  const body = updateProfileSchema.parse(req.body);
  const result = await userController.updateProfile(req.user!.id, body);
  res.json(result);
});

router.patch("/me/password", requireAuth, async (req, res) => {
  const body = changePasswordSchema.parse(req.body);
  await userController.changePassword(req.user!.id, body);
  res.status(204).end();
});

router.delete("/me", requireAuth, async (req, res) => {
  const body = currentPasswordSchema.parse(req.body);
  await userController.deleteAccount(req.user!.id, body);
  clearRefreshCookie(res);
  res.status(204).end();
});

export const authRouter = router;
