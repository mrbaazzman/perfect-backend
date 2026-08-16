import { Router } from "express";
import { z } from "zod";
import { authController } from "../controllers/AuthController.js";
import { ApiError } from "../middlewares/error-handler.js";
import { requireAuth } from "../middlewares/auth.js";
import { clearRefreshCookie, REFRESH_COOKIE, setRefreshCookie } from "../middlewares/cookies.js";

const router = Router();

const emailSchema = z.email("Invalid email address");
const passwordSchema = z
  .string()
  .min(8, "Password must be at least 8 characters long")
  .regex(/[a-z]/, "Password must contain a lowercase letter")
  .regex(/[A-Z]/, "Password must contain an uppercase letter")
  .regex(/[0-9]/, "Password must contain a number");

const rememberSchema = z.boolean().optional();

const nameFieldSchema = z
  .string()
  .trim()
  .min(1, "Name cannot be empty")
  .max(100, "Name is too long")
  .optional();

const addressSchema = z
  .object({
    state: z.string().trim().max(100, "State is too long").optional(),
    city: z.string().trim().max(100, "City is too long").optional(),
    line: z.string().trim().max(300, "Address is too long").optional(),
  })
  .optional()
  .nullable();

const registerSchema = z.object({
  email: emailSchema,
  password: passwordSchema,
  firstName: nameFieldSchema,
  lastName: nameFieldSchema,
  remember: rememberSchema,
});

const credentialsSchema = z.object({
  email: z.string().min(1, "Email is required"),
  password: z.string().min(1, "Password is required"),
  remember: rememberSchema,
});

const updateProfileSchema = z.object({
  firstName: nameFieldSchema,
  lastName: nameFieldSchema,
  phone: z.string().trim().max(30, "Phone number is too long").optional(),
  birthDate: z.string().date("Invalid birth date").optional(),
  image: z.string().trim().max(500, "Image URL is too long").optional(),
  address: addressSchema,
});

const currentPasswordField = z.string().min(1, "Current password is required").optional();

const changePasswordSchema = z.object({
  currentPassword: currentPasswordField,
  newPassword: passwordSchema,
});

const currentPasswordSchema = z.object({
  currentPassword: currentPasswordField,
});

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
  const result = await authController.me(req.user!.id);
  res.json(result);
});

router.patch("/me", requireAuth, async (req, res) => {
  const body = updateProfileSchema.parse(req.body);
  const result = await authController.updateProfile(req.user!.id, body);
  res.json(result);
});

router.patch("/me/password", requireAuth, async (req, res) => {
  const body = changePasswordSchema.parse(req.body);
  await authController.changePassword(req.user!.id, body);
  res.status(204).end();
});

router.delete("/me", requireAuth, async (req, res) => {
  const body = currentPasswordSchema.parse(req.body);
  await authController.deleteAccount(req.user!.id, body);
  clearRefreshCookie(res);
  res.status(204).end();
});

export const authRouter = router;
