import { Router } from "express";
import multer from "multer";
import * as user from "../controllers/UserController.js";
import { requireAuth } from "../middlewares/auth.js";
import { clearRefreshCookie } from "../middlewares/cookies.js";
import { updateProfileSchema, changePasswordSchema, currentPasswordSchema } from "../schemas/authSchemas.js";

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const allowed = ["image/png", "image/jpeg", "image/webp", "image/gif"];
    cb(null, allowed.includes(file.mimetype));
  },
});

const router = Router();

router.use(requireAuth);

router.get("/me", async (req, res) => {
  const result = await user.me(req.user!.id);
  res.json(result);
});

router.patch("/me", upload.single("image"), async (req, res) => {
  const body = updateProfileSchema.parse(req.body);
  const result = await user.updateProfile(req.user!.id, body, req.file);
  res.json(result);
});

router.patch("/me/password", async (req, res) => {
  const body = changePasswordSchema.parse(req.body);
  await user.changePassword(req.user!.id, body);
  res.status(204).end();
});

router.delete("/me", async (req, res) => {
  const body = currentPasswordSchema.parse(req.body);
  await user.deleteAccount(req.user!.id, body);
  clearRefreshCookie(res);
  res.status(204).end();
});

export const userRouter = router;
