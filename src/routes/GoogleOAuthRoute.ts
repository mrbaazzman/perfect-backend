import { Router } from "express";
import { googleOAuthController } from "../controllers/GoogleOAuthController.js";

const router = Router();

router.get("/google", googleOAuthController.start);
router.get("/google/callback", googleOAuthController.callback);

export const googleOAuthRouter = router;
