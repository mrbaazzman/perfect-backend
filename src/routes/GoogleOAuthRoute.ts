import { Router } from "express";
import { start, callback } from "../controllers/GoogleOAuthController.js";

const router = Router();

router.get("/google", start);
router.get("/google/callback", callback);

export const googleOAuthRouter = router;
