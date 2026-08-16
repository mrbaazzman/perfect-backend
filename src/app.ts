import express from "express";
import helmet from "helmet";
import cookieParser from "cookie-parser";
import cors from "cors";
import { corsOrigins, env } from "./config/env.js";
import { authRouter } from "./routes/AuthRoute.js";
import { googleOAuthRouter } from "./routes/GoogleOAuthRoute.js";
import { uploadRouter } from "./routes/UploadRoute.js";
import { apiLimiter, authLimiter } from "./middlewares/rate-limiter.js";
import { notFound } from "./middlewares/not-found.js";
import { errorHandler } from "./middlewares/error-handler.js";

export function createApp() {
  const app = express();

  app.disable("x-powered-by");
  app.set("trust proxy", 1);

  app.use(helmet());
  app.use(
    cors({
      origin: corsOrigins.includes("*") ? true : corsOrigins,
      credentials: true,
    }),
  );
  app.use(cookieParser());
  app.use(express.json({ limit: "1mb" }));

  app.get("/", (_req, res) => {
    res.json({ name: "perfect-backend", status: "ok", uptime: process.uptime() });
  });

  app.use("/api", apiLimiter);

  app.get("/api/health", (_req, res) => {
    res.json({ status: "ok", timestamp: new Date().toISOString() });
  });

  // Serve uploaded files (local driver). In dev the frontend proxies /uploads
  // to this backend; in prod it's the same origin or a CDN in front of the
  // storage provider's public base.
  if (env.STORAGE_DRIVER === "local") {
    app.use(env.UPLOAD_PUBLIC_BASE, express.static(env.UPLOAD_DIR));
  }

  // Strict limiter only where brute-forcing matters; `/auth/session` (page-load
  // bootstrap) and everything else stay under the global `apiLimiter`.
  app.use("/api/auth/login", authLimiter);
  app.use("/api/auth/register", authLimiter);
  app.use("/api/auth/refresh", authLimiter);
  app.use("/api/auth", authRouter);
  app.use("/api/auth", googleOAuthRouter);
  app.use("/api/uploads", uploadRouter);

  app.use(notFound);
  app.use(errorHandler);

  return app;
}
