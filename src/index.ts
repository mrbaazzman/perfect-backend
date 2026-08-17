import express from "express";
import helmet from "helmet";
import cookieParser from "cookie-parser";
import cors from "cors";
import { corsOrigins, env } from "./config/env.js";
import { prisma } from "./prisma/prisma.js";
import { authRouter } from "./routes/AuthRoute.js";
import { googleOAuthRouter } from "./routes/GoogleOAuthRoute.js";
import { uploadRouter } from "./routes/UploadRoute.js";
import { apiLimiter, authLimiter } from "./middlewares/rate-limiter.js";
import { errorHandler } from "./middlewares/error-handler.js";

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

app.use("/api/auth/login", authLimiter);
app.use("/api/auth/register", authLimiter);
app.use("/api/auth/refresh", authLimiter);
app.use("/api/auth/google", authLimiter);
app.use("/api/auth", authRouter);
app.use("/api/auth", googleOAuthRouter);
app.use("/api/uploads", uploadRouter);

app.use((_req, res) => res.status(404).json({ error: "Not found", code: "NOT_FOUND" }));
app.use(errorHandler);

async function main() {
  await prisma.$connect();
  console.log("Database connected");

  const server = app.listen(env.PORT, () => {
    console.log(`Server listening on http://localhost:${env.PORT} (${env.NODE_ENV})`);
  });

  let shuttingDown = false;
  async function shutdown(signal: string) {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`${signal} received, shutting down gracefully...`);

    const forceExit = setTimeout(() => {
      console.error("Forced shutdown after timeout");
      process.exit(1);
    }, 10_000);
    forceExit.unref();

    server.close(async () => {
      await prisma.$disconnect();
      console.log("Database disconnected. Bye.");
      process.exit(0);
    });
  }

  process.on("SIGINT", () => void shutdown("SIGINT"));
  process.on("SIGTERM", () => void shutdown("SIGTERM"));
}

main().catch((err) => {
  console.error("Failed to start server:", err);
  process.exit(1);
});
