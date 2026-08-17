import "dotenv/config";
import { z } from "zod";

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.coerce.number().int().positive().default(3000),
  CORS_ORIGIN: z.string().default("*"),
  DATABASE_URL: z.string().min(1, "DATABASE_URL is required"),
  JWT_ACCESS_SECRET: z.string().min(32, "JWT_ACCESS_SECRET must be at least 32 chars"),
  JWT_REFRESH_SECRET: z.string().min(32, "JWT_REFRESH_SECRET must be at least 32 chars"),
  JWT_ACCESS_EXPIRES_IN: z.string().default("15m"),
  JWT_REFRESH_EXPIRES_IN: z.string().default("7d"),
  GOOGLE_CLIENT_ID: z.string().min(1).optional(),
  GOOGLE_CLIENT_SECRET: z.string().min(1).optional(),
  GOOGLE_REDIRECT_URI: z.string().url("GOOGLE_REDIRECT_URI must be a valid URL").optional(),
  FRONTEND_URL: z.string().url("FRONTEND_URL must be a valid URL").default("http://localhost:5173"),
  STORAGE_DRIVER: z.enum(["local", "cloudinary", "s3"]).default("local"),
  UPLOAD_DIR: z.string().min(1).default("perfect-app/avatars"),
  UPLOAD_MAX_SIZE_MB: z.coerce.number().positive().default(5),
  UPLOAD_ALLOWED_MIMES: z
    .string()
    .default("image/png,image/jpeg,image/webp,image/gif,application/pdf,text/plain,application/json"),
  CLOUDINARY_CLOUD_NAME: z.string().min(1).optional(),
  CLOUDINARY_API_KEY: z.string().min(1).optional(),
  CLOUDINARY_API_SECRET: z.string().min(1).optional(),
}).superRefine((env, ctx) => {
  if (env.STORAGE_DRIVER === "cloudinary") {
    const missing: string[] = [];
    if (!env.CLOUDINARY_CLOUD_NAME) missing.push("CLOUDINARY_CLOUD_NAME");
    if (!env.CLOUDINARY_API_KEY) missing.push("CLOUDINARY_API_KEY");
    if (!env.CLOUDINARY_API_SECRET) missing.push("CLOUDINARY_API_SECRET");
    if (missing.length > 0) {
      ctx.addIssue({
        code: "custom",
        path: ["STORAGE_DRIVER"],
        message: `STORAGE_DRIVER=cloudinary requires ${missing.join(", ")}`,
      });
    }
  }

  if (env.GOOGLE_REDIRECT_URI) {
    if (!env.GOOGLE_CLIENT_ID || !env.GOOGLE_CLIENT_SECRET) {
      const missing: string[] = [];
      if (!env.GOOGLE_CLIENT_ID) missing.push("GOOGLE_CLIENT_ID");
      if (!env.GOOGLE_CLIENT_SECRET) missing.push("GOOGLE_CLIENT_SECRET");
      ctx.addIssue({
        code: "custom",
        path: ["GOOGLE_REDIRECT_URI"],
        message: `Google OAuth requires ${missing.join(", ")}`,
      });
    }
  }

  if (env.NODE_ENV === "production" && env.CORS_ORIGIN === "*") {
    ctx.addIssue({
      code: "custom",
      path: ["CORS_ORIGIN"],
      message: "CORS_ORIGIN=* is not allowed in production (security risk with credentials)",
    });
  }
});

const parsed = envSchema.safeParse(process.env);

if (!parsed.success) {
  console.error("Invalid environment variables:");
  console.error(JSON.stringify(parsed.error.flatten().fieldErrors, null, 2));
  process.exit(1);
}

export const env = parsed.data;

// --- Derived config ---

const DURATION_UNITS: Record<string, number> = { s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 };

function durationToMs(value: string): number {
  const match = /^(\d+)([smhd])$/.exec(value.trim());
  if (!match) throw new Error(`Invalid duration: "${value}". Expected <number><unit> (e.g. 15m, 7d)`);
  return Number(match[1]) * (DURATION_UNITS[match[2]!] ?? 0);
}

export const refreshTokenLifetimeMs = durationToMs(env.JWT_REFRESH_EXPIRES_IN);

export const uploadAllowedMimes = env.UPLOAD_ALLOWED_MIMES.split(",")
  .map((m) => m.trim().toLowerCase())
  .filter(Boolean);

export const uploadMaxSizeBytes = env.UPLOAD_MAX_SIZE_MB * 1024 * 1024;

export const corsOrigins = env.CORS_ORIGIN.split(",")
  .map((o) => o.trim())
  .filter(Boolean);
