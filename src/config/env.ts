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
  GOOGLE_CLIENT_ID: z.string().min(1, "GOOGLE_CLIENT_ID is required"),
  GOOGLE_CLIENT_SECRET: z.string().min(1, "GOOGLE_CLIENT_SECRET is required"),
  GOOGLE_REDIRECT_URI: z.string().url("GOOGLE_REDIRECT_URI must be a valid URL"),
  FRONTEND_URL: z.string().url("FRONTEND_URL must be a valid URL").default("http://localhost:5173"),
  STORAGE_DRIVER: z.enum(["local", "cloudinary", "s3"]).default("local"),
  UPLOAD_DIR: z.string().min(1).default("uploads"),
  UPLOAD_PUBLIC_BASE: z.string().min(1).default("/uploads"),
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
});

const parsed = envSchema.safeParse(process.env);

if (!parsed.success) {
  console.error("Invalid environment variables:");
  console.error(JSON.stringify(parsed.error.flatten().fieldErrors, null, 2));
  process.exit(1);
}

export const env = parsed.data;

// Upload policy derived from the env strings above.
export const uploadAllowedMimes = env.UPLOAD_ALLOWED_MIMES.split(",")
  .map((mime) => mime.trim().toLowerCase())
  .filter((mime) => mime.length > 0);

export const uploadMaxSizeBytes = env.UPLOAD_MAX_SIZE_MB * 1024 * 1024;

const DURATION_UNITS: Record<string, number> = {
  s: 1000,
  m: 60_000,
  h: 3_600_000,
  d: 86_400_000,
};

function durationToMs(value: string): number {
  const match = /^(\d+)([smhd])$/.exec(value.trim());
  if (!match) return 7 * 86_400_000;
  const unit = match[2]!;
  return Number(match[1]) * (DURATION_UNITS[unit] ?? 0);
}

/** Lifetime of the refresh token / cookie, derived from JWT_REFRESH_EXPIRES_IN. */
export const refreshTokenLifetimeMs = durationToMs(env.JWT_REFRESH_EXPIRES_IN);

export const corsOrigins = env.CORS_ORIGIN.split(",")
  .map((origin) => origin.trim())
  .filter((origin) => origin.length > 0);
