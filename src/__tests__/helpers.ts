import crypto from "node:crypto";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { prisma } from "../db/prisma.js";
import { env, refreshTokenLifetimeMs } from "../config/env.js";

/** Delete all rows in FK order so tests start with a clean slate. */
export async function resetDb() {
  await prisma.refreshToken.deleteMany();
  await prisma.address.deleteMany();
  await prisma.user.deleteMany();
}

/** Create a user directly in the DB (bypasses the controller). */
export async function createTestUser(
  overrides: { email?: string; password?: string; isActive?: boolean } = {},
) {
  const email = overrides.email ?? `test-${crypto.randomUUID().slice(0, 8)}@example.com`;
  const passwordHash = overrides.password
    ? await bcrypt.hash(overrides.password, 4) // low rounds for speed
    : null;

  return prisma.user.create({
    data: {
      email,
      passwordHash,
      firstName: "Test",
      lastName: "User",
      isActive: overrides.isActive ?? true,
    },
  });
}

/** Create a refresh token row directly in the DB. */
export async function createRefreshToken(
  userId: string,
  opts: { familyId?: string; revokedAt?: Date | null; expiresAt?: Date } = {},
) {
  const raw = crypto.randomUUID();
  const tokenHash = crypto.createHash("sha256").update(raw).digest("hex");
  const familyId = opts.familyId ?? crypto.randomUUID();

  const row = await prisma.refreshToken.create({
    data: {
      tokenHash,
      familyId,
      userId,
      expiresAt: opts.expiresAt ?? new Date(Date.now() + refreshTokenLifetimeMs),
      revokedAt: opts.revokedAt ?? null,
    },
  });

  return { ...row, raw };
}

/** Sign an access token for testing (mirrors AuthController.signAccessToken). */
export function signAccessToken(user: { id: string; email: string; role: string }) {
  return jwt.sign(
    { sub: user.id, email: user.email, role: user.role },
    env.JWT_ACCESS_SECRET,
    { expiresIn: env.JWT_ACCESS_EXPIRES_IN as jwt.SignOptions["expiresIn"] },
  );
}

/** Sign a refresh token for testing (mirrors AuthController.signRefreshToken). */
export function signRefreshToken(userId: string) {
  return jwt.sign(
    { sub: userId, jti: crypto.randomUUID(), remember: true },
    env.JWT_REFRESH_SECRET,
    { expiresIn: env.JWT_REFRESH_EXPIRES_IN as jwt.SignOptions["expiresIn"] },
  );
}
