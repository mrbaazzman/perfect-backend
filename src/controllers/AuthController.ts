import crypto from "node:crypto";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { env, refreshTokenLifetimeMs } from "../config/env.js";
import { prisma } from "../prisma/prisma.js";
import { ApiError } from "../middlewares/error-handler.js";
import type { Prisma } from "../prisma/generated/client.js";
import { BCRYPT_ROUNDS, toPublicUser } from "../utils/auth-utils.js";

const REUSE_GRACE_MS = 30_000;

function hashRefreshToken(token: string): string {
  return crypto.createHash("sha256").update(token).digest("hex");
}

interface TokenUser {
  id: string;
  email: string;
  role: string;
}

function signAccessToken(user: TokenUser): string {
  return jwt.sign(
    { sub: user.id, email: user.email, role: user.role },
    env.JWT_ACCESS_SECRET,
    { expiresIn: env.JWT_ACCESS_EXPIRES_IN as jwt.SignOptions["expiresIn"] },
  );
}

function signRefreshToken(userId: string, remember: boolean): string {
  return jwt.sign({ sub: userId, jti: crypto.randomUUID(), remember }, env.JWT_REFRESH_SECRET, {
    expiresIn: env.JWT_REFRESH_EXPIRES_IN as jwt.SignOptions["expiresIn"] },
  );
}

async function issueTokenPair(
  user: TokenUser,
  remember: boolean,
  familyId: string = crypto.randomUUID(),
) {
  const accessToken = signAccessToken(user);
  const refreshToken = signRefreshToken(user.id, remember);

  await prisma.refreshToken.create({
    data: {
      tokenHash: hashRefreshToken(refreshToken),
      familyId,
      userId: user.id,
      expiresAt: new Date(Date.now() + refreshTokenLifetimeMs),
    },
  });

  return { accessToken, refreshToken, remember };
}

async function resolveRefreshSession(refreshToken: string) {
  try {
    const payload = jwt.verify(refreshToken, env.JWT_REFRESH_SECRET) as jwt.JwtPayload;
    const userId = String(payload.sub);
    const stored = await prisma.refreshToken.findUnique({
      where: { tokenHash: hashRefreshToken(refreshToken) },
    });
    if (!stored || stored.userId !== userId || stored.revokedAt !== null) return null;
    if (stored.expiresAt.getTime() <= Date.now()) return null;

    const user = await prisma.user.findUnique({
      where: { id: userId },
      include: { address: true },
    });
    if (!user || !user.isActive) return null;

    return { user, remember: payload.remember ?? false };
  } catch {
    return null;
  }
}

export async function register(input: {
  email: string;
  password: string;
  firstName?: string;
  lastName?: string;
  remember?: boolean;
}) {
  const email = input.email.toLowerCase().trim();

  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) {
    if (!existing.passwordHash) {
      throw new ApiError(
        409,
        "This email already has a Google account. Sign in with Google instead.",
        "OAUTH_ONLY_ACCOUNT",
      );
    }
    throw new ApiError(409, "Email is already registered", "EMAIL_TAKEN");
  }

  const passwordHash = await bcrypt.hash(input.password, BCRYPT_ROUNDS);
  const user = await prisma.user.create({
    data: {
      email,
      passwordHash,
      firstName: input.firstName?.trim() || null,
      lastName: input.lastName?.trim() || null,
    },
  });

  const tokens = await issueTokenPair(user, input.remember ?? false);

  return { user: toPublicUser(user), ...tokens };
}

export async function login(input: { email: string; password: string; remember?: boolean }) {
  const email = input.email.toLowerCase().trim();
  const user = await prisma.user.findUnique({
    where: { email },
    include: { address: true },
  });

  if (!user) {
    throw new ApiError(401, "Invalid email or password", "INVALID_CREDENTIALS");
  }
  if (!user.passwordHash) {
    throw new ApiError(
      400,
      "This account uses Google sign-in and has no password set",
      "NO_PASSWORD_SET",
    );
  }
  if (!(await bcrypt.compare(input.password, user.passwordHash))) {
    throw new ApiError(401, "Invalid email or password", "INVALID_CREDENTIALS");
  }
  if (!user.isActive) {
    throw new ApiError(403, "Account is deactivated", "ACCOUNT_INACTIVE");
  }

  const tokens = await issueTokenPair(user, input.remember ?? false);

  return { user: toPublicUser(user), ...tokens };
}

export async function loginWithGoogle(profile: {
  email: string;
  firstName?: string | null;
  lastName?: string | null;
  image?: string | null;
}) {
  const email = profile.email.toLowerCase().trim();

  let user = await prisma.user.findUnique({
    where: { email },
    include: { address: true },
  });

  if (!user) {
    user = await prisma.user.create({
      data: {
        email,
        firstName: profile.firstName?.trim() || null,
        lastName: profile.lastName?.trim() || null,
        image: profile.image?.trim() || null,
      },
      include: { address: true },
    });
  } else if (user.isActive) {
    const data: Prisma.UserUpdateInput = {};
    if (!user.firstName && profile.firstName) data.firstName = profile.firstName.trim();
    if (!user.lastName && profile.lastName) data.lastName = profile.lastName.trim();
    if (!user.image && profile.image) data.image = profile.image.trim();
    if (Object.keys(data).length > 0) {
      user = await prisma.user.update({
        where: { id: user.id },
        data,
        include: { address: true },
      });
    }
  }

  if (!user.isActive) {
    throw new ApiError(403, "Account is deactivated", "ACCOUNT_INACTIVE");
  }

  const tokens = await issueTokenPair(user, true);

  return { user: toPublicUser(user), ...tokens };
}

export async function refresh(refreshToken: string) {
  const tokenHash = hashRefreshToken(refreshToken);
  const stored = await prisma.refreshToken.findUnique({ where: { tokenHash } });

  if (stored?.revokedAt) {
    const ageMs = Date.now() - stored.revokedAt.getTime();
    if (ageMs > REUSE_GRACE_MS) {
      await prisma.refreshToken.updateMany({
        where: { familyId: stored.familyId, revokedAt: null },
        data: { revokedAt: new Date() },
      });
      console.warn(`[auth] refresh token reuse detected (family ${stored.familyId})`);
      throw new ApiError(
        401,
        "Refresh token was reused; the session was terminated",
        "TOKEN_REUSED",
      );
    }
    throw new ApiError(401, "Invalid refresh token", "INVALID_REFRESH_TOKEN");
  }

  const session = await resolveRefreshSession(refreshToken);
  if (!session) {
    throw new ApiError(401, "Invalid refresh token", "INVALID_REFRESH_TOKEN");
  }

  await prisma.refreshToken.updateMany({
    where: { tokenHash, revokedAt: null },
    data: { revokedAt: new Date() },
  });

  const tokens = await issueTokenPair(session.user, session.remember, stored?.familyId);
  return { user: toPublicUser(session.user), ...tokens };
}

export async function logout(refreshToken?: string) {
  if (!refreshToken) return;
  const tokenHash = hashRefreshToken(refreshToken);
  const stored = await prisma.refreshToken.findUnique({
    where: { tokenHash },
    select: { familyId: true },
  });
  await prisma.refreshToken.updateMany({
    where: {
      ...(stored ? { familyId: stored.familyId } : { tokenHash }),
      revokedAt: null,
    },
    data: { revokedAt: new Date() },
  });
}

export async function session(refreshToken?: string) {
  if (!refreshToken) {
    return { user: null, accessToken: null };
  }
  const sess = await resolveRefreshSession(refreshToken);
  if (!sess) {
    return { user: null, accessToken: null };
  }
  return {
    user: toPublicUser(sess.user),
    accessToken: signAccessToken(sess.user),
  };
}
