import crypto from "node:crypto";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { env, refreshTokenLifetimeMs } from "../config/env.js";
import { prisma } from "../db/prisma.js";
import { storageService } from "../services/StorageService.js";
import { ApiError } from "../middlewares/error-handler.js";
import type { Address, Prisma } from "../generated/prisma/client.js";

const BCRYPT_ROUNDS = 10;

// A legitimately rotating session presents each refresh token exactly once.
// A re-presented (already revoked) token is the fingerprint of a stolen cookie
// being replayed. The grace window absorbs the benign race where two browser
// tabs swap the same cookie a few seconds apart, so that case just rejects the
// token instead of nuking the whole family.
const REUSE_GRACE_MS = 30_000;

interface TokenUser {
  id: string;
  email: string;
  role: string;
}

// Public profile shape: every scalar field of `User` plus a cleaned (id-free)
// address. Accepts users with or without the address relation loaded.
type PublicAddress = Pick<Address, "state" | "city" | "line"> | null;

class AuthController {
  private hashRefreshToken(token: string): string {
    return crypto.createHash("sha256").update(token).digest("hex");
  }

  private toPublicUser(user: Prisma.UserGetPayload<{}> & { address?: PublicAddress }) {
    return {
      id: user.id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      birthDate: user.birthDate,
      phone: user.phone,
      role: user.role,
      image: user.image,
      hasPassword: user.passwordHash !== null,
      address: user.address
        ? {
            state: user.address.state,
            city: user.address.city,
            line: user.address.line,
          }
        : null,
    };
  }

  private signAccessToken(user: TokenUser): string {
    return jwt.sign(
      { sub: user.id, email: user.email, role: user.role },
      env.JWT_ACCESS_SECRET,
      { expiresIn: env.JWT_ACCESS_EXPIRES_IN as jwt.SignOptions["expiresIn"] },
    );
  }

  private signRefreshToken(userId: string, remember: boolean): string {
    return jwt.sign({ sub: userId, jti: crypto.randomUUID(), remember }, env.JWT_REFRESH_SECRET, {
      expiresIn: env.JWT_REFRESH_EXPIRES_IN as jwt.SignOptions["expiresIn"],
    });
  }

  // familyId groups every refresh token issued by one login session: rotation
  // extends the family, and reuse of a rotated token revokes all of it.
  private async issueTokenPair(
    user: TokenUser,
    remember: boolean,
    familyId: string = crypto.randomUUID(),
  ) {
    const accessToken = this.signAccessToken(user);
    const refreshToken = this.signRefreshToken(user.id, remember);

    await prisma.refreshToken.create({
      data: {
        tokenHash: this.hashRefreshToken(refreshToken),
        familyId,
        userId: user.id,
        expiresAt: new Date(Date.now() + refreshTokenLifetimeMs),
      },
    });

    return { accessToken, refreshToken, remember };
  }

  async register(input: {
    email: string;
    password: string;
    firstName?: string;
    lastName?: string;
    remember?: boolean;
  }) {
    const email = input.email.toLowerCase().trim();

    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing) {
      // Google-only accounts have no password, so re-registering them with one
      // is a dead end — point the user at Google sign-in instead. (The 409 +
      // distinct code also lets the frontend offer the right guidance.)
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

    const tokens = await this.issueTokenPair(user, input.remember ?? false);

    return { user: this.toPublicUser(user), ...tokens };
  }

  async login(input: { email: string; password: string; remember?: boolean }) {
    const email = input.email.toLowerCase().trim();
    const user = await prisma.user.findUnique({
      where: { email },
      include: { address: true },
    });

    if (!user) {
      throw new ApiError(401, "Invalid email or password", "INVALID_CREDENTIALS");
    }
    // Google-only accounts have no password yet — guide the user to sign in
    // with Google (or set a password from their account page) instead of the
    // dead-end "invalid credentials". Tradeoff: reveals that the email exists
    // and is passwordless, but existence is already exposed via register (409).
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

    const tokens = await this.issueTokenPair(user, input.remember ?? false);

    return { user: this.toPublicUser(user), ...tokens };
  }

  // Google OAuth login: find the user by verified email or create one (no
  // passwordHash for OAuth-only accounts). Existing profile fields are only
  // backfilled from Google where they are still null, so user edits win.
  async loginWithGoogle(profile: {
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

    // OAuth logins keep the user signed in (7d refresh cookie).
    const tokens = await this.issueTokenPair(user, true);

    return { user: this.toPublicUser(user), ...tokens };
  }

  // Validates a refresh token (signature + DB record + expiry + active user).
  // Returns null for any invalid state so callers decide how to surface it.
  private async resolveRefreshSession(refreshToken: string) {
    try {
      const payload = jwt.verify(refreshToken, env.JWT_REFRESH_SECRET) as jwt.JwtPayload;
      const userId = String(payload.sub);
      const stored = await prisma.refreshToken.findUnique({
        where: { tokenHash: this.hashRefreshToken(refreshToken) },
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

  async refresh(refreshToken: string) {
    const tokenHash = this.hashRefreshToken(refreshToken);
    const stored = await prisma.refreshToken.findUnique({ where: { tokenHash } });

    // The token was already rotated (revoked) and is being presented again.
    // Under normal rotation a token is only ever presented once, so replaying
    // it outside the grace window means a copy leaked (stolen cookie replay):
    // revoke the whole family so both the thief and the legitimate client must
    // re-authenticate, and the stolen session dies on first reuse.
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
      // Benign race (two tabs rotating a moment apart): reject quietly without
      // killing the family — the sibling token still works.
      throw new ApiError(401, "Invalid refresh token", "INVALID_REFRESH_TOKEN");
    }

    const session = await this.resolveRefreshSession(refreshToken);
    if (!session) {
      throw new ApiError(401, "Invalid refresh token", "INVALID_REFRESH_TOKEN");
    }

    // Rotation: revoke the presented token before issuing a new pair.
    await prisma.refreshToken.updateMany({
      where: { tokenHash, revokedAt: null },
      data: { revokedAt: new Date() },
    });

    const tokens = await this.issueTokenPair(session.user, session.remember, stored?.familyId);
    return { user: this.toPublicUser(session.user), ...tokens };
  }

  async logout(refreshToken?: string) {
    if (!refreshToken) return;
    const tokenHash = this.hashRefreshToken(refreshToken);
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

  async me(userId: string) {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      include: { address: true },
    });
    if (!user || !user.isActive) {
      throw new ApiError(401, "Account no longer exists or is deactivated", "ACCOUNT_INACTIVE");
    }
    return { user: this.toPublicUser(user) };
  }

  // Page-load bootstrap: validates the refresh cookie WITHOUT rotating it and
  // returns a fresh access token. Always 200 so logged-out loads are quiet.
  async session(refreshToken?: string) {
    if (!refreshToken) {
      return { user: null, accessToken: null };
    }
    const session = await this.resolveRefreshSession(refreshToken);
    if (!session) {
      return { user: null, accessToken: null };
    }
    return {
      user: this.toPublicUser(session.user),
      accessToken: this.signAccessToken(session.user),
    };
  }

  async updateProfile(
    userId: string,
    input: {
      firstName?: string;
      lastName?: string;
      birthDate?: string;
      phone?: string;
      image?: string;
      address?: { state?: string; city?: string; line?: string } | null;
    },
  ) {
    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user || !user.isActive) {
      throw new ApiError(401, "Account no longer exists or is deactivated", "ACCOUNT_INACTIVE");
    }

    const data: Prisma.UserUpdateInput = {};
    if (input.firstName !== undefined) data.firstName = input.firstName.trim() || null;
    if (input.lastName !== undefined) data.lastName = input.lastName.trim() || null;
    if (input.phone !== undefined) data.phone = input.phone.trim() || null;
    if (input.birthDate !== undefined) {
      data.birthDate = input.birthDate ? new Date(input.birthDate) : null;
    }

    // Replacing an uploaded avatar: once the update lands, the previous file is
    // ours (managed URL) — delete it so storage doesn't accumulate orphans.
    // Clearing the image (`""` -> null) cleans up too. Orphaned-but-never-
    // attached uploads are out of scope for the template.
    let oldManagedImageKey: string | undefined;
    if (input.image !== undefined && user.image !== input.image.trim()) {
      oldManagedImageKey = storageService.keyFromUrl(user.image ?? "");
    }
    if (input.image !== undefined) data.image = input.image.trim() || null;

    if (input.address !== undefined) {
      if (input.address === null) {
        data.address = { delete: true };
      } else {
        const { state, city, line } = input.address;
        data.address = {
          upsert: {
            create: {
              state: state?.trim() || null,
              city: city?.trim() || null,
              line: line?.trim() || null,
            },
            update: {
              state: state?.trim() || null,
              city: city?.trim() || null,
              line: line?.trim() || null,
            },
          },
        };
      }
    }

    const updated = await prisma.user.update({
      where: { id: userId },
      data,
      include: { address: true },
    });

    // Old avatar removed only after the update succeeded (best-effort; a
    // failure here leaves an orphaned file, never a broken profile).
    if (oldManagedImageKey) {
      await storageService.remove(oldManagedImageKey).catch(() => undefined);
    }

    return { user: this.toPublicUser(updated) };
  }

  // Users with a password must prove it; password-less (OAuth) accounts skip
  // the check entirely.
  private async verifyCurrentPassword(
    user: { passwordHash: string | null },
    input: { currentPassword?: string },
  ) {
    if (
      user.passwordHash &&
      (!input.currentPassword || !(await bcrypt.compare(input.currentPassword, user.passwordHash)))
    ) {
      throw new ApiError(400, "Current password is incorrect", "WRONG_PASSWORD");
    }
  }

  async changePassword(userId: string, input: { currentPassword?: string; newPassword: string }) {
    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user || !user.isActive) {
      throw new ApiError(401, "Account no longer exists or is deactivated", "ACCOUNT_INACTIVE");
    }
    await this.verifyCurrentPassword(user, input);

    const passwordHash = await bcrypt.hash(input.newPassword, BCRYPT_ROUNDS);
    await prisma.user.update({ where: { id: userId }, data: { passwordHash } });

    // Invalidate existing refresh tokens so the session must be re-established.
    await prisma.refreshToken.updateMany({
      where: { userId, revokedAt: null },
      data: { revokedAt: new Date() },
    });
  }

  async deleteAccount(userId: string, input: { currentPassword?: string }) {
    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user || !user.isActive) {
      throw new ApiError(401, "Account no longer exists or is deactivated", "ACCOUNT_INACTIVE");
    }
    // Password-less (OAuth) accounts are gated by the active session + the
    // frontend confirmation panel instead of a password.
    await this.verifyCurrentPassword(user, input);

    // Refresh tokens are removed by the onDelete Cascade on the FK. An uploaded
    // avatar is cleaned up after the row is gone (best-effort — a failure only
    // leaves an orphaned file).
    const managedImageKey = storageService.keyFromUrl(user.image ?? "");
    await prisma.user.delete({ where: { id: userId } });
    if (managedImageKey) {
      await storageService.remove(managedImageKey).catch(() => undefined);
    }
  }
}

export const authController = new AuthController();
