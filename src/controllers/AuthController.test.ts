import { describe, it, expect, beforeEach, vi } from "vitest";
import crypto from "node:crypto";
import { authController } from "../controllers/AuthController.js";
import { userController } from "../controllers/UserController.js";
import { prisma } from "../prisma/prisma.js";
import { resetDb, createTestUser, createRefreshToken } from "../__tests__/helpers.js";

beforeEach(async () => {
  await resetDb();
});

// ---------------------------------------------------------------------------
// register
// ---------------------------------------------------------------------------
describe("register", () => {
  it("creates a user and returns tokens", async () => {
    const result = await authController.register({
      email: "new@example.com",
      password: "Password1",
    });

    expect(result.user.email).toBe("new@example.com");
    expect(result.user.hasPassword).toBe(true);
    expect(result.accessToken).toBeDefined();
    expect(result.refreshToken).toBeDefined();
  });

  it("stores the user in the DB", async () => {
    const result = await authController.register({
      email: "db@example.com",
      password: "Password1",
    });

    const db = await prisma.user.findUnique({ where: { id: result.user.id } });
    expect(db).not.toBeNull();
    expect(db!.email).toBe("db@example.com");
    expect(db!.passwordHash).not.toBeNull();
  });

  it("normalises email to lowercase", async () => {
    const result = await authController.register({
      email: "UPPER@Example.COM",
      password: "Password1",
    });
    expect(result.user.email).toBe("upper@example.com");
  });

  it("rejects duplicate email", async () => {
    await authController.register({ email: "dup@example.com", password: "Password1" });
    await expect(
      authController.register({ email: "dup@example.com", password: "Password2" }),
    ).rejects.toMatchObject({ code: "EMAIL_TAKEN" });
  });

  it("rejects registration for an OAuth-only account", async () => {
    await createTestUser({ email: "oauth@example.com", password: undefined });
    await expect(
      authController.register({ email: "oauth@example.com", password: "Password1" }),
    ).rejects.toMatchObject({ code: "OAUTH_ONLY_ACCOUNT" });
  });

  it("creates a refresh token row in the DB", async () => {
    const result = await authController.register({
      email: "token@example.com",
      password: "Password1",
    });

    const tokens = await prisma.refreshToken.findMany({
      where: { userId: result.user.id },
    });
    expect(tokens).toHaveLength(1);
    expect(tokens[0]!.revokedAt).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// login
// ---------------------------------------------------------------------------
describe("login", () => {
  it("returns tokens for valid credentials", async () => {
    await authController.register({ email: "login@example.com", password: "Password1" });
    const result = await authController.login({
      email: "login@example.com",
      password: "Password1",
    });

    expect(result.user.email).toBe("login@example.com");
    expect(result.accessToken).toBeDefined();
    expect(result.refreshToken).toBeDefined();
  });

  it("rejects invalid email", async () => {
    await expect(
      authController.login({ email: "nobody@example.com", password: "Password1" }),
    ).rejects.toMatchObject({ code: "INVALID_CREDENTIALS" });
  });

  it("rejects wrong password", async () => {
    await authController.register({ email: "wrong@example.com", password: "Password1" });
    await expect(
      authController.login({ email: "wrong@example.com", password: "WrongPass1" }),
    ).rejects.toMatchObject({ code: "INVALID_CREDENTIALS" });
  });

  it("rejects login for OAuth-only account (no password)", async () => {
    await createTestUser({ email: "oauth-login@example.com" });
    await expect(
      authController.login({ email: "oauth-login@example.com", password: "whatever" }),
    ).rejects.toMatchObject({ code: "NO_PASSWORD_SET" });
  });

  it("rejects login for deactivated account", async () => {
    await createTestUser({ email: "inactive@example.com", password: "Password1", isActive: false });
    await expect(
      authController.login({ email: "inactive@example.com", password: "Password1" }),
    ).rejects.toMatchObject({ code: "ACCOUNT_INACTIVE" });
  });

  it("creates a second refresh token row", async () => {
    await authController.register({ email: "multi@example.com", password: "Password1" });
    await authController.login({ email: "multi@example.com", password: "Password1" });

    const tokens = await prisma.refreshToken.findMany({
      where: { user: { email: "multi@example.com" } },
    });
    expect(tokens).toHaveLength(2);
  });
});

// ---------------------------------------------------------------------------
// refresh — rotation
// ---------------------------------------------------------------------------
describe("refresh", () => {
  it("rotates the refresh token (old revoked, new active)", async () => {
    const reg = await authController.register({
      email: "rotate@example.com",
      password: "Password1",
    });
    const result = await authController.refresh(reg.refreshToken);

    expect(result.accessToken).toBeDefined();
    expect(result.refreshToken).not.toBe(reg.refreshToken);

    // Old token should be revoked
    const oldHash = crypto
      .createHash("sha256")
      .update(reg.refreshToken)
      .digest("hex");
    const old = await prisma.refreshToken.findUnique({ where: { tokenHash: oldHash } });
    expect(old!.revokedAt).not.toBeNull();

    // New token should be active
    const newHash = crypto
      .createHash("sha256")
      .update(result.refreshToken)
      .digest("hex");
    const fresh = await prisma.refreshToken.findUnique({ where: { tokenHash: newHash } });
    expect(fresh!.revokedAt).toBeNull();
  });

  it("preserves the familyId across rotations", async () => {
    const reg = await authController.register({
      email: "family@example.com",
      password: "Password1",
    });
    const result = await authController.refresh(reg.refreshToken);

    const oldHash = crypto
      .createHash("sha256")
      .update(reg.refreshToken)
      .digest("hex");
    const newHash = crypto
      .createHash("sha256")
      .update(result.refreshToken)
      .digest("hex");

    const old = await prisma.refreshToken.findUnique({ where: { tokenHash: oldHash } });
    const fresh = await prisma.refreshToken.findUnique({ where: { tokenHash: newHash } });

    expect(old!.familyId).toBe(fresh!.familyId);
  });

  it("rejects an invalid (non-existent) token", async () => {
    await expect(authController.refresh("totally-fake-token")).rejects.toMatchObject({
      code: "INVALID_REFRESH_TOKEN",
    });
  });
});

// ---------------------------------------------------------------------------
// refresh — reuse detection
// ---------------------------------------------------------------------------
describe("refresh — reuse detection", () => {
  it("revokes entire family when a rotated token is replayed after grace window", async () => {
    const reg = await authController.register({
      email: "reuse@example.com",
      password: "Password1",
    });

    // First rotation — revokes the original
    const rotated = await authController.refresh(reg.refreshToken);

    // Simulate time passing beyond the 30s grace window
    const oldHash = crypto
      .createHash("sha256")
      .update(reg.refreshToken)
      .digest("hex");
    const oldRow = await prisma.refreshToken.findUnique({ where: { tokenHash: oldHash } });
    await prisma.refreshToken.update({
      where: { id: oldRow!.id },
      data: { revokedAt: new Date(Date.now() - 60_000) }, // 60s ago, past 30s grace
    });

    // Replay the original (already revoked) token — should kill the family
    await expect(authController.refresh(reg.refreshToken)).rejects.toMatchObject({
      code: "TOKEN_REUSED",
    });

    // All tokens in the family should now be revoked
    const familyTokens = await prisma.refreshToken.findMany({
      where: { familyId: oldRow!.familyId },
    });
    expect(familyTokens.every((t) => t.revokedAt !== null)).toBe(true);
  });

  it("rejects quietly during the grace window (two-tab race)", async () => {
    const reg = await authController.register({
      email: "grace@example.com",
      password: "Password1",
    });

    // First rotation
    await authController.refresh(reg.refreshToken);

    // Replay immediately (within 30s grace) — should reject but NOT kill family
    await expect(authController.refresh(reg.refreshToken)).rejects.toMatchObject({
      code: "INVALID_REFRESH_TOKEN",
    });

    // The sibling token from the first rotation should still be active
    const rotated = await prisma.refreshToken.findMany({
      where: { userId: reg.user.id, revokedAt: null },
    });
    expect(rotated.length).toBeGreaterThanOrEqual(1);
  });
});

// ---------------------------------------------------------------------------
// logout
// ---------------------------------------------------------------------------
describe("logout", () => {
  it("revokes all tokens in the family", async () => {
    const reg = await authController.register({
      email: "logout@example.com",
      password: "Password1",
    });
    await authController.logout(reg.refreshToken);

    const tokens = await prisma.refreshToken.findMany({
      where: { userId: reg.user.id },
    });
    expect(tokens.every((t) => t.revokedAt !== null)).toBe(true);
  });

  it("does nothing when no token is provided", async () => {
    await expect(authController.logout(undefined)).resolves.toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// session
// ---------------------------------------------------------------------------
describe("session", () => {
  it("returns user and access token for a valid refresh token", async () => {
    const reg = await authController.register({
      email: "session@example.com",
      password: "Password1",
    });
    const result = await authController.session(reg.refreshToken);

    expect(result.user).not.toBeNull();
    expect(result.user!.email).toBe("session@example.com");
    expect(result.accessToken).toBeDefined();
  });

  it("returns nulls for an invalid token", async () => {
    const result = await authController.session("bad-token");
    expect(result.user).toBeNull();
    expect(result.accessToken).toBeNull();
  });

  it("returns nulls when no token is provided", async () => {
    const result = await authController.session(undefined);
    expect(result.user).toBeNull();
    expect(result.accessToken).toBeNull();
  });

  it("does NOT rotate the token (read-only bootstrap)", async () => {
    const reg = await authController.register({
      email: "no-rotate@example.com",
      password: "Password1",
    });
    await authController.session(reg.refreshToken);

    // The original token should still be active (not revoked)
    const hash = crypto
      .createHash("sha256")
      .update(reg.refreshToken)
      .digest("hex");
    const stored = await prisma.refreshToken.findUnique({ where: { tokenHash: hash } });
    expect(stored!.revokedAt).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// me
// ---------------------------------------------------------------------------
describe("me", () => {
  it("returns the public profile", async () => {
    const reg = await authController.register({
      email: "me@example.com",
      password: "Password1",
      firstName: "John",
      lastName: "Doe",
    });
    const result = await userController.me(reg.user.id);

    expect(result.user.email).toBe("me@example.com");
    expect(result.user.firstName).toBe("John");
    expect(result.user.lastName).toBe("Doe");
    expect(result.user.hasPassword).toBe(true);
    expect(result.user.address).toBeNull();
  });

  it("throws for non-existent user", async () => {
    await expect(userController.me("non-existent-id")).rejects.toMatchObject({
      code: "ACCOUNT_INACTIVE",
    });
  });
});

// ---------------------------------------------------------------------------
// updateProfile
// ---------------------------------------------------------------------------
describe("updateProfile", () => {
  it("updates basic profile fields", async () => {
    const reg = await authController.register({
      email: "profile@example.com",
      password: "Password1",
    });
    const result = await userController.updateProfile(reg.user.id, {
      firstName: "Jane",
      phone: "+1 555 123 4567",
    });

    expect(result.user.firstName).toBe("Jane");
    expect(result.user.phone).toBe("+1 555 123 4567");
  });

  it("upserts address", async () => {
    const reg = await authController.register({
      email: "addr@example.com",
      password: "Password1",
    });
    const result = await userController.updateProfile(reg.user.id, {
      address: { state: "CA", city: "SF", line: "123 Main" },
    });

    expect(result.user.address).toEqual({ state: "CA", city: "SF", line: "123 Main" });
  });

  it("deletes address when set to null", async () => {
    const reg = await authController.register({
      email: "del-addr@example.com",
      password: "Password1",
    });
    await userController.updateProfile(reg.user.id, {
      address: { state: "CA", city: "SF", line: "123 Main" },
    });
    const result = await userController.updateProfile(reg.user.id, { address: null });

    expect(result.user.address).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// changePassword
// ---------------------------------------------------------------------------
describe("changePassword", () => {
  it("changes the password and revokes all refresh tokens", async () => {
    const reg = await authController.register({
      email: "chg@example.com",
      password: "Password1",
    });
    await userController.changePassword(reg.user.id, {
      currentPassword: "Password1",
      newPassword: "NewPass123",
    });

    // Old tokens should be revoked
    const tokens = await prisma.refreshToken.findMany({
      where: { userId: reg.user.id },
    });
    expect(tokens.every((t) => t.revokedAt !== null)).toBe(true);

    // New login with old password should fail
    await expect(
      authController.login({ email: "chg@example.com", password: "Password1" }),
    ).rejects.toMatchObject({ code: "INVALID_CREDENTIALS" });

    // New login with new password should work
    const login = await authController.login({ email: "chg@example.com", password: "NewPass123" });
    expect(login.accessToken).toBeDefined();
  });

  it("rejects wrong current password", async () => {
    const reg = await authController.register({
      email: "wrong-chg@example.com",
      password: "Password1",
    });
    await expect(
      userController.changePassword(reg.user.id, {
        currentPassword: "WrongPass",
        newPassword: "NewPass123",
      }),
    ).rejects.toMatchObject({ code: "WRONG_PASSWORD" });
  });

  it("allows setting password for OAuth-only account (no current password required)", async () => {
    const user = await createTestUser({ email: "oauth-set@example.com" });
    await expect(
      userController.changePassword(user.id, { newPassword: "BrandNew1" }),
    ).resolves.toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// deleteAccount
// ---------------------------------------------------------------------------
describe("deleteAccount", () => {
  it("deletes the user and cascades", async () => {
    const reg = await authController.register({
      email: "delete@example.com",
      password: "Password1",
    });
    await userController.deleteAccount(reg.user.id, { currentPassword: "Password1" });

    const user = await prisma.user.findUnique({ where: { id: reg.user.id } });
    expect(user).toBeNull();

    const tokens = await prisma.refreshToken.findMany({
      where: { userId: reg.user.id },
    });
    expect(tokens).toHaveLength(0);
  });

  it("rejects wrong password", async () => {
    const reg = await authController.register({
      email: "del-wrong@example.com",
      password: "Password1",
    });
    await expect(
      userController.deleteAccount(reg.user.id, { currentPassword: "WrongPass" }),
    ).rejects.toMatchObject({ code: "WRONG_PASSWORD" });
  });

  it("allows OAuth-only account deletion without password", async () => {
    const user = await createTestUser({ email: "del-oauth@example.com" });
    await expect(
      userController.deleteAccount(user.id, {}),
    ).resolves.toBeUndefined();

    const deleted = await prisma.user.findUnique({ where: { id: user.id } });
    expect(deleted).toBeNull();
  });
});
