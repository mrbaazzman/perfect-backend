import { describe, it, expect } from "vitest";
import jwt from "jsonwebtoken";
import { requireAuth } from "../middlewares/auth.js";
import { env } from "../config/env.js";

function mockReq(authHeader?: string) {
  return {
    headers: { authorization: authHeader },
  } as any;
}

function mockRes() {
  return {} as any;
}

describe("requireAuth", () => {
  it("calls next with user for a valid token", () => {
    const user = { id: "u1", email: "a@b.com", role: "USER" };
    const token = jwt.sign(
      { sub: user.id, email: user.email, role: user.role },
      env.JWT_ACCESS_SECRET,
      { expiresIn: "15m" },
    );

    const req = mockReq(`Bearer ${token}`);
    const res = mockRes();
    const next = vi.fn();

    requireAuth(req, res, next);

    expect(next).toHaveBeenCalledWith();
    expect(req.user).toEqual(user);
  });

  it("returns 401 UNAUTHORIZED when no header is present", () => {
    const next = vi.fn();
    requireAuth(mockReq(undefined), mockRes(), next);

    expect(next).toHaveBeenCalledWith(
      expect.objectContaining({ code: "UNAUTHORIZED", statusCode: 401 }),
    );
  });

  it("returns 401 UNAUTHORIZED for non-Bearer scheme", () => {
    const next = vi.fn();
    requireAuth(mockReq("Basic abc123"), mockRes(), next);

    expect(next).toHaveBeenCalledWith(
      expect.objectContaining({ code: "UNAUTHORIZED" }),
    );
  });

  it("returns 401 UNAUTHORIZED for empty Bearer token", () => {
    const next = vi.fn();
    requireAuth(mockReq("Bearer "), mockRes(), next);

    expect(next).toHaveBeenCalledWith(
      expect.objectContaining({ code: "UNAUTHORIZED" }),
    );
  });

  it("returns 401 INVALID_TOKEN for an expired token", () => {
    const token = jwt.sign(
      { sub: "u1", email: "a@b.com", role: "USER" },
      env.JWT_ACCESS_SECRET,
      { expiresIn: "-1s" }, // already expired
    );

    const next = vi.fn();
    requireAuth(mockReq(`Bearer ${token}`), mockRes(), next);

    expect(next).toHaveBeenCalledWith(
      expect.objectContaining({ code: "INVALID_TOKEN", statusCode: 401 }),
    );
  });

  it("returns 401 INVALID_TOKEN for a token signed with the wrong secret", () => {
    const token = jwt.sign(
      { sub: "u1", email: "a@b.com", role: "USER" },
      "wrong-secret-at-least-32-chars-long!!",
      { expiresIn: "15m" },
    );

    const next = vi.fn();
    requireAuth(mockReq(`Bearer ${token}`), mockRes(), next);

    expect(next).toHaveBeenCalledWith(
      expect.objectContaining({ code: "INVALID_TOKEN" }),
    );
  });

  it("returns 401 INVALID_TOKEN for a malformed token", () => {
    const next = vi.fn();
    requireAuth(mockReq("Bearer not.a.jwt"), mockRes(), next);

    expect(next).toHaveBeenCalledWith(
      expect.objectContaining({ code: "INVALID_TOKEN" }),
    );
  });

  it("returns 401 INVALID_TOKEN when payload is missing required fields", () => {
    const token = jwt.sign({ sub: "u1" }, env.JWT_ACCESS_SECRET, { expiresIn: "15m" });

    const next = vi.fn();
    requireAuth(mockReq(`Bearer ${token}`), mockRes(), next);

    expect(next).toHaveBeenCalledWith(
      expect.objectContaining({ code: "INVALID_TOKEN" }),
    );
  });
});
