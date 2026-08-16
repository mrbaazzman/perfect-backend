import { describe, it, expect, vi } from "vitest";
import { ZodError, z } from "zod";
import { ApiError, errorHandler } from "../middlewares/error-handler.js";
import * as envModule from "../config/env.js";

function mockRes() {
  const res = {
    status: vi.fn().mockReturnThis(),
    json: vi.fn().mockReturnThis(),
  };
  return res as unknown as { status: ReturnType<typeof vi.fn>; json: ReturnType<typeof vi.fn> };
}

describe("ApiError", () => {
  it("has the correct name", () => {
    const err = new ApiError(400, "bad request");
    expect(err.name).toBe("ApiError");
    expect(err).toBeInstanceOf(Error);
  });

  it("stores statusCode, message, and code", () => {
    const err = new ApiError(409, "taken", "EMAIL_TAKEN");
    expect(err.statusCode).toBe(409);
    expect(err.message).toBe("taken");
    expect(err.code).toBe("EMAIL_TAKEN");
  });

  it("code is optional", () => {
    const err = new ApiError(500, "oops");
    expect(err.code).toBeUndefined();
  });
});

describe("errorHandler", () => {
  it("returns JSON for ApiError with code", () => {
    const res = mockRes();
    const err = new ApiError(409, "Email taken", "EMAIL_TAKEN");

    errorHandler(err, {} as any, res as any, vi.fn());

    expect(res.status).toHaveBeenCalledWith(409);
    expect(res.json).toHaveBeenCalledWith({ error: "Email taken", code: "EMAIL_TAKEN" });
  });

  it("returns JSON for ApiError without code", () => {
    const res = mockRes();
    const err = new ApiError(401, "Unauthorized");

    errorHandler(err, {} as any, res as any, vi.fn());

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: "Unauthorized" });
  });

  it("formats ZodError into 400 with VALIDATION code", () => {
    const res = mockRes();
    const schema = z.object({ email: z.string().email() });
    const err = new ZodError(
      schema.safeParse({ email: "bad" }).error!.issues,
    );

    errorHandler(err, {} as any, res as any, vi.fn());

    expect(res.status).toHaveBeenCalledWith(400);
    const body = res.json.mock.calls[0]![0] as Record<string, string>;
    expect(body.code).toBe("VALIDATION");
    expect(body.error).toContain("email");
  });

  it("returns 500 for unknown errors", () => {
    const res = mockRes();
    const consoleSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    errorHandler(new Error("something broke"), {} as any, res as any, vi.fn());

    expect(res.status).toHaveBeenCalledWith(500);
    const body = res.json.mock.calls[0]![0] as Record<string, string>;
    expect(body.error).toBe("Internal server error");
    // In test (NODE_ENV=test), detail should be included
    expect(body.detail).toBe("something broke");

    consoleSpy.mockRestore();
  });

  it("hides detail in production", () => {
    vi.spyOn(envModule, "env", "get").mockReturnValue({
      ...envModule.env,
      NODE_ENV: "production" as const,
    });

    const res = mockRes();
    const consoleSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    errorHandler(new Error("secret"), {} as any, res as any, vi.fn());

    const body = res.json.mock.calls[0]![0] as Record<string, string>;
    expect(body.detail).toBeUndefined();

    consoleSpy.mockRestore();
    vi.restoreAllMocks();
  });
});
