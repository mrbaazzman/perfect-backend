import crypto from "node:crypto";
import bcrypt from "bcryptjs";
import { ApiError } from "../middlewares/error-handler.js";
import type { Address, Prisma } from "../prisma/generated/client.js";

export const BCRYPT_ROUNDS = 10;

// Public profile shape: every scalar field of `User` plus a cleaned (id-free)
// address. Accepts users with or without the address relation loaded.
type PublicAddress = Pick<Address, "state" | "city" | "line"> | null;

export function hashRefreshToken(token: string): string {
  return crypto.createHash("sha256").update(token).digest("hex");
}

export function toPublicUser(user: Prisma.UserGetPayload<{}> & { address?: PublicAddress }) {
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

// Users with a password must prove it; password-less (OAuth) accounts skip
// the check entirely.
export async function verifyCurrentPassword(
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
