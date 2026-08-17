import type { Prisma } from "../prisma/generated/client.js";

export const BCRYPT_ROUNDS = 10;

type PublicAddress = { state: string | null; city: string | null; line: string | null } | null;

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
      ? { state: user.address.state, city: user.address.city, line: user.address.line }
      : null,
  };
}
