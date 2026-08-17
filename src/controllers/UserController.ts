import type { Request } from "express";
import type { Express } from "express";
import bcrypt from "bcryptjs";
import { prisma } from "../prisma/prisma.js";
import { storageService } from "../services/StorageService.js";
import { ApiError } from "../middlewares/error-handler.js";
import type { Prisma } from "../prisma/generated/client.js";
import { BCRYPT_ROUNDS, toPublicUser } from "../utils/auth-utils.js";

async function verifyCurrentPassword(
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

const MIME_TO_EXT: Record<string, string> = {
  "image/png": ".png",
  "image/jpeg": ".jpg",
  "image/webp": ".webp",
  "image/gif": ".gif",
  "application/pdf": ".pdf",
  "text/plain": ".txt",
  "application/json": ".json",
};

export async function me(userId: string) {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    include: { address: true },
  });
  if (!user || !user.isActive) {
    throw new ApiError(401, "Account no longer exists or is deactivated", "ACCOUNT_INACTIVE");
  }
  return { user: toPublicUser(user) };
}

export async function updateProfile(
  userId: string,
  input: {
    firstName?: string;
    lastName?: string;
    birthDate?: string;
    phone?: string;
    image?: string;
    address?: { state?: string; city?: string; line?: string } | null;
  },
  file?: Express.Multer.File,
) {
  const user = await prisma.user.findUnique({ where: { id: userId }, include: { address: true } });
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

  let oldManagedImageKey: string | undefined;
  if (input.image !== undefined && user.image !== input.image.trim()) {
    oldManagedImageKey = storageService.keyFromUrl(user.image ?? "");
  }
  if (input.image !== undefined) data.image = input.image.trim() || null;

  if (file) {
    const stored = await storageService.save({
      buffer: file.buffer,
      mimeType: file.mimetype,
      extension: MIME_TO_EXT[file.mimetype] ?? "",
    });
    data.image = stored.url;
  }

  if (input.address !== undefined) {
    if (input.address === null) {
      if (user.address) {
        data.address = { delete: true };
      }
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

  if (oldManagedImageKey) {
    await storageService.remove(oldManagedImageKey).catch(() => undefined);
  }

  return { user: toPublicUser(updated) };
}

export async function upload(req: Request) {
  const file = req.file;
  if (!file) {
    throw new ApiError(400, "No file provided", "FILE_REQUIRED");
  }
  const extension = MIME_TO_EXT[file.mimetype] ?? "";
  const stored = await storageService.save({
    buffer: file.buffer,
    mimeType: file.mimetype,
    extension,
  });
  return { url: stored.url, key: stored.key, size: file.size, mimeType: file.mimetype };
}

export async function changePassword(userId: string, input: { currentPassword?: string; newPassword: string }) {
  const user = await prisma.user.findUnique({ where: { id: userId } });
  if (!user || !user.isActive) {
    throw new ApiError(401, "Account no longer exists or is deactivated", "ACCOUNT_INACTIVE");
  }
  await verifyCurrentPassword(user, input);

  const passwordHash = await bcrypt.hash(input.newPassword, BCRYPT_ROUNDS);
  await prisma.user.update({ where: { id: userId }, data: { passwordHash } });

  await prisma.refreshToken.updateMany({
    where: { userId, revokedAt: null },
    data: { revokedAt: new Date() },
  });
}

export async function deleteAccount(userId: string, input: { currentPassword?: string }) {
  const user = await prisma.user.findUnique({ where: { id: userId } });
  if (!user || !user.isActive) {
    throw new ApiError(401, "Account no longer exists or is deactivated", "ACCOUNT_INACTIVE");
  }
  await verifyCurrentPassword(user, input);

  const managedImageKey = storageService.keyFromUrl(user.image ?? "");
  await prisma.user.delete({ where: { id: userId } });
  if (managedImageKey) {
    await storageService.remove(managedImageKey).catch(() => undefined);
  }
}
