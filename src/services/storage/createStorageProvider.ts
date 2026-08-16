import { env } from "../../config/env.js";
import { CloudinaryStorageProvider } from "./CloudinaryStorageProvider.js";
import { LocalDiskStorageProvider } from "./LocalDiskStorageProvider.js";
import type { StorageProvider } from "./types.js";

export function createStorageProvider(): StorageProvider {
  switch (env.STORAGE_DRIVER) {
    case "local":
      return new LocalDiskStorageProvider(env.UPLOAD_DIR, env.UPLOAD_PUBLIC_BASE);
    case "cloudinary":
      // Env validation guarantees these are present when driver=cloudinary.
      return new CloudinaryStorageProvider(
        env.CLOUDINARY_CLOUD_NAME!,
        env.CLOUDINARY_API_KEY!,
        env.CLOUDINARY_API_SECRET!,
      );
    case "s3":
      // Planned: S3 / Cloudflare R2 object storage. Throws a clear "not
      // implemented" error until wired so a misconfigured prod env can't fail
      // silently.
      throw new Error("STORAGE_DRIVER=s3 is not implemented yet. Use `local` or `cloudinary`.");
    default:
      throw new Error(`Unknown STORAGE_DRIVER: ${env.STORAGE_DRIVER}`);
  }
}
