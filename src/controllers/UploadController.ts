import type { Request } from "express";
import { ApiError } from "../middlewares/error-handler.js";
import { storageService } from "../services/StorageService.js";

// Canonical extension per MIME type. The on-disk extension is derived from the
// declared type (not the client's filename), so the served Content-Type always
// matches the file's extension. Types not in this map are still whitelisted by
// UPLOAD_ALLOWED_MIMES but are saved without an extension.
const MIME_TO_EXT: Record<string, string> = {
  "image/png": ".png",
  "image/jpeg": ".jpg",
  "image/webp": ".webp",
  "image/gif": ".gif",
  "application/pdf": ".pdf",
  "text/plain": ".txt",
  "application/json": ".json",
};

class UploadController {
  // Generic upload primitive: stores any whitelisted file and returns its
  // public URL. Consumers attach the URL wherever it belongs (avatar -> image
  // on the user, post -> a content field, ...) — one endpoint for every
  // future resource.
  async upload(req: Request) {
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
}

export const uploadController = new UploadController();
