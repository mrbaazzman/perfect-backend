import { Router } from "express";
import type { NextFunction, Request, Response } from "express";
import multer from "multer";
import { uploadMaxSizeBytes, env, uploadAllowedMimes } from "../config/env.js";
import { uploadController } from "../controllers/UploadController.js";
import { ApiError } from "../middlewares/error-handler.js";
import { requireAuth } from "../middlewares/auth.js";

const router = Router();

const upload = multer({
  // Memory storage keeps the provider abstraction cloud-portable: a file never
  // touches disk twice, the provider decides where it lands (local dir today,
  // S3/R2 later).
  storage: multer.memoryStorage(),
  limits: { fileSize: uploadMaxSizeBytes },
  fileFilter: (_req, file, cb) => {
    if (!uploadAllowedMimes.includes(file.mimetype.toLowerCase())) {
      return cb(
        new ApiError(
          400,
          `File type not allowed. Allowed: ${uploadAllowedMimes.join(", ")}`,
          "FILE_TYPE_NOT_ALLOWED",
        ),
      );
    }
    cb(null, true);
  },
});

// Wraps multer so its errors become ApiErrors (the error handler stays
// multer-agnostic). LIMIT_FILE_SIZE is surfaced with a friendly code/message.
function singleFile(field: string) {
  const middleware = upload.single(field);
  return (req: Request, res: Response, next: NextFunction) =>
    middleware(req, res, (err: unknown) => {
      if (err instanceof multer.MulterError) {
        if (err.code === "LIMIT_FILE_SIZE") {
          return next(
            new ApiError(
              400,
              `File too large — the limit is ${env.UPLOAD_MAX_SIZE_MB} MB`,
              "FILE_TOO_LARGE",
            ),
          );
        }
        return next(new ApiError(400, "Upload failed", "UPLOAD_FAILED"));
      }
      next(err);
    });
}

router.post("/", requireAuth, singleFile("file"), async (req, res) => {
  const result = await uploadController.upload(req);
  res.status(201).json(result);
});

export const uploadRouter = router;
