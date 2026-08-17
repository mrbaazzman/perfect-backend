import { v2 as cloudinary } from "cloudinary";
import { env } from "../config/env.js";

cloudinary.config({
  cloud_name: env.CLOUDINARY_CLOUD_NAME,
  api_key: env.CLOUDINARY_API_KEY,
  api_secret: env.CLOUDINARY_API_SECRET,
  secure: true,
});

export const storageService = {
  async save(input: { buffer: Buffer; mimeType?: string; extension?: string }) {
    const result = await new Promise<{ public_id: string; secure_url: string }>((resolve, reject) => {
      const uploadStream = cloudinary.uploader.upload_stream(
        {
          resource_type: "auto",
          folder: env.UPLOAD_DIR,
        },
        (error, result) => {
          if (error) return reject(error);
          if (!result) return reject(new Error("Upload failed"));
          resolve(result);
        },
      );
      uploadStream.end(input.buffer);
    });

    return { url: result.secure_url, key: result.public_id };
  },

  async remove(key: string) {
    if (!key) return;
    await cloudinary.uploader.destroy(key);
  },

  keyFromUrl(url: string): string | undefined {
    if (!url.includes("cloudinary.com")) return undefined;
    const match = url.match(/\/upload\/v\d+\/(.+?)(?:\.\w+)?$/);
    return match?.[1];
  },
};
