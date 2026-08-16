import crypto from "node:crypto";
import { ApiError } from "../../middlewares/error-handler.js";
import type { StorageProvider } from "./types.js";

// Signed-request Cloudinary uploads via the REST API — plain `fetch`, no SDK
// (same precedent as the Google-OAuth integration).
//
// The `key` returned here is a composite `resourceType:publicId` (e.g.
// `image:a1b2c3-...`) so `remove` knows which resource_type to destroy —
// Cloudinary's destroy API needs it. Consumers never parse it; it only flows
// back through `remove` / `keyFromUrl`.

type ResourceType = "image" | "video" | "raw";

function resourceTypeFor(mimeType: string): ResourceType {
  if (mimeType.startsWith("image/")) return "image";
  if (mimeType.startsWith("video/")) return "video";
  return "raw";
}

export class CloudinaryStorageProvider implements StorageProvider {
  readonly publicBase: string;

  constructor(
    private readonly cloudName: string,
    private readonly apiKey: string,
    private readonly apiSecret: string,
  ) {
    this.publicBase = `https://res.cloudinary.com/${cloudName}`;
  }

  private sign(params: Record<string, string | number>): string {
    const toSign = Object.keys(params)
      .sort()
      .map((k) => `${k}=${params[k]}`)
      .join("&");
    return crypto.createHash("sha1").update(`${toSign}${this.apiSecret}`).digest("hex");
  }

  async save(input: { buffer: Buffer; mimeType: string }) {
    const resourceType = resourceTypeFor(input.mimeType);
    const timestamp = Math.floor(Date.now() / 1000);
    const publicId = crypto.randomUUID();
    // `resource_type` lives in the URL path, so Cloudinary excludes it from the
    // signed string (verified empirically: a signature over `public_id` +
    // `resource_type` + `timestamp` returns 401 "Invalid Signature").
    const signature = this.sign({ public_id: publicId, timestamp });

    const body = new URLSearchParams();
    body.set("api_key", this.apiKey);
    body.set("file", `data:${input.mimeType};base64,${input.buffer.toString("base64")}`);
    body.set("public_id", publicId);
    body.set("resource_type", resourceType);
    body.set("timestamp", String(timestamp));
    body.set("signature", signature);

    const res = await fetch(
      `https://api.cloudinary.com/v1_1/${this.cloudName}/${resourceType}/upload`,
      { method: "POST", body },
    );
    if (!res.ok) {
      const detail = (await res.text().catch(() => "")).slice(0, 300);
      throw new ApiError(502, `Cloudinary upload failed (${res.status}): ${detail}`, "UPLOAD_FAILED");
    }
    const data = (await res.json()) as { secure_url: string; public_id: string };
    return { url: data.secure_url, key: `${resourceType}:${data.public_id}` };
  }

  async remove(key: string) {
    const [resourceType, publicId] = key.split(":", 2);
    if (!resourceType || !publicId) return;
    const timestamp = Math.floor(Date.now() / 1000);
    const signature = this.sign({ public_id: publicId, timestamp });

    const body = new URLSearchParams();
    body.set("api_key", this.apiKey);
    body.set("public_id", publicId);
    body.set("timestamp", String(timestamp));
    body.set("signature", signature);

    // Best-effort: a failed delete leaves an orphan in the cloud, never a
    // broken profile. The response carries { result: "ok" | "not found" }.
    // `resource_type` lives in the URL path (same as upload), so the signature
    // over `public_id` + `timestamp` stays valid for any type.
    await fetch(`https://api.cloudinary.com/v1_1/${this.cloudName}/${resourceType}/destroy`, {
      method: "POST",
      body,
    }).catch(() => undefined);
  }

  isManagedUrl(url: string) {
    return url.startsWith(`${this.publicBase}/`);
  }

  keyFromUrl(url: string) {
    if (!this.isManagedUrl(url)) return undefined;
    try {
      const segments = new URL(url).pathname.split("/").filter(Boolean);
      // .../<resourceType>/upload/v<version>/<public_id>.<ext>
      const uploadIndex = segments.indexOf("upload");
      if (uploadIndex < 1 || uploadIndex + 1 >= segments.length) return undefined;
      const resourceType = segments[uploadIndex - 1];
      if (resourceType !== "image" && resourceType !== "video" && resourceType !== "raw") {
        return undefined;
      }
      let id = segments.slice(uploadIndex + 1).join("/");
      const first = id.split("/")[0] ?? "";
      if (/^v\d+$/.test(first)) id = id.split("/").slice(1).join("/");
      const dot = id.lastIndexOf(".");
      if (dot > 0) id = id.slice(0, dot);
      if (!id) return undefined;
      return `${resourceType}:${id}`;
    } catch {
      return undefined;
    }
  }
}
