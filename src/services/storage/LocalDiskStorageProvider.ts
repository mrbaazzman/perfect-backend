import crypto from "node:crypto";
import { mkdirSync } from "node:fs";
import { rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { StorageProvider } from "./types.js";

// Keys are always `crypto.randomUUID() + extension` — generated server-side, so
// a client can never inject a path or filename (no traversal, no extension
// spoofing beyond the MIME-derived one).
const SAFE_KEY = /^[a-f0-9-]+(\.[a-z0-9]+)?$/;

export class LocalDiskStorageProvider implements StorageProvider {
  readonly publicBase: string;
  private readonly dir: string;

  constructor(dir: string, publicBase: string) {
    this.dir = path.isAbsolute(dir)
      ? dir
      : path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..", dir);
    this.publicBase = publicBase;
    mkdirSync(this.dir, { recursive: true });
  }

  async save(input: { buffer: Buffer; extension: string }) {
    const key = `${crypto.randomUUID()}${input.extension}`;
    await writeFile(path.join(this.dir, key), input.buffer);
    return { url: `${this.publicBase}/${key}`, key };
  }

  async remove(key: string) {
    // Defensive: only ever delete keys we generated.
    if (!SAFE_KEY.test(key)) return;
    await rm(path.join(this.dir, key), { force: true });
  }

  isManagedUrl(url: string) {
    return url.startsWith(`${this.publicBase}/`);
  }

  keyFromUrl(url: string) {
    if (!this.isManagedUrl(url)) return undefined;
    return url.slice(this.publicBase.length + 1);
  }
}
