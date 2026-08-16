import { createStorageProvider } from "./storage/createStorageProvider.js";
import type { StorageProvider } from "./storage/types.js";

// Thin service wrapper around the storage provider (a transport-style
// abstraction). Controllers/routes use `storageService`, never a concrete
// provider.
class StorageService {
  constructor(private readonly provider: StorageProvider) {}

  save(input: { buffer: Buffer; mimeType?: string; extension?: string }) {
    return this.provider.save(input);
  }

  remove(key: string) {
    return this.provider.remove(key);
  }

  keyFromUrl(url: string) {
    return this.provider.keyFromUrl(url);
  }
}

export const storageService = new StorageService(createStorageProvider());
