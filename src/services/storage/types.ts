// Storage provider contract. The rest of the app only ever talks to this
// interface (via StorageService) — swapping `local` for S3/R2 later is a
// one-file change and zero changes to controllers/routes.
export interface StorageProvider {
  /** Public URL (or path) the file will be served from. */
  readonly publicBase: string;

  save(input: { buffer: Buffer; mimeType?: string; extension?: string }): Promise<{ url: string; key: string }>;

  remove(key: string): Promise<void>;

  /** True when this provider "owns" the given URL (i.e. it's one of ours). */
  isManagedUrl(url: string): boolean;

  /** Derive the provider key from a URL produced by `save`. */
  keyFromUrl(url: string): string | undefined;
}
