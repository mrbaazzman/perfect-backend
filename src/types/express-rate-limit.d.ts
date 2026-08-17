declare module "express-rate-limit" {
  import type { RequestHandler } from "express";

  interface Options {
    windowMs?: number;
    limit?: number;
    standardHeaders?: "draft-6" | "draft-7" | "draft-8";
    legacyHeaders?: boolean;
    skip?: (req: any) => boolean;
    message?: any;
    [key: string]: unknown;
  }

  type RateLimitRequestHandler = RequestHandler & { resetKey?: (key: string) => void };

  function rateLimit(options?: Partial<Options>): RateLimitRequestHandler;

  export { rateLimit as default };
  export type { Options, RateLimitRequestHandler };
}
