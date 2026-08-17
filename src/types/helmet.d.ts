declare module "helmet" {
  import type { IncomingMessage, ServerResponse } from "node:http";

  type HelmetMiddleware = (
    req: IncomingMessage,
    res: ServerResponse,
    next: (err?: unknown) => void,
  ) => void;

  interface Helmet {
    (options?: Record<string, unknown>): HelmetMiddleware;
  }

  const helmet: Helmet;
  export default helmet;
}
