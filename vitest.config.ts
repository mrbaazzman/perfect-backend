import { defineConfig } from "vitest/config";
import path from "node:path";

export default defineConfig({
  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname, "src"),
    },
  },
  test: {
    globals: true,
    environment: "node",
    setupFiles: ["src/__tests__/setup.ts"],
    include: ["src/**/*.test.ts"],
    pool: "forks",
    singleFork: true,
    env: {
      NODE_ENV: "test",
      DATABASE_URL: "file:./prisma/test.db",
      JWT_ACCESS_SECRET: "test-access-secret-at-least-32-chars-long!",
      JWT_REFRESH_SECRET: "test-refresh-secret-at-least-32-chars-long!",
      JWT_ACCESS_EXPIRES_IN: "15m",
      JWT_REFRESH_EXPIRES_IN: "7d",
      GOOGLE_CLIENT_ID: "test-google-client-id",
      GOOGLE_CLIENT_SECRET: "test-google-client-secret",
      GOOGLE_REDIRECT_URI: "http://localhost:3000/api/auth/google/callback",
      FRONTEND_URL: "http://localhost:5173",
      STORAGE_DRIVER: "local",
      UPLOAD_DIR: "uploads-test",
      UPLOAD_PUBLIC_BASE: "/uploads",
    },
  },
});
