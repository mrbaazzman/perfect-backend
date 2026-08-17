import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    environment: "node",
    setupFiles: ["src/__tests__/setup.ts"],
    include: ["src/**/*.test.ts"],
    pool: "forks",
    maxWorkers: 1,
    env: {
      NODE_ENV: "test",
      DATABASE_URL: "file:./prisma/test.db",
      JWT_ACCESS_SECRET: "test-access-secret-at-least-32-chars-long!",
      JWT_REFRESH_SECRET: "test-refresh-secret-at-least-32-chars-long!",
      JWT_ACCESS_EXPIRES_IN: "15m",
      JWT_REFRESH_EXPIRES_IN: "7d",
      FRONTEND_URL: "http://localhost:5173",
      STORAGE_DRIVER: "local",
      UPLOAD_DIR: "uploads-test",
      UPLOAD_PUBLIC_BASE: "/uploads",
    },
  },
});
