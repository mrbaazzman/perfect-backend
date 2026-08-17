import { execSync } from "node:child_process";
import { prisma } from "../prisma/prisma.js";

// Ensure the test DB schema is up to date before any tests run.
execSync("npx prisma migrate deploy", {
  stdio: "pipe",
  env: { ...process.env, DATABASE_URL: process.env.DATABASE_URL },
});

afterAll(async () => {
  await prisma.$disconnect();
});
