import "express";

declare global {
  interface AuthUser {
    id: string;
    email: string;
    role: string;
  }

  namespace Express {
    interface Request {
      user?: AuthUser;
    }
  }
}

export {};
