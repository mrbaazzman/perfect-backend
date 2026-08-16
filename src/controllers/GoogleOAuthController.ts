import type { Request, Response } from "express";
import { env } from "../config/env.js";
import { ApiError } from "../middlewares/error-handler.js";
import { setRefreshCookie } from "../middlewares/cookies.js";
import { authController } from "./AuthController.js";
import {
  buildAuthUrl,
  exchangeCodeForTokens,
  generateOAuthToken,
  generatePkce,
  verifyIdToken,
} from "../services/GoogleOAuth.js";

// Carries { state, nonce, codeVerifier } between the /google redirect and the
// /google/callback round-trip. httpOnly + short-lived + path-scoped.
const OAUTH_FLOW_COOKIE = "oauthFlow";
const OAUTH_FLOW_COOKIE_OPTIONS = {
  httpOnly: true,
  secure: env.NODE_ENV === "production",
  sameSite: "lax" as const,
  path: "/api/auth/google",
  maxAge: 10 * 60 * 1000,
};

function redirectOAuthError(res: Response, err: unknown) {
  const code = err instanceof ApiError && err.code ? err.code : "OAUTH_PROVIDER_ERROR";
  res.redirect(`${env.FRONTEND_URL}/login?oauth=error=${encodeURIComponent(code)}`);
}

class GoogleOAuthController {
  // GET /api/auth/google — builds the Google consent URL and redirects.
  async start(_req: Request, res: Response) {
    try {
      const state = generateOAuthToken();
      const nonce = generateOAuthToken();
      const { verifier, challenge } = generatePkce();

      const url = await buildAuthUrl({ state, nonce, codeChallenge: challenge });

      res.cookie(
        OAUTH_FLOW_COOKIE,
        JSON.stringify({ state, nonce, verifier }),
        OAUTH_FLOW_COOKIE_OPTIONS,
      );
      res.redirect(url);
    } catch (err) {
      redirectOAuthError(res, err);
    }
  }

  // GET /api/auth/google/callback — verifies the flow cookie, exchanges the
  // code, verifies the ID token, logs the user in, then bounces to the frontend.
  // Every failure redirects to the frontend with `?oauth=error=<CODE>` (never a
  // raw JSON body) so a real browser round-trip stays in the SPA.
  async callback(req: Request, res: Response) {
    res.clearCookie(OAUTH_FLOW_COOKIE, OAUTH_FLOW_COOKIE_OPTIONS);
    try {
      const rawFlow = req.cookies?.[OAUTH_FLOW_COOKIE];
      if (!rawFlow) {
        throw new ApiError(400, "OAuth flow not found", "OAUTH_FLOW_NOT_FOUND");
      }
      let flow: { state: string; nonce: string; verifier: string };
      try {
        flow = JSON.parse(rawFlow);
      } catch {
        throw new ApiError(400, "OAuth flow is invalid", "OAUTH_FLOW_NOT_FOUND");
      }

      const { code, state, error } = req.query;
      if (error) {
        throw new ApiError(400, `Google OAuth denied: ${error}`, "OAUTH_DENIED");
      }
      if (typeof code !== "string" || typeof state !== "string" || state !== flow.state) {
        throw new ApiError(400, "OAuth state mismatch", "OAUTH_STATE_MISMATCH");
      }

      const tokens = await exchangeCodeForTokens(code, flow.verifier);
      const profile = await verifyIdToken(tokens.id_token, flow.nonce);

      const result = await authController.loginWithGoogle({
        email: profile.email,
        firstName: profile.given_name ?? null,
        lastName: profile.family_name ?? null,
        image: profile.picture ?? null,
      });

      setRefreshCookie(res, result.refreshToken, result.remember);
      res.redirect(`${env.FRONTEND_URL}/login?oauth=success`);
    } catch (err) {
      redirectOAuthError(res, err);
    }
  }
}

export const googleOAuthController = new GoogleOAuthController();
