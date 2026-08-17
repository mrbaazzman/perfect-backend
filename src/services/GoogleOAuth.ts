import crypto from "node:crypto";
import { env } from "../config/env.js";
import { ApiError } from "../middlewares/error-handler.js";

const OIDC_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration";
const GOOGLE_ISSUERS = ["accounts.google.com", "https://accounts.google.com"];
const CACHE_TTL_MS = 60 * 60 * 1000;
const CLOCK_SKEW_SECONDS = 60;

interface OidcConfig {
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
}

interface JwkKey {
  kty: string;
  kid?: string;
  use?: string;
  alg?: string;
  n?: string;
  e?: string;
}

interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  id_token: string;
  scope: string;
}

interface GoogleProfile {
  sub: string;
  email: string;
  email_verified: boolean;
  name?: string;
  given_name?: string;
  family_name?: string;
  picture?: string;
  iss?: string;
  aud?: string;
  exp?: number;
  iat?: number;
  nonce?: string;
}

let oidcCache: { fetchedAt: number; data: OidcConfig } | null = null;
let jwksCache: { fetchedAt: number; uri: string; keys: JwkKey[] } | null = null;

function requireOAuthEnv() {
  if (!env.GOOGLE_CLIENT_ID || !env.GOOGLE_CLIENT_SECRET || !env.GOOGLE_REDIRECT_URI) {
    throw new ApiError(500, "Google OAuth is not configured", "OAUTH_NOT_CONFIGURED");
  }
  return { clientId: env.GOOGLE_CLIENT_ID, clientSecret: env.GOOGLE_CLIENT_SECRET, redirectUri: env.GOOGLE_REDIRECT_URI };
}

async function fetchJson<T>(url: string): Promise<T> {
  const res = await fetch(url, {
    headers: { Accept: "application/json" },
    // Discovery and JWKS are public, immutable-for-hours documents — a short
    // timeout keeps a stuck upstream from hanging a login.
    signal: AbortSignal.timeout(10_000),
  });
  if (!res.ok) {
    throw new ApiError(502, `Google OAuth upstream returned ${res.status}`, "OAUTH_PROVIDER_ERROR");
  }
  return (await res.json()) as T;
}

/** Fetches (and caches for 1h) Google's OIDC discovery document. */
async function getOidcConfig(): Promise<OidcConfig> {
  if (oidcCache && Date.now() - oidcCache.fetchedAt < CACHE_TTL_MS) {
    return oidcCache.data;
  }
  const data = await fetchJson<OidcConfig>(OIDC_DISCOVERY_URL);
  oidcCache = { fetchedAt: Date.now(), data };
  return data;
}

/** Fetches (and caches for 1h) the signing keys from Google's JWKS endpoint. */
async function getJwks(): Promise<JwkKey[]> {
  const oidc = await getOidcConfig();
  if (jwksCache && jwksCache.uri === oidc.jwks_uri && Date.now() - jwksCache.fetchedAt < CACHE_TTL_MS) {
    return jwksCache.keys;
  }
  const doc = await fetchJson<{ keys: JwkKey[] }>(oidc.jwks_uri);
  const keys = doc.keys.filter((k) => k.kty === "RSA" && (!k.use || k.use === "sig"));
  jwksCache = { fetchedAt: Date.now(), uri: oidc.jwks_uri, keys };
  return keys;
}

/** S256 PKCE challenge per RFC 7636. */
function computeCodeChallenge(verifier: string): string {
  return crypto.createHash("sha256").update(verifier).digest("base64url");
}

export function generatePkce(): { verifier: string; challenge: string } {
  const verifier = crypto.randomBytes(32).toString("base64url");
  return { verifier, challenge: computeCodeChallenge(verifier) };
}

export function generateOAuthToken(): string {
  return crypto.randomBytes(16).toString("hex");
}

/** Builds the Google authorization URL for the code + PKCE flow. */
export async function buildAuthUrl(params: {
  state: string;
  nonce: string;
  codeChallenge: string;
}): Promise<string> {
  const oidc = await getOidcConfig();
  const { clientId, redirectUri } = requireOAuthEnv();
  const url = new URL(oidc.authorization_endpoint);
  url.searchParams.set("client_id", clientId);
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", "openid email profile");
  url.searchParams.set("state", params.state);
  url.searchParams.set("nonce", params.nonce);
  url.searchParams.set("code_challenge", params.codeChallenge);
  url.searchParams.set("code_challenge_method", "S256");
  return url.toString();
}

/** Exchanges an authorization code for tokens at Google's token endpoint. */
export async function exchangeCodeForTokens(code: string, codeVerifier: string): Promise<TokenResponse> {
  const oidc = await getOidcConfig();
  const { clientId, clientSecret, redirectUri } = requireOAuthEnv();
  const body = new URLSearchParams({
    code,
    client_id: clientId,
    client_secret: clientSecret,
    redirect_uri: redirectUri,
    grant_type: "authorization_code",
    code_verifier: codeVerifier,
  });

  const res = await fetch(oidc.token_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
    signal: AbortSignal.timeout(10_000),
  });
  const data = (await res.json()) as Partial<TokenResponse> & { error?: string };
  if (!res.ok || typeof data.id_token !== "string") {
    throw new ApiError(
      502,
      `Token exchange failed${data.error ? `: ${data.error}` : ` (HTTP ${res.status})`}`,
      "OAUTH_EXCHANGE_FAILED",
    );
  }
  return data as TokenResponse;
}

/** Verifies the RS256 signature on a JWT against the given JWKS keys. */
function verifyJwtSignature<T>(
  token: string,
  keys: JwkKey[],
): { header: { kid?: string; alg?: string }; payload: T } {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new ApiError(400, "Malformed ID token", "OAUTH_INVALID_ID_TOKEN");
  }
  const [headerB64, payloadB64, sigB64] = parts;
  if (headerB64 === undefined || payloadB64 === undefined || sigB64 === undefined) {
    throw new ApiError(400, "Malformed ID token", "OAUTH_INVALID_ID_TOKEN");
  }

  let header: { kid?: string; alg?: string };
  let payload: T;
  try {
    header = JSON.parse(Buffer.from(headerB64, "base64url").toString("utf8"));
    payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8")) as T;
  } catch {
    throw new ApiError(400, "Malformed ID token", "OAUTH_INVALID_ID_TOKEN");
  }

  const key = keys.find((k) => k.kid === header.kid);
  if (!key || key.kty !== "RSA" || !key.n || !key.e) {
    throw new ApiError(400, "No signing key matches the ID token", "OAUTH_INVALID_ID_TOKEN");
  }

  const publicKey = crypto.createPublicKey({ key: { kty: key.kty, n: key.n, e: key.e }, format: "jwk" });
  const valid = crypto.verify(
    "RSA-SHA256",
    Buffer.from(`${headerB64}.${payloadB64}`, "utf8"),
    publicKey,
    Buffer.from(sigB64, "base64url"),
  );
  if (!valid) {
    throw new ApiError(400, "ID token signature is invalid", "OAUTH_INVALID_ID_TOKEN");
  }

  return { header, payload };
}

/** Verifies a Google ID token end-to-end (signature + claims) and returns the profile. */
export async function verifyIdToken(idToken: string, nonce: string): Promise<GoogleProfile> {
  const keys = await getJwks();
  const { payload } = verifyJwtSignature<GoogleProfile>(idToken, keys);
  const { clientId } = requireOAuthEnv();

  const now = Math.floor(Date.now() / 1000);
  if (payload.iss === undefined || !GOOGLE_ISSUERS.includes(payload.iss)) {
    throw new ApiError(400, "ID token issuer is not Google", "OAUTH_INVALID_ID_TOKEN");
  }
  if (payload.aud !== clientId) {
    throw new ApiError(400, "ID token audience does not match this client", "OAUTH_INVALID_ID_TOKEN");
  }
  if (payload.exp !== undefined && payload.exp <= now - CLOCK_SKEW_SECONDS) {
    throw new ApiError(400, "ID token has expired", "OAUTH_INVALID_ID_TOKEN");
  }
  if (payload.iat !== undefined && payload.iat > now + CLOCK_SKEW_SECONDS) {
    throw new ApiError(400, "ID token was issued in the future", "OAUTH_INVALID_ID_TOKEN");
  }
  if (payload.nonce !== nonce) {
    throw new ApiError(400, "ID token nonce mismatch", "OAUTH_INVALID_ID_TOKEN");
  }
  if (payload.email_verified !== true || typeof payload.email !== "string") {
    throw new ApiError(403, "Google email is not verified", "OAUTH_EMAIL_UNVERIFIED");
  }

  return payload;
}
