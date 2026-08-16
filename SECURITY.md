# Security

This template is designed to be **secure-ready**: the core web-application threats are addressed by default so the baseline is safe to build on.

## Threat model

| Threat | Mitigation |
|---|---|
| **XSS stealing tokens** | Access token is **memory-only** (JS variable, never `localStorage`/`sessionStorage`). Refresh token is an **httpOnly cookie** JS cannot read. Even if an attacker runs JS in the page, they get nothing durable. |
| **CSRF / cross-site requests** | Refresh token cookie is `SameSite=Lax`, `Path=/api/auth`, `Secure` in prod. Cross-site `POST`/XHR never carries it; only same-origin requests can refresh. |
| **Stolen refresh token** | **Rotation on every refresh** — old token is revoked the moment a new one is issued, so a stolen token is single-use. **Reuse-revocation:** re-presenting a revoked token (the fingerprint of a replay) kills the **entire token family** — the thief and the legitimate client are both forced to re-authenticate. A short grace window (30s) absorbs the benign two-tab race without nuking the session. Tokens stored **hashed (sha256)** in the DB, never in plaintext. |
| **Stolen access token** | Short TTL (15m default) limits the damage window. |
| **Brute-force login** | bcrypt (10 rounds) + `authLimiter` (30 req / 15 min per IP) on `/api/auth/login|register|refresh` only. The page-load bootstrap (`/auth/session`) is exempt from limiting (cookie-gated, returns only the caller's own data), so refreshing the page can't trip the lockout. |
| **Malicious file uploads** | `POST /api/uploads` is auth-gated, size-capped (`UPLOAD_MAX_SIZE_MB`, multer `LIMIT_FILE_SIZE`), and MIME-whitelisted (`UPLOAD_ALLOWED_MIMES`). **SVG is deliberately excluded** — an SVG is HTML that can carry `<script>`, and served from our own origin it would be a stored-XSS vector. Files go through the storage provider: Cloudinary (signed requests — `api_key`/`api_secret` never reach the client; the composite `resourceType:publicId` key means `destroy` can only be called with a valid signature) or local disk with server-generated filenames (`crypto.randomUUID()` + MIME-derived extension, never client-controlled — no path traversal, no extension spoofing). Old managed files are deleted on avatar replace/clear and on account deletion (best-effort; a failure leaves an orphan, never a broken profile). |
| **Credential leak (API)** | Passwords are bcrypt-hashed; the API never returns a refresh token in a JSON body; secrets come from `.env` with zod min-length validation. |
| **Clickjacking / framing** | `frame-ancestors 'none'` (CSP) + helmet `X-Frame-Options`. |
| **Injection (SQL/NoSQL/HTML)** | Prisma parametrizes all queries; zod validates every input; React escapes all output. |
| **Injection (scripts/styles)** | Strict **CSP** in production: `script-src 'self'` — no inline scripts. User content is never rendered as raw HTML. |
| **DoS / abuse** | `express-rate-limit` per IP, 1mb body cap, helmet headers. |

## Implemented controls

- **Authentication:** JWT access token (HS256, 15m) + rotating refresh token (7d). Register / login / refresh / logout / me / update-profile / change-password / delete-account. Refresh tokens are grouped into **families** (`familyId`); `logout` and password-change revoke the whole family, and a replayed (already-revoked) token revokes it too — so a session can only die on replay, never be extended by one.
- **Token transport:** refresh token in an `httpOnly`, `SameSite=Lax`, `Secure` (prod), `Path=/api/auth` cookie; `remember` kept as a JWT claim so rotation preserves the cookie lifetime (7d vs session cookie). `withCredentials` on the axios client.
- **Hashing:** bcrypt (10 rounds) for passwords; sha256 for refresh-token DB records.
- **Headers:** helmet (CSP, HSTS, X-Content-Type-Options, referrer-policy, frame options, etc.); `x-powered-by` disabled; `trust proxy` for correct IPs behind a reverse proxy.
- **Validation:** zod on every request body (email, password strength, sizes); ZodError → 400 via a global error handler that hides internals in production.
- **Rate limiting:** global `apiLimiter` (100/15min/IP, `skip` for `/auth/session`) + `authLimiter` (30/15min/IP) scoped to `login`/`register`/`refresh` — brute-force surface only.
- **CSP:** injected by `vite.config.ts` — strict in prod, dev-compatible for Fast Refresh. FOUC theme guard lives in an external file (`public/theme-guard.js`). `frame-ancestors` is set as a **header** (helmet on the API; prod host for the SPA) since meta tags can't carry it. Page loads bootstrap through `GET /api/auth/session` (always 200) so logged-out users produce no error noise.

## Deployment checklist (when going live)

1. `NODE_ENV=production`, `JWT_ACCESS_SECRET` / `JWT_REFRESH_SECRET` as 32+ char random values (e.g. `openssl rand -hex 32`).
2. Serve over HTTPS (the refresh cookie `Secure` flag depends on it) and set `CORS_ORIGIN` to the exact frontend origin (not `*`).
3. Serve the built frontend from a static host/CDN with the same CSP header (and HSTS), ideally behind a reverse proxy (nginx/Caddy) — rate limit IPs come from `trust proxy`.
4. Per-account lockout and login-delay are the natural next hardening steps — they need DB-backed counters/Redis.

## Notes

- The access token is intentionally short-lived and memory-only: a full-page refresh re-establishes the session through the httpOnly refresh cookie — `GET /auth/session` (page-load bootstrap) validates it without rotating, and `POST /auth/refresh` rotates it.
- `img-src https:` in the CSP is required for user-supplied avatar URLs; tighten to `img-src 'self' https://your-cdn.example` if avatars are ever served from a controlled origin.
- `npm audit` reports **0 vulnerabilities** in both projects (as of the last check).
