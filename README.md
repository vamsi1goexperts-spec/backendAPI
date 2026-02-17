# INFLIQ Backend Microservices Runbook

This backend is now gateway-first and core-free for active app traffic.

## Services

- `api-gateway` (`:3000`) - single public entrypoint
- `auth-service` (`:3001`) - auth + OTP + JWT
- `user-service` (`:3002`) - profile/follow/search/nearby
- `post-service` (`:3003`) - post/reels/feed-like routes
- `feed-service` (`:3004`) - specialized feed APIs
- `chat-service` (`:3005`) - chat REST + chat realtime
- `call-service` (`:3006`) - call REST + call realtime + Twilio token
- `media-service` (`:3008`) - media upload/list/delete/signed URLs
- infra: Mongo (`:27017`), Redis (`:6379`)

## Public API Entry

Point clients to the gateway:

- base URL: `http://localhost:3000`
- Expo override env:
  - `EXPO_PUBLIC_API_BASE_URL=http://localhost:3000`

## Route Ownership

- `/api/auth/*` -> auth-service
- `/api/users/*` -> user-service
- `/api/posts/*` -> post-service
- `/api/reels/*` -> post-service
- `/api/feed/*` -> feed-service
- `/api/chats/*` -> chat-service
- `/api/calls/*` -> call-service
- `/api/media/*` -> media-service
- `/api/admin/media/audit-logs` -> media-service audit endpoint alias

Realtime:

- chat socket path: `/socket-chat.io` -> chat-service
- call socket path: `/socket.io` -> call-service

## Local Startup

### Option A: Node dev processes

From `InflicBackendApis`:

- `npm install`
- `npm run dev`

### Option B: Docker stack

From `InflicBackendApis`:

- `npm run micro:up`
- `npm run micro:down`

## Smoke Test

Run smoke checks against the gateway:

- `npm run test:smoke`

Run payload contract checks:

- `npm run test:contracts`
- Includes auth/feed/user plus protected chat and call payload contracts

Optional env vars:

- `SMOKE_BASE_URL` (default: `http://localhost:3000`)
- `SMOKE_TIMEOUT_MS` (default: `10000`)
- `SMOKE_JWT` (enable protected endpoint checks)
- `SMOKE_ADMIN_JWT` (enable admin audit endpoint check)
- `SMOKE_USER_ID` (enables `/api/users/:id` contract check when `SMOKE_JWT` is set)

Contract test optional env:

- `CONTRACT_BASE_URL` (default: `http://localhost:3000`)
- `CONTRACT_TIMEOUT_MS` (default: `10000`)
- `CONTRACT_EMAIL` + `CONTRACT_PASSWORD` (for protected contract checks)
- or `CONTRACT_PHONE` + `CONTRACT_OTP`

Example:

- `SMOKE_BASE_URL=http://localhost:3000 SMOKE_JWT=<token> SMOKE_USER_ID=<userId> npm run test:smoke`

CI:

- GitHub Actions workflow: `.github/workflows/backend-smoke.yml`
- Runs on PRs that touch `InflicBackendApis/**`
- Can also be run manually via `workflow_dispatch`
- Runs both smoke checks and contract checks

Logging:

- Services emit structured JSON logs for startup and error paths.
- Request correlation is preserved with `x-request-id` from gateway to downstream services.

## Environment

Copy `env.sample` values into your real runtime env source.

Key required groups:

- Core: `MONGO_URI`, `JWT_SECRET`, `JWT_EXPIRES_IN`, `REDIS_URL`, `STRICT_PRODUCTION_MODE`
- Service URLs: `AUTH_SERVICE_URL`, `USER_SERVICE_URL`, `POST_SERVICE_URL`, `FEED_SERVICE_URL`, `CHAT_SERVICE_URL`, `CALL_SERVICE_URL`, `MEDIA_SERVICE_URL`, `GATEWAY_PORT`
- Security: `ALLOWED_ORIGINS`, `RATE_LIMIT_WINDOW_MS`, `RATE_LIMIT_MAX`
- Twilio: `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_API_KEY_SID`, `TWILIO_API_KEY_SECRET`
- OTP safety: `OTP_WINDOW_MS`, `OTP_MAX_PER_WINDOW`, `OTP_TTL_SECONDS`
- AWS: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`, `S3_BUCKET`
- Media hardening: `MEDIA_ALLOWED_FOLDERS`, `MAX_MULTIPLE_UPLOAD_FILES`, `SIGNED_URL_EXPIRES_MIN`, `SIGNED_URL_EXPIRES_MAX`, `USER_UPLOAD_WINDOW_MS`, `USER_UPLOAD_MAX_IN_WINDOW`
- Media distributed rate keys: `MEDIA_RATE_LIMIT_PREFIX`
- Media integrity: `MEDIA_STRICT_SIGNATURE_CHECK` (validates magic bytes against MIME)
- Media audit: `MEDIA_AUDIT_LOG_ENABLED`, `MEDIA_AUDIT_LOG_RETENTION_DAYS`
- Media audit access: `MEDIA_AUDIT_READ_MAX_LIMIT`, `MEDIA_ADMIN_USER_IDS`
- Stories hardening: `MAX_STORIES_PER_USER`, `STORY_CREATE_WINDOW_MS`, `STORY_CREATE_MAX_IN_WINDOW`, `STORY_CAPTION_MAX_LEN`, `STORY_MEDIA_ALLOWED_HOSTS`

## Production Notes

- Set `NODE_ENV=production`.
- Keep `STRICT_PRODUCTION_MODE=true` so Redis-dependent services fail fast instead of using in-memory fallback.
- Set strict `ALLOWED_ORIGINS` (no wildcard).
- Keep Twilio/AWS secrets in secret manager (not plaintext env files in repo).
- Run each service as separate deployable unit behind gateway.
- Add centralized logging/metrics/tracing before high traffic rollout.
- Enforce trusted story media hosts (`STORY_MEDIA_ALLOWED_HOSTS`) so stories only use approved storage URLs.
- Keep media object access user-scoped (key ownership checks) and keep signed URL TTLs short.
- Keep strict media signature validation enabled in production (`MEDIA_STRICT_SIGNATURE_CHECK=true`).
- Keep media audit logging enabled for traceability and incident response.
- Expose media audit logs only to trusted admins (`MEDIA_ADMIN_USER_IDS`) and keep list limits bounded.
- Use gateway-provided `x-request-id` for request correlation across services and logs.

