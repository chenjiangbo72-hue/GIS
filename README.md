# Express JWT authentication demo

A small, runnable Node.js authentication service that demonstrates password handling, access-token authentication, refresh-token rotation, and logout.

## Run it

```bash
cp .env.example .env
npm install
npm start
```

Open [http://localhost:3000](http://localhost:3000). Register an account, then use the page to call the protected endpoint.

## Routes

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/auth/register` | Create an account and issue tokens |
| `POST` | `/auth/login` | Verify credentials and issue tokens |
| `POST` | `/auth/refresh` | Rotate refresh token and return a new access token |
| `POST` | `/auth/logout` | Revoke the current refresh session |
| `GET` | `/api/me` | Read the current user from a bearer access token |
| `GET` | `/health` | Liveness check |

## Authentication flow

1. Registration and login hash passwords with bcrypt (cost 12); plaintext passwords are never stored.
2. The API returns a signed 15-minute access JWT. The browser keeps it only in JavaScript memory and sends it as `Authorization: Bearer <token>` to protected APIs.
3. The API places a signed seven-day refresh JWT in an `HttpOnly`, `SameSite=Lax` cookie scoped to `/auth`. JavaScript cannot read it.
4. `/auth/refresh` verifies and consumes the old refresh token, then issues a replacement cookie and access token. The server stores only a SHA-256 digest of every refresh token, so reuse of a consumed token fails.
5. Logout deletes the server-side session entry and clears the cookie.

## Credential and token handling

- Secrets come only from `JWT_ACCESS_SECRET` and `JWT_REFRESH_SECRET`; `.env` is ignored by Git. Set separate high-entropy values in deployment.
- Production mode refuses to start without both secrets and enables the `Secure` cookie flag.
- Access and refresh tokens use different signing secrets and carry a `type` claim to prevent cross-use.
- This example uses in-memory users and refresh sessions, so a process restart signs everyone out and it is not horizontally scalable. Replace the `Map` objects in `src/auth-store.js` with a database (and consider Redis for refresh-session allowlists) before production use.
- Add HTTPS, rate limiting, email verification, password-reset flow, CSRF protection appropriate to your deployment, audit logging, and a secrets manager for production.
