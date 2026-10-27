import { toIsoTimestamp, toIsoTimestampOrNull } from '@framework/database';
import {
  type FrameworkEnv,
  notFound,
  resolve,
  tooManyRequests,
  unauthenticated,
  validationFailed,
} from '@framework/http';
import { validate } from '@framework/validation';
import { Hono } from 'hono';
import { deleteCookie, setCookie } from 'hono/cookie';
import { csrf } from 'hono/csrf';
import type { CookieOptions } from 'hono/utils/cookie';
import { z } from 'zod/v4';
import { defaultAuthConfig } from './config-schema';
import { requireAuth } from './middleware';
import { authPrincipal } from './principals';
import type { ApiTokenRecord, AuthRoutesDeps, UserRecord } from './types';

export const registerSchema = z.object({
  name: z.string().trim().min(1).max(120),
  email: z.string().trim().toLowerCase().email(),
  password: z.string().min(8).max(200),
});

export const loginSchema = z.object({
  email: z.string().trim().toLowerCase().email(),
  password: z.string().min(1).max(200),
});

export const createTokenSchema = z.object({
  name: z.string().trim().min(1).max(120),
  abilities: z.array(z.string().min(1)).min(1).default(['*']),
  ttlSeconds: z.number().int().positive().nullable().optional(),
});

export const verifyEmailSchema = z.object({ token: z.string().min(16).max(200) }).strict();

export const forgotPasswordSchema = z.object({ email: z.string().trim().toLowerCase().email() }).strict();

export const resetPasswordSchema = z
  .object({ token: z.string().min(16).max(200), password: z.string().min(8).max(200) })
  .strict();

export const twoStepSchema = z
  .object({ challenge: z.string().min(16).max(200), code: z.string().min(6).max(32) })
  .strict();

export const totpCodeSchema = z.object({ code: z.string().min(6).max(32) }).strict();

/** Public projection — `passwordHash`, `totpSecret` and raw timestamps never leave. */
export const publicUser = (user: UserRecord) => ({
  id: user.id,
  name: user.name,
  email: user.email,
  emailVerifiedAt: toIsoTimestampOrNull(user.emailVerifiedAt),
  createdAt: toIsoTimestamp(user.createdAt),
  updatedAt: toIsoTimestamp(user.updatedAt),
});

const publicToken = (token: ApiTokenRecord) => ({
  id: token.id,
  name: token.name,
  abilities: token.abilities,
  expiresAt: toIsoTimestampOrNull(token.expiresAt),
  lastUsedAt: toIsoTimestamp(token.lastUsedAt),
  createdAt: toIsoTimestamp(token.createdAt),
});

const cookieOptions = (deps: AuthRoutesDeps): CookieOptions => ({
  httpOnly: true,
  sameSite: 'Lax',
  path: '/',
  secure: deps.session.secure,
  maxAge: deps.session.ttlSeconds,
});

/** Fixed-window counter key: failures are counted per lowercased email. */
const loginKey = (email: string) => `login:${email.toLowerCase()}`;

/** Field errors shaped for the 422 envelope. */
const fieldError = (path: string, message: string) => [{ path, message, code: 'invalid' }] as const;

/**
 * Framework auth endpoints (register/login/logout/me + personal API tokens,
 * email verification, password recovery, two-step login). Mounted by the
 * application, e.g. `.route('/auth', …)` under the API prefix. Credentials
 * are only ever accepted over the JSON body.
 *
 * Login throttling is active only when a `rateLimiter` is injected and
 * `rateLimit.enabled` — either missing leaves the endpoint unlimited, an
 * explicit configuration choice, never a silent bypass. The flow counts
 * failures only: one `consume` per login serves as both the pre-verification
 * check and the failure registration, and a successful login `reset`s the
 * window, so successes never eat into the allowance. Blocked callers get
 * `TOO_MANY_REQUESTS` (429) with a `Retry-After` header before any
 * credential work.
 *
 * Email verification and password recovery never disclose whether an email
 * is registered: `password/forgot` answers an identical 202 either way, and
 * tokens are delivered out of band through the app's notifier hooks. A
 * successful reset rotates the password and revokes every session and API
 * token.
 *
 * Two-step login: when the user has TOTP enabled, `login` returns
 * `{ twoStep: true, challenge }` — a single-use, short-lived challenge — and
 * no session exists until `two-step` verifies a TOTP or recovery code. The
 * challenge is consumed up front, so each code attempt costs one full
 * (throttled) login.
 *
 * CSRF (native Hono middleware) guards the cookie flows only — Bearer-token
 * routes are immune to CSRF, so they accept plain JSON clients without an
 * origin check.
 */
export function defineAuthRoutes(deps: AuthRoutesDeps): Hono<FrameworkEnv> {
  const service = (c: Parameters<typeof resolve>[0]) => resolve(c, deps.service);
  const cookie = cookieOptions(deps);
  const cookieFlow = deps.csrf ?? csrf();
  const rateLimit = deps.rateLimit ?? defaultAuthConfig.rateLimit;
  const limiter = deps.rateLimiter && rateLimit.enabled ? deps.rateLimiter : undefined;

  return (
    new Hono<FrameworkEnv>()
      .post('/register', cookieFlow, validate('json', registerSchema), async (c) => {
        const user = await service(c).register(c.req.valid('json'));
        const session = await service(c).startSession(user.id);
        setCookie(c, deps.session.cookie, session.sessionToken, cookie);
        return c.json({ user: publicUser(user) }, 201);
      })
      .post('/login', cookieFlow, validate('json', loginSchema), async (c) => {
        const input = c.req.valid('json');
        const key = loginKey(input.email);
        if (limiter) {
          const verdict = await limiter.consume(key, rateLimit.maxAttempts, rateLimit.windowSeconds);
          if (!verdict.allowed) {
            c.header('Retry-After', String(verdict.retryAfterSeconds));
            throw tooManyRequests();
          }
        }
        const start = await service(c).startLogin(input.email, input.password);
        if (!start) throw unauthenticated('Invalid credentials');
        if (start.kind === 'two-step') {
          // No session exists yet; the challenge is single-use and short-lived.
          return c.json({ twoStep: true, challenge: start.challenge }, 200);
        }
        if (limiter) await limiter.reset(key);
        setCookie(c, deps.session.cookie, start.sessionToken, cookie);
        return c.json({ user: publicUser(start.user) }, 200);
      })
      .post('/two-step', cookieFlow, validate('json', twoStepSchema), async (c) => {
        const { challenge, code } = c.req.valid('json');
        const result = await service(c).completeTwoStep(challenge, code);
        if (!result) throw unauthenticated('Invalid or expired verification');
        setCookie(c, deps.session.cookie, result.sessionToken, cookie);
        return c.json({ user: publicUser(result.user) }, 200);
      })
      .post('/logout', cookieFlow, requireAuth(), async (c) => {
        const principal = authPrincipal(c);
        if (principal) await service(c).logout(principal);
        deleteCookie(c, deps.session.cookie, { path: '/' });
        return c.body(null, 204);
      })
      .get('/me', requireAuth(), (c) => {
        const principal = authPrincipal(c);
        if (!principal) throw unauthenticated();
        return c.json({ user: publicUser(principal.user), via: principal.via, abilities: principal.abilities }, 200);
      })
      // -- Email verification ----------------------------------------------------
      .post('/email/verification-request', cookieFlow, requireAuth(), async (c) => {
        const principal = authPrincipal(c);
        if (!principal) throw unauthenticated();
        await service(c).requestEmailVerification(principal.user);
        return c.body(null, 202);
      })
      .post('/email/verify', validate('json', verifyEmailSchema), async (c) => {
        const user = await service(c).verifyEmail(c.req.valid('json').token);
        if (!user) throw validationFailed(fieldError('token', 'Invalid or expired verification token'));
        return c.json({ user: publicUser(user) }, 200);
      })
      // -- Password recovery -----------------------------------------------------
      .post('/password/forgot', validate('json', forgotPasswordSchema), async (c) => {
        // Identical response whether or not the email is registered.
        await service(c).requestPasswordReset(c.req.valid('json').email);
        return c.body(null, 202);
      })
      .post('/password/reset', validate('json', resetPasswordSchema), async (c) => {
        const { token, password } = c.req.valid('json');
        const done = await service(c).resetPassword(token, password);
        if (!done) throw validationFailed(fieldError('token', 'Invalid or expired reset token'));
        return c.body(null, 204);
      })
      // -- Two-step (TOTP) management ---------------------------------------------
      .post('/totp/enroll', cookieFlow, requireAuth(), async (c) => {
        const principal = authPrincipal(c);
        if (!principal) throw unauthenticated();
        const enrollment = await service(c).startTotpEnrollment(principal.user);
        return c.json(enrollment, 200);
      })
      .post('/totp/enable', cookieFlow, requireAuth(), validate('json', totpCodeSchema), async (c) => {
        const principal = authPrincipal(c);
        if (!principal) throw unauthenticated();
        const codes = await service(c).enableTotp(principal.id, c.req.valid('json').code);
        if (!codes) throw validationFailed(fieldError('code', 'Invalid verification code'));
        // Plaintext recovery codes are shown exactly once, here.
        return c.json({ recoveryCodes: codes }, 200);
      })
      .post('/totp/disable', cookieFlow, requireAuth(), validate('json', totpCodeSchema), async (c) => {
        const principal = authPrincipal(c);
        if (!principal) throw unauthenticated();
        if (!(await service(c).disableTotp(principal.id, c.req.valid('json').code))) {
          throw validationFailed(fieldError('code', 'Invalid verification code'));
        }
        return c.body(null, 204);
      })
      // -- Personal API tokens -----------------------------------------------------
      .post('/tokens', requireAuth(), validate('json', createTokenSchema), async (c) => {
        const principal = authPrincipal(c);
        if (!principal) throw unauthenticated();
        const issued = await service(c).issueToken(principal.user, c.req.valid('json'));
        // The plaintext value appears exactly once, in this response.
        return c.json({ token: publicToken(issued.token), value: issued.plaintext }, 201);
      })
      .get('/tokens', requireAuth(), async (c) => {
        const principal = authPrincipal(c);
        if (!principal) throw unauthenticated();
        return c.json({ tokens: (await service(c).listTokens(principal.id)).map(publicToken) }, 200);
      })
      .delete('/tokens/:id', requireAuth(), async (c) => {
        const principal = authPrincipal(c);
        if (!principal) throw unauthenticated();
        if (!(await service(c).revokeToken(c.req.param('id'), principal.id))) throw notFound('Token not found');
        return c.body(null, 204);
      })
  );
}
