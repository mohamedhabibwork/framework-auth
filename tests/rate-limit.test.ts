import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { MemoryRateLimiter, RATE_LIMITER } from '@framework/cache';
import { Application, token } from '@framework/core';
import { createConnection, type DatabaseConnection } from '@framework/database';
import { createHttpKernel } from '@framework/http';
import { createTestDatabase, requireTestDatabaseUrl, type TestDatabase } from '@framework/testing';
import {
  AUTH_RATE_LIMITER,
  AUTH_SERVICE,
  type AuthConfig,
  type AuthRoutesDeps,
  authActorResolver,
  createAuthProvider,
  defaultAuthConfig,
  defineAuthRoutes,
} from '../src';

/** Small limit so the window behaviour is exercisable in a handful of requests. */
const MAX_ATTEMPTS = 3;
const WINDOW_SECONDS = 60;
const PASSWORD = 'correct horse battery';
const WRONG_PASSWORD = 'wrong password';

/** Limiter enabled: the main application under test. */
const config: { auth: AuthConfig } = {
  auth: {
    ...defaultAuthConfig,
    rateLimit: { enabled: true, maxAttempts: MAX_ATTEMPTS, windowSeconds: WINDOW_SECONDS },
  },
};
type TestApp = Application<typeof config>;

/** Same limit, but the feature is explicitly switched off in configuration. */
const disabledConfig: { auth: AuthConfig } = {
  auth: {
    ...defaultAuthConfig,
    rateLimit: { enabled: false, maxAttempts: MAX_ATTEMPTS, windowSeconds: WINDOW_SECONDS },
  },
};
type DisabledApp = Application<typeof disabledConfig>;

/** Binds the test connection so the auth provider uses the isolated database. */
const TEST_CONNECTION = token<DatabaseConnection>('test.database-connection');

const providersFor = <TConfig extends { auth: AuthConfig }>() => [
  {
    name: 'database',
    register({ container }: { container: Application<TConfig>['container'] }) {
      container.singleton(TEST_CONNECTION, () => connection);
    },
  },
  {
    name: 'rate-limiter',
    register({ container }: { container: Application<TConfig>['container'] }) {
      container.value(RATE_LIMITER, new MemoryRateLimiter());
    },
  },
  createAuthProvider<TConfig>({ connection: TEST_CONNECTION }),
];

let database: TestDatabase;
let connection: DatabaseConnection;
let app: TestApp;
let disabledApp: DisabledApp;

/** Login flow with the limiter the auth provider published as AUTH_RATE_LIMITER. */
let http: ReturnType<typeof buildHttp>;
/** Limiter injected, but `rateLimit.enabled: false` in the route configuration. */
let disabledHttp: ReturnType<typeof buildHttp>;
/** No limiter injected at all (pre-feature call shape). */
let unlimitedHttp: ReturnType<typeof buildHttp>;

const buildHttp = (application: TestApp | DisabledApp, routes: AuthRoutesDeps) =>
  createHttpKernel(application, { exposeInternalErrors: true, resolveActor: authActorResolver(application) }).route(
    '/auth',
    defineAuthRoutes(routes),
  );

/** Minimal shape of a mounted Hono kernel for tests. */
type HttpLike = { request: (path: string, init?: RequestInit) => Response | Promise<Response> };

/** Compact login probe returning the raw response for status/header/body checks. */
const login = (h: HttpLike, email: string, password: string) =>
  h.request('/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
    headers: { 'content-type': 'application/json' },
  });

const register = (email: string) =>
  http.request('/auth/register', {
    method: 'POST',
    body: JSON.stringify({ name: 'R', email, password: PASSWORD }),
    headers: { 'content-type': 'application/json' },
  });

beforeAll(async () => {
  database = await createTestDatabase({ adminUrl: requireTestDatabaseUrl() });
  connection = createConnection({ url: database.url, maxConnections: 4 });
  await connection.sql`
    create table users (
      id uuid primary key default gen_random_uuid(),
      name text not null,
      email text not null unique,
      email_verified_at timestamptz,
      password_hash text not null,
      totp_secret text,
      created_at timestamptz not null default now(),
      updated_at timestamptz not null default now())`;
  await connection.sql`
    create table sessions (
      id uuid primary key default gen_random_uuid(),
      user_id uuid not null references users(id) on delete cascade,
      token_hash text not null unique,
      expires_at timestamptz not null,
      last_used_at timestamptz not null default now(),
      created_at timestamptz not null default now(),
      updated_at timestamptz not null default now())`;
  await connection.sql`
    create table api_tokens (
      id uuid primary key default gen_random_uuid(),
      user_id uuid not null references users(id) on delete cascade,
      name text not null,
      token_hash text not null unique,
      abilities text[] not null,
      expires_at timestamptz,
      last_used_at timestamptz not null default now(),
      revoked_at timestamptz,
      created_at timestamptz not null default now(),
      updated_at timestamptz not null default now())`;

  app = new Application<typeof config>({
    config,
    providers: providersFor<typeof config>(),
  });
  await app.boot();

  disabledApp = new Application<typeof disabledConfig>({
    config: disabledConfig,
    providers: providersFor<typeof disabledConfig>(),
  });
  await disabledApp.boot();

  // Wiring mirrors the documented composition: the limiter published by the
  // auth provider (only when bound and enabled) is handed to the routes.
  http = buildHttp(app, {
    service: AUTH_SERVICE,
    session: config.auth.session,
    rateLimit: config.auth.rateLimit,
    rateLimiter: app.container.has(AUTH_RATE_LIMITER) ? app.container.resolve(AUTH_RATE_LIMITER) : undefined,
  });
  disabledHttp = buildHttp(disabledApp, {
    service: AUTH_SERVICE,
    session: disabledConfig.auth.session,
    rateLimit: disabledConfig.auth.rateLimit,
    rateLimiter: disabledApp.container.resolve(RATE_LIMITER),
  });
  unlimitedHttp = buildHttp(app, { service: AUTH_SERVICE, session: config.auth.session });
});

afterAll(async () => {
  await app.shutdown();
  await disabledApp.shutdown();
  await database.drop();
});

describe('Login rate limiting', () => {
  test('the auth provider publishes the cache limiter only when enabled and bound', () => {
    expect(app.container.has(AUTH_RATE_LIMITER)).toBe(true);
    expect(disabledApp.container.has(AUTH_RATE_LIMITER)).toBe(false);
  });

  test(`the first ${MAX_ATTEMPTS} failures get 401; the next attempt is 429 with Retry-After`, async () => {
    const email = 'burst@example.test';
    expect((await register(email)).status).toBe(201);

    for (let i = 0; i < MAX_ATTEMPTS; i++) {
      const response = await login(http, email, WRONG_PASSWORD);
      expect(response.status).toBe(401);
    }
    const blocked = await login(http, email, WRONG_PASSWORD);
    expect(blocked.status).toBe(429);
    const body = (await blocked.json()) as { error: { code: string } };
    expect(body.error.code).toBe('TOO_MANY_REQUESTS');
    const retryAfter = Number(blocked.headers.get('retry-after'));
    expect(Number.isInteger(retryAfter)).toBe(true);
    expect(retryAfter).toBeGreaterThanOrEqual(1);
    expect(retryAfter).toBeLessThanOrEqual(WINDOW_SECONDS);
  });

  test('a correct password after failures still logs in', async () => {
    const email = 'recover@example.test';
    expect((await register(email)).status).toBe(201);
    expect((await login(http, email, WRONG_PASSWORD)).status).toBe(401);

    const ok = await login(http, email, PASSWORD);
    expect(ok.status).toBe(200);
    expect(ok.headers.get('set-cookie')).toBeDefined();
  });

  test('only failures count: a success resets the window', async () => {
    const email = 'window@example.test';
    expect((await register(email)).status).toBe(201);

    // Two failures, then a success — the success must wipe the counter.
    expect((await login(http, email, WRONG_PASSWORD)).status).toBe(401);
    expect((await login(http, email, WRONG_PASSWORD)).status).toBe(401);
    expect((await login(http, email, PASSWORD)).status).toBe(200);

    // Without the reset these failures would have exhausted the allowance already.
    expect((await login(http, email, WRONG_PASSWORD)).status).toBe(401);
    expect((await login(http, email, WRONG_PASSWORD)).status).toBe(401);
    expect((await login(http, email, WRONG_PASSWORD)).status).toBe(401);
    expect((await login(http, email, WRONG_PASSWORD)).status).toBe(429);
  });

  test('counters are isolated per email and case-insensitive', async () => {
    const blocked = 'isolated-a@example.test';
    const other = 'isolated-b@example.test';
    expect((await register(blocked)).status).toBe(201);
    expect((await register(other)).status).toBe(201);

    for (let i = 0; i < MAX_ATTEMPTS; i++) {
      expect((await login(http, blocked, WRONG_PASSWORD)).status).toBe(401);
    }
    expect((await login(http, blocked, WRONG_PASSWORD)).status).toBe(429);

    // A different mailbox keeps its own allowance…
    expect((await login(http, other, WRONG_PASSWORD)).status).toBe(401);
    expect((await login(http, other, PASSWORD)).status).toBe(200);

    // …and casing does not escape the blocked counter.
    expect((await login(http, blocked.toUpperCase(), WRONG_PASSWORD)).status).toBe(429);
  });

  test('enabled: false leaves the endpoint unlimited even with a limiter bound', async () => {
    const email = 'disabled@example.test';
    expect((await register(email)).status).toBe(201);

    for (let i = 0; i < MAX_ATTEMPTS + 2; i++) {
      expect((await login(disabledHttp, email, WRONG_PASSWORD)).status).toBe(401);
    }
    expect((await login(disabledHttp, email, PASSWORD)).status).toBe(200);
  });

  test('an absent limiter keeps the endpoint unlimited (backward compatibility)', async () => {
    const email = 'nolimiter@example.test';
    expect((await register(email)).status).toBe(201);

    for (let i = 0; i < MAX_ATTEMPTS + 2; i++) {
      expect((await login(unlimitedHttp, email, WRONG_PASSWORD)).status).toBe(401);
    }
    expect((await login(unlimitedHttp, email, PASSWORD)).status).toBe(200);
  });
});
