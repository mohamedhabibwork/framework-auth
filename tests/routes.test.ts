import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { Application, EXECUTION_CONTEXT, token } from '@framework/core';
import { createConnection, type DatabaseConnection } from '@framework/database';
import { createHttpKernel, resolve } from '@framework/http';
import { createTestDatabase, requireTestDatabaseUrl, type TestDatabase } from '@framework/testing';
import {
  AUTH_SERVICE,
  type AuthConfig,
  authActorResolver,
  createAuthProvider,
  defaultAuthConfig,
  defineAuthRoutes,
  requireAbility,
} from '../src';

const config = { auth: defaultAuthConfig } satisfies { auth: AuthConfig };
type TestApp = Application<typeof config>;

/** Binds the test connection so the auth provider uses the isolated database. */
const TEST_CONNECTION = token<DatabaseConnection>('test.database-connection');
const connectionProvider = {
  name: 'database',
  register({ container }: { container: TestApp['container'] }) {
    container.singleton(
      TEST_CONNECTION,
      () => connection,
      (c) => c.close(),
    );
  },
};

let database: TestDatabase;
let connection: DatabaseConnection;
let app: TestApp;
let http: ReturnType<typeof buildHttp>;

const buildHttp = () =>
  createHttpKernel(app, { exposeInternalErrors: true, resolveActor: authActorResolver(app) })
    .route('/auth', defineAuthRoutes({ service: AUTH_SERVICE, session: config.auth.session }))
    .get('/whoami', (c) => c.json(resolve(c, EXECUTION_CONTEXT).actor))
    .get('/notes-only', requireAbility('notes.view'), (c) => c.text('granted'));

/** Extracts the framework session cookie value from a Set-Cookie header. */
const sessionCookie = (response: Response): string | undefined =>
  response.headers
    .get('set-cookie')
    ?.split(';')
    .find((part) => part.trim().startsWith(`${defaultAuthConfig.session.cookie}=`))
    ?.split('=')
    .slice(1)
    .join('=');

const cookieHeader = (value: string) => ({ cookie: `${defaultAuthConfig.session.cookie}=${value}` });
const bearer = (value: string) => ({ authorization: `Bearer ${value}` });
const post = (body: unknown, headers?: Record<string, string>) => ({
  method: 'POST',
  body: JSON.stringify(body),
  headers: { 'content-type': 'application/json', ...headers },
});
const login = async () => {
  const response = await http.request(
    '/auth/login',
    post({ email: 'ada@example.test', password: 'correct horse battery' }),
  );
  expect(response.status).toBe(200);
  return sessionCookie(response) as string;
};
const status = async (path: string, init?: RequestInit) => (await http.request(path, init)).status;

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
    create table account_tokens (
      id uuid primary key default gen_random_uuid(),
      user_id uuid not null references users(id) on delete cascade,
      purpose text not null,
      token_hash text not null unique,
      expires_at timestamptz not null,
      consumed_at timestamptz,
      created_at timestamptz not null default now(),
      updated_at timestamptz not null default now())`;
  await connection.sql`create index account_tokens_user_id_idx on account_tokens (user_id)`;
  await connection.sql`
    create table totp_recovery_codes (
      id uuid primary key default gen_random_uuid(),
      user_id uuid not null references users(id) on delete cascade,
      code_hash text not null unique,
      used_at timestamptz,
      created_at timestamptz not null default now(),
      updated_at timestamptz not null default now())`;
  await connection.sql`create index totp_recovery_codes_user_id_idx on totp_recovery_codes (user_id)`;
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
    providers: [connectionProvider, createAuthProvider<typeof config>({ connection: TEST_CONNECTION })],
  });
  await app.boot();
  http = buildHttp();

  await http.request(
    '/auth/register',
    post({ name: 'Ada', email: 'ada@example.test', password: 'correct horse battery' }),
  );
});

afterAll(async () => {
  await app.shutdown();
  await database.drop();
});

describe('Auth endpoints', () => {
  test('register creates the user, sets a secure session cookie and authenticates', async () => {
    const response = await http.request(
      '/auth/register',
      post({ name: 'New', email: 'new@example.test', password: 'another password' }),
    );
    expect(response.status).toBe(201);
    const setCookie = response.headers.get('set-cookie') ?? '';
    expect(setCookie).toContain('HttpOnly');
    expect(setCookie).toContain('SameSite=Lax');
    expect(setCookie).toContain(`Max-Age=${defaultAuthConfig.session.ttlSeconds}`);

    const me = await http.request('/auth/me', { headers: cookieHeader(sessionCookie(response) as string) });
    expect(me.status).toBe(200);
    const body = (await me.json()) as {
      user: { email: string; passwordHash?: string };
      via: string;
      abilities: string[];
    };
    expect(body.user.email).toBe('new@example.test');
    expect(body.user.passwordHash).toBeUndefined();
    expect(body.via).toBe('session');
    expect(body.abilities).toEqual(['*']);
  });

  test('duplicate registration maps to 409 with the stable code', async () => {
    const response = await http.request(
      '/auth/register',
      post({ name: 'Clone', email: 'ada@example.test', password: 'whatever-123' }),
    );
    expect(response.status).toBe(409);
    expect(((await response.json()) as { error: { code: string } }).error.code).toBe('UNIQUE_VIOLATION');
  });

  test('validation failures return 422 with field errors', async () => {
    const response = await http.request('/auth/register', post({ name: '', email: 'not-an-email', password: 'short' }));
    expect(response.status).toBe(422);
    const body = (await response.json()) as { error: { code: string; fields: { path: string }[] } };
    expect(body.error.code).toBe('VALIDATION_FAILED');
    expect(body.error.fields.map((f) => f.path).sort()).toEqual(['email', 'name', 'password']);
  });

  test('login rejects wrong credentials and accepts right ones', async () => {
    const bad = await http.request('/auth/login', post({ email: 'ada@example.test', password: 'wrong password' }));
    expect(bad.status).toBe(401);
    expect(((await bad.json()) as { error: { code: string } }).error.code).toBe('UNAUTHENTICATED');

    const ok = await http.request(
      '/auth/login',
      post({ email: 'ada@example.test', password: 'correct horse battery' }),
    );
    expect(ok.status).toBe(200);
    expect(sessionCookie(ok)).toBeDefined();
  });

  test('logout revokes the session; the cookie stops working', async () => {
    const cookie = await login();
    expect(
      await status('/auth/logout', {
        method: 'POST',
        headers: { ...cookieHeader(cookie), 'content-type': 'application/json' },
      }),
    ).toBe(204);
    expect(await status('/auth/me', { headers: cookieHeader(cookie) })).toBe(401);
  });

  test('expired session cookies are rejected by the guard', async () => {
    const cookie = await login();
    await connection.sql`update sessions set expires_at = now() - interval '1 minute' where token_hash = (select token_hash from sessions order by created_at desc limit 1)`;
    expect(await status('/auth/me', { headers: cookieHeader(cookie) })).toBe(401);
  });

  test('the authenticated actor is visible through the execution context', async () => {
    const cookie = await login();
    const response = await http.request('/whoami', { headers: cookieHeader(cookie) });
    const actor = (await response.json()) as { id: string | null; type: string };
    expect(actor.type).toBe('user');
    expect(actor.id).not.toBeNull();
  });

  test('anonymous requests stay anonymous and protected routes return 401', async () => {
    const who = await http.request('/whoami');
    expect(((await who.json()) as { type: string }).type).toBe('anonymous');
    expect(await status('/auth/me')).toBe(401);
    expect(await status('/notes-only')).toBe(401);
  });

  test('CSRF middleware challenges cross-site form posts on cookie flows', async () => {
    const response = await http.request('/auth/login', {
      method: 'POST',
      body: 'email=ada@example.test&password=x',
      headers: { 'content-type': 'application/x-www-form-urlencoded', origin: 'https://evil.example' },
    });
    expect(response.status).toBe(403);
  });

  test('JSON logins are not challenged by CSRF (API-first contract)', async () => {
    expect(await login()).toBeDefined();
  });
});

describe('API token endpoints', () => {
  test('issuing returns the plaintext exactly once and the token authenticates', async () => {
    const cookie = await login();
    const create = await http.request(
      '/auth/tokens',
      post({ name: 'ci', abilities: ['notes.view'] }, cookieHeader(cookie)),
    );
    expect(create.status).toBe(201);
    const body = (await create.json()) as { value: string; token: { id: string; abilities: string[] } };
    expect(body.value.startsWith('fw_pat_')).toBe(true);
    expect(body.token.abilities).toEqual(['notes.view']);

    const me = await http.request('/auth/me', { headers: bearer(body.value) });
    expect(me.status).toBe(200);
    expect(((await me.json()) as { via: string }).via).toBe('api-token');

    expect(await status('/notes-only', { headers: bearer(body.value) })).toBe(200);
    const list = await http.request('/auth/tokens', { headers: bearer(body.value) });
    expect(((await list.json()) as { tokens: { name: string }[] }).tokens.some((t) => t.name === 'ci')).toBe(true);
  });

  test('token abilities deny what they do not grant (403, not 401)', async () => {
    const cookie = await login();
    const granted = await http.request(
      '/auth/tokens',
      post({ name: 'granted', abilities: ['notes.view'] }, cookieHeader(cookie)),
    );
    const grantedValue = ((await granted.json()) as { value: string }).value;
    expect(await status('/notes-only', { headers: bearer(grantedValue) })).toBe(200);

    const other = await http.request(
      '/auth/tokens',
      post({ name: 'unrelated', abilities: ['orders.view'] }, cookieHeader(cookie)),
    );
    const otherValue = ((await other.json()) as { value: string }).value;
    expect(await status('/notes-only', { headers: bearer(otherValue) })).toBe(403);
  });

  test('revoking the current token invalidates it immediately', async () => {
    const cookie = await login();
    const create = await http.request('/auth/tokens', post({ name: 'shortlived' }, cookieHeader(cookie)));
    const body = (await create.json()) as { value: string; token: { id: string } };
    expect(await status(`/auth/tokens/${body.token.id}`, { method: 'DELETE', headers: bearer(body.value) })).toBe(204);
    expect(await status('/auth/me', { headers: bearer(body.value) })).toBe(401);
  });

  test('revoking an unknown token id returns 404; token routes require authentication', async () => {
    const cookie = await login();
    const create = await http.request('/auth/tokens', post({ name: 'x' }, cookieHeader(cookie)));
    const value = ((await create.json()) as { value: string }).value;
    expect(await status(`/auth/tokens/${crypto.randomUUID()}`, { method: 'DELETE', headers: bearer(value) })).toBe(404);

    expect(await status('/auth/tokens', post({ name: 'anon' }))).toBe(401);
    expect(await status('/auth/tokens')).toBe(401);
  });
});
