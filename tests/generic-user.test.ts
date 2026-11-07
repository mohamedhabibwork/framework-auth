import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { join } from 'node:path';
import { Application, FrameworkError, type ServiceProvider, token } from '@framework/core';
import { createConnection, type DatabaseConnection } from '@framework/database';
import { createHttpKernel } from '@framework/http';
import { createTestDatabase, requireTestDatabaseUrl, type TestDatabase } from '@framework/testing';
import { pgTable, text } from 'drizzle-orm/pg-core';
import {
  AUTH_SERVICE,
  type AuthConfig,
  type AuthGuard,
  authActorResolver,
  authUserColumns,
  authConfigSchema,
  authGuardsSchema,
  authPrincipal,
  createAuthProvider,
  DatabaseUserProvider,
  defaultAuthConfig,
  PASSWORD_HASHER,
  publicUser,
  type PasswordHasher,
  type Principal,
  SESSION_STORE,
  type SessionStore,
  TOKEN_STORE,
  type ApiTokenStore,
  USER_PROVIDER,
  type UserProvider,
} from '../src';

const appUsers = pgTable('users', { ...authUserColumns(), plan: text('plan').notNull().default('free') });
const otherUsers = pgTable('accounts', authUserColumns());
type AppUser = typeof appUsers.$inferSelect;

const FIXTURE = join(import.meta.dir, 'fixtures/register');
const TEST_CONNECTION = token<DatabaseConnection>('test.generic-user-connection');

type Config = { readonly auth: AuthConfig };

let database: TestDatabase;
let connection: DatabaseConnection;

const databaseProvider: ServiceProvider<Config> = {
  name: 'database',
  register({ container }) {
    container.value(TEST_CONNECTION, connection);
  },
};

const bootApp = async (
  provider: ServiceProvider<Config>,
  auth: AuthConfig = defaultAuthConfig,
): Promise<Application<Config>> => {
  const app = new Application<Config>({ config: { auth }, providers: [databaseProvider, provider] });
  await app.boot();
  return app;
};

/** The code of the provider error `Application.boot` wraps in its `BootError`. */
const bootFailureCode = (boot: Promise<unknown>): Promise<string | undefined> =>
  boot.then(
    () => undefined,
    (error: Error) => (error.cause instanceof FrameworkError ? error.cause.code : undefined),
  );

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
      plan text not null default 'free',
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
});

afterAll(async () => {
  await connection.close();
  await database.drop();
});

describe('createAuthProvider with a custom users table', () => {
  test('every guard resolves the app row, extra columns included', async () => {
    const app = await bootApp(
      createAuthProvider<Config, AppUser>({ connection: TEST_CONNECTION, usersTable: appUsers }),
    );
    const service = app.container.resolve(AUTH_SERVICE);
    const user = await service.register({ name: 'Custom', email: 'custom@example.com', password: 'secret-password' });
    expect((user as AppUser).plan).toBe('free');

    const session = await service.startSession(user.id);
    const issued = await service.issueToken(user, { name: 'cli' });
    const seen: { readonly via: string; readonly plan: string | undefined }[] = [];
    const http = createHttpKernel(app, { exposeInternalErrors: true, resolveActor: authActorResolver(app) });
    http.get('/me', (c) => {
      const principal = authPrincipal<AppUser>(c);
      seen.push({ via: principal?.via ?? 'none', plan: principal?.user.plan });
      return c.json({});
    });

    await http.request('/me', { headers: { cookie: `${defaultAuthConfig.session.cookie}=${session.sessionToken}` } });
    await http.request('/me', { headers: { authorization: `Bearer ${issued.plaintext}` } });

    expect(seen).toEqual([
      { via: 'session', plan: 'free' },
      { via: 'api-token', plan: 'free' },
    ]);
    await app.shutdown();
  });

  test('the default provider reads extra columns on its own lookups', async () => {
    const provider = new DatabaseUserProvider<AppUser>(connection, appUsers);
    const created = await provider.create({ name: 'Direct', email: 'direct@example.com', passwordHash: 'hash' });

    expect(created.plan).toBe('free');
    expect((await provider.findByEmail('direct@example.com'))?.plan).toBe('free');
    await provider.markEmailVerified(created.id);
    expect((await provider.findById(created.id))?.emailVerifiedAt).not.toBeNull();
  });

  test('publicUser never exposes an added column', async () => {
    const provider = new DatabaseUserProvider<AppUser>(connection, appUsers);
    const created = await provider.create({ name: 'Private', email: 'private@example.com', passwordHash: 'hash' });

    const exposed = publicUser(created);

    expect(Object.keys(exposed).sort()).toEqual(['createdAt', 'email', 'emailVerifiedAt', 'id', 'name', 'updatedAt']);
  });

  test('refuses a table the auth foreign keys cannot reference', async () => {
    const boot = bootApp(createAuthProvider<Config>({ connection: TEST_CONNECTION, usersTable: otherUsers }));

    expect(await bootFailureCode(boot)).toBe('AUTH_USERS_TABLE_UNSUPPORTED');
  });
});

describe('replacing auth parts through options', () => {
  const hasher: PasswordHasher = { hash: async (plain) => `hashed:${plain}`, verify: async () => false };
  const users = { findById: async () => null } as unknown as UserProvider;
  const sessions = { touch: async () => {} } as unknown as SessionStore;
  const tokens = { touch: async () => {} } as unknown as ApiTokenStore;

  test('binds the given hasher, user provider and stores', async () => {
    const app = await bootApp(
      createAuthProvider<Config>({
        connection: TEST_CONNECTION,
        hasher,
        userProvider: users,
        stores: { sessions, tokens },
      }),
    );

    expect(app.container.resolve(PASSWORD_HASHER)).toBe(hasher);
    expect(app.container.resolve(USER_PROVIDER)).toBe(users);
    expect(app.container.resolve(SESSION_STORE)).toBe(sessions);
    expect(app.container.resolve(TOKEN_STORE)).toBe(tokens);
    await app.shutdown();
  });

  test('the service uses what was replaced', async () => {
    const lookups: string[] = [];
    const recording = {
      findByEmail: async (email: string) => {
        lookups.push(email);
        return null;
      },
    } as unknown as UserProvider;
    const app = await bootApp(
      createAuthProvider<Config>({ connection: TEST_CONNECTION, hasher, userProvider: recording }),
    );

    const start = await app.container.resolve(AUTH_SERVICE).startLogin('someone@example.com', 'password');

    expect(start).toBeNull();
    expect(lookups).toEqual(['someone@example.com']);
    await app.shutdown();
  });
});

describe('custom guards', () => {
  const partner: Principal = {
    id: 'partner-1',
    via: 'partner-api' as Principal['via'],
    abilities: ['orders.view'],
    user: {} as Principal['user'],
  };
  const partnerGuard: AuthGuard = async (c) => (c.req.header('x-partner-key') === 'valid' ? partner : null);
  const auth: AuthConfig = {
    ...defaultAuthConfig,
    guards: ['partner-api' as AuthConfig['guards'][number], 'session'],
  };

  test('a named guard runs in config order and installs its principal', async () => {
    const app = await bootApp(
      createAuthProvider<Config>({ connection: TEST_CONNECTION, guards: { 'partner-api': partnerGuard } }),
      auth,
    );
    const seen: (string | undefined)[] = [];
    const http = createHttpKernel(app, { exposeInternalErrors: true, resolveActor: authActorResolver(app) });
    http.get('/me', (c) => {
      seen.push(c.get('principal')?.id);
      return c.json({});
    });

    await http.request('/me', { headers: { 'x-partner-key': 'valid' } });
    await http.request('/me', { headers: { 'x-partner-key': 'invalid' } });

    expect(seen).toEqual(['partner-1', undefined]);
    await app.shutdown();
  });

  test('a configured guard with no implementation fails boot', async () => {
    const boot = bootApp(createAuthProvider<Config>({ connection: TEST_CONNECTION }), auth);

    expect(await bootFailureCode(boot)).toBe('AUTH_GUARD_UNKNOWN');
  });

  test('prototype keys are not guards', async () => {
    const boot = bootApp(createAuthProvider<Config>({ connection: TEST_CONNECTION }), {
      ...defaultAuthConfig,
      guards: ['constructor' as AuthConfig['guards'][number]],
    });

    expect(await bootFailureCode(boot)).toBe('AUTH_GUARD_UNKNOWN');
  });

  test('the config schema stays closed unless the app names its guards', () => {
    expect(authConfigSchema.safeParse({ guards: ['partner-api'] }).success).toBe(false);

    const extended = authConfigSchema.extend({ guards: authGuardsSchema('partner-api') });

    expect<readonly string[]>(extended.parse({ guards: ['partner-api', 'jwt'] }).guards).toEqual([
      'partner-api',
      'jwt',
    ]);
    expect(extended.parse({}).guards).toEqual(['session', 'api-token']);
    expect(extended.safeParse({ guards: ['nope'] }).success).toBe(false);
    expect(extended.safeParse({ guards: [] }).success).toBe(false);
  });
});

describe('Register augmentation', () => {
  test('an app augmenting Register.user and guards gets them everywhere', async () => {
    const typecheck = Bun.spawn(['bunx', 'tsc', '-p', 'tsconfig.json'], {
      cwd: FIXTURE,
      stdout: 'pipe',
      stderr: 'pipe',
    });
    const [stdout, stderr, code] = await Promise.all([
      new Response(typecheck.stdout).text(),
      new Response(typecheck.stderr).text(),
      typecheck.exited,
    ]);

    expect(`${code}: ${stdout}${stderr}`).toBe('0: ');
  }, 120_000);
});
