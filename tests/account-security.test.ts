import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { Application, token } from '@framework/core';
import { createConnection, type DatabaseConnection } from '@framework/database';
import { createHttpKernel } from '@framework/http';
import { createTestDatabase, requireTestDatabaseUrl, type TestDatabase } from '@framework/testing';
import {
  type AccountTokenStore,
  AUTH_SERVICE,
  type AuthConfig,
  type AuthRoutesDeps,
  authActorResolver,
  base32Decode,
  createAuthProvider,
  defaultAuthConfig,
  defineAuthRoutes,
  hotp,
  PgRecoveryCodeStore,
  type RecoveryCodeStore,
  type SessionStore,
  verified,
} from '../src';
import { AuthService } from '../src/auth-service';
import {
  BunPasswordHasher,
  DatabaseUserProvider,
  PgAccountTokenStore,
  PgSessionStore,
  PgTokenStore,
} from '../src/index';

const PASSWORD = 'correct horse battery';
const RESET_PASSWORD = 'rotated correct horse';

/** Captured notifier deliveries: purpose → tokens (assertion + retrieval). */
const deliveries: Record<'emailVerification' | 'passwordReset', string[]> = {
  emailVerification: [],
  passwordReset: [],
};

const notifiers = {
  emailVerification: async (_user: unknown, token: string) => {
    deliveries.emailVerification.push(token);
  },
  passwordReset: async (_user: unknown, token: string) => {
    deliveries.passwordReset.push(token);
  },
};

let database: TestDatabase;
let connection: DatabaseConnection;
let service: AuthService;
let accountTokens: AccountTokenStore;
let sessions: SessionStore;

/** The TOTP code the user's authenticator would show right now. */
const currentCode = (secret: string): string => hotp(base32Decode(secret), BigInt(Math.floor(Date.now() / 30_000)));

/** Asserts a delivery exists and returns it (non-null without `!`). */
const firstDelivery = (purpose: 'emailVerification' | 'passwordReset'): string => {
  const token = deliveries[purpose][0];
  if (!token) throw new Error(`expected a captured ${purpose} token`);
  return token;
};

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
  await connection.sql`
    create table totp_recovery_codes (
      id uuid primary key default gen_random_uuid(),
      user_id uuid not null references users(id) on delete cascade,
      code_hash text not null unique,
      used_at timestamptz,
      created_at timestamptz not null default now(),
      updated_at timestamptz not null default now())`;

  accountTokens = new PgAccountTokenStore(connection);
  const recoveryCodes: RecoveryCodeStore = new PgRecoveryCodeStore(connection);
  sessions = new PgSessionStore(connection);
  service = new AuthService({
    hasher: new BunPasswordHasher(),
    users: new DatabaseUserProvider(connection),
    sessions,
    tokens: new PgTokenStore(connection),
    accountTokens,
    recoveryCodes,
    notifiers,
    sessionTtlSeconds: defaultAuthConfig.session.ttlSeconds,
    tokenTtlSeconds: defaultAuthConfig.token.ttlSeconds,
    verificationTtlSeconds: defaultAuthConfig.verification.ttlSeconds,
    resetTtlSeconds: defaultAuthConfig.passwordReset.ttlSeconds,
    twoStepChallengeTtlSeconds: defaultAuthConfig.twoStep.challengeTtlSeconds,
    totpIssuer: defaultAuthConfig.twoStep.issuer,
  });
});

afterAll(async () => {
  await connection.close();
  await database.drop();
});

describe('Email verification', () => {
  let userId: string;
  let token: string;

  test('issues a single-use token and delivers it through the notifier hook', async () => {
    const user = await service.register({ name: 'Vera', email: 'vera@example.test', password: PASSWORD });
    userId = user.id;
    expect(user.emailVerifiedAt).toBeNull();
    token = await service.requestEmailVerification(user);
    expect(deliveries.emailVerification).toEqual([token]);
    expect(token).toMatch(/^[0-9a-f]{64}$/);
  });

  test('verifying stamps email_verified_at exactly once', async () => {
    const verified = await service.verifyEmail(token);
    expect(verified?.emailVerifiedAt).not.toBeNull();

    // Single use: the replay resolves to nothing and changes nothing.
    expect(await service.verifyEmail(token)).toBeNull();
  });

  test('expired and unknown tokens are indistinguishable no-ops', async () => {
    const second = await service.requestEmailVerification({ id: userId } as never);
    await connection.sql`update account_tokens set expires_at = now() - interval '1 second' where token_hash is not null and consumed_at is null`;
    expect(await service.verifyEmail(second)).toBeNull();
    expect(await service.verifyEmail('deadbeef'.repeat(8))).toBeNull();
  });
});

describe('Password recovery', () => {
  let adaId: string;
  let resetToken: string;
  let sessionToken: string;
  let apiTokenValue: string;

  test('unknown emails resolve silently without issuing anything', async () => {
    await service.requestPasswordReset('nobody@example.test');
    expect(deliveries.passwordReset).toEqual([]);
  });

  test('known emails issue one token via the notifier', async () => {
    const ada = await service.register({ name: 'Ada', email: 'reset-ada@example.test', password: PASSWORD });
    adaId = ada.id;
    const issued = await service.issueToken(ada, { name: 'cli', abilities: ['*'] });
    apiTokenValue = issued.plaintext;
    const session = await service.startSession(ada.id);
    sessionToken = session.sessionToken;

    await service.requestPasswordReset('RESET-ada@example.test'); // case-insensitive like login
    expect(deliveries.passwordReset).toHaveLength(1);
    resetToken = firstDelivery('passwordReset');
  });

  test('a fresh request supersedes the outstanding token', async () => {
    await service.requestPasswordReset('reset-ada@example.test');
    const newer = deliveries.passwordReset[1];
    if (!newer) throw new Error('expected a second reset delivery');
    expect(newer).not.toBe(resetToken);
    expect(await service.resetPassword(resetToken, RESET_PASSWORD)).toBe(false);
    resetToken = newer;
  });

  test('reset rotates the password and revokes every session and API token', async () => {
    expect(await sessions.find(sessionToken)).not.toBeNull(); // alive before the reset
    expect(await service.resetPassword(resetToken, RESET_PASSWORD)).toBe(true);

    expect(await sessions.find(sessionToken)).toBeNull(); // session gone
    const via = await service.attempt('reset-ada@example.test', RESET_PASSWORD);
    expect(via?.user.id).toBe(adaId); // new password works
    expect(await service.attempt('reset-ada@example.test', PASSWORD)).toBeNull(); // old password dead

    // API tokens are credentials too: a reset revokes them.
    const found = await new PgTokenStore(connection).find(apiTokenValue);
    expect(found).toBeNull();
  });

  test('replayed and unknown reset tokens are indistinguishable failures', async () => {
    expect(await service.resetPassword(resetToken, RESET_PASSWORD)).toBe(false);
    expect(await service.resetPassword('deadbeef'.repeat(8), RESET_PASSWORD)).toBe(false);
  });
});

describe('Two-step login (TOTP + recovery codes)', () => {
  let graceId: string;
  let secret: string;
  let recoveryCodes: readonly string[];

  test('users without TOTP log in directly', async () => {
    const grace = await service.register({ name: 'Grace', email: 'grace@example.test', password: PASSWORD });
    graceId = grace.id;
    const start = await service.startLogin('grace@example.test', PASSWORD);
    expect(start?.kind).toBe('session');
  });

  test('enrollment stores a pending secret and provisioning URI', async () => {
    const enrollment = await service.startTotpEnrollment({ id: graceId, email: 'grace@example.test' } as never);
    secret = enrollment.secret;
    expect(enrollment.uri).toContain('otpauth://totp/');
    expect(enrollment.uri).toContain(`secret=${secret}`);
  });

  test('activation requires a valid code and yields recovery codes', async () => {
    expect(await service.enableTotp(graceId, '000000')).toBeNull(); // wrong code
    expect(await service.enableTotp(graceId, '12345')).toBeNull(); // wrong shape
    const codes = await service.enableTotp(graceId, currentCode(secret));
    expect(codes).toHaveLength(10);
    expect(await service.unusedRecoveryCodes(graceId)).toBe(10);
    recoveryCodes = codes ?? [];
  });

  test('with TOTP enabled, the first factor yields a challenge, not a session', async () => {
    const start = await service.startLogin('grace@example.test', PASSWORD);
    expect(start?.kind).toBe('two-step');
    if (start?.kind !== 'two-step') throw new Error('unreachable');
    // Wrong code consumes the challenge; the replay is dead too.
    expect(await service.completeTwoStep(start.challenge, '000000')).toBeNull();
    expect(await service.completeTwoStep(start.challenge, currentCode(secret))).toBeNull();
    // Wrong password never gets a challenge.
    expect(await service.startLogin('grace@example.test', 'nope')).toBeNull();
  });

  test('a valid TOTP code completes the login', async () => {
    const start = await service.startLogin('grace@example.test', PASSWORD);
    if (start?.kind !== 'two-step') throw new Error('expected a two-step challenge');
    const done = await service.completeTwoStep(start.challenge, currentCode(secret));
    expect(done?.user.id).toBe(graceId);
    expect(done?.sessionToken).toMatch(/^fw_sess_/);
  });

  test('a recovery code completes the login exactly once', async () => {
    const [first, second] = recoveryCodes;
    if (!first || !second) throw new Error('expected two recovery codes');
    const start = await service.startLogin('grace@example.test', PASSWORD);
    if (start?.kind !== 'two-step') throw new Error('expected a two-step challenge');
    expect(await service.completeTwoStep(start.challenge, first)).not.toBeNull();
    expect(await service.unusedRecoveryCodes(graceId)).toBe(9);

    // A failed attempt consumed that challenge: each code attempt costs one
    // full (throttled) login. The used code fails; the next one works.
    const retry = await service.startLogin('grace@example.test', PASSWORD);
    if (retry?.kind !== 'two-step') throw new Error('expected a two-step challenge');
    expect(await service.completeTwoStep(retry.challenge, first)).toBeNull();
    const fresh = await service.startLogin('grace@example.test', PASSWORD);
    if (fresh?.kind !== 'two-step') throw new Error('expected a two-step challenge');
    expect(await service.completeTwoStep(fresh.challenge, second)).not.toBeNull();
  });

  test('disabling verifies a code, then clears the secret and remaining codes', async () => {
    expect(await service.disableTotp(graceId, '000000')).toBe(false); // wrong code keeps 2FA on
    expect(await service.disableTotp(graceId, currentCode(secret))).toBe(true);
    expect(await service.unusedRecoveryCodes(graceId)).toBe(0);
    const start = await service.startLogin('grace@example.test', PASSWORD);
    expect(start?.kind).toBe('session');
  });
});

describe('Account security endpoints', () => {
  const config = { auth: defaultAuthConfig } satisfies { auth: AuthConfig };
  type TestApp = Application<typeof config>;
  const TEST_CONNECTION = token<DatabaseConnection>('test.database-connection');
  let app: TestApp;
  let http: ReturnType<typeof buildHttp>;

  const buildHttp = () =>
    createHttpKernel(app, { exposeInternalErrors: true, resolveActor: authActorResolver(app) }).route(
      '/auth',
      defineAuthRoutes({ service: AUTH_SERVICE, session: config.auth.session } satisfies AuthRoutesDeps),
    );

  const post = (body: unknown) => ({
    method: 'POST',
    body: JSON.stringify(body),
    headers: { 'content-type': 'application/json' },
  });
  const cookieFor = (response: Response): string =>
    response.headers
      .get('set-cookie')
      ?.split(';')
      .find((part) => part.trim().startsWith(`${defaultAuthConfig.session.cookie}=`))
      ?.split('=')
      .slice(1)
      .join('=') ?? '';

  test('login answers two-step shape and two-step completes to a session', async () => {
    app = new Application<typeof config>({
      config,
      providers: [
        {
          name: 'database',
          register({ container }: { container: TestApp['container'] }) {
            container.singleton(TEST_CONNECTION, () => connection);
          },
        },
        createAuthProvider<typeof config>({ connection: TEST_CONNECTION, notifiers }),
      ],
    });
    await app.boot();
    http = buildHttp();

    const user = await service.register({ name: 'Tess', email: 'tess@example.test', password: PASSWORD });
    const enrollment = await service.startTotpEnrollment(user);
    await service.enableTotp(user.id, currentCode(enrollment.secret));

    const loginResponse = await http.request('/auth/login', post({ email: 'tess@example.test', password: PASSWORD }));
    expect(loginResponse.status).toBe(200);
    const body = (await loginResponse.json()) as { twoStep: boolean; challenge: string };
    expect(body.twoStep).toBe(true);
    expect(body.challenge).toMatch(/^[0-9a-f]{64}$/);

    const done = await http.request(
      '/auth/two-step',
      post({ challenge: body.challenge, code: currentCode(enrollment.secret) }),
    );
    expect(done.status).toBe(200);
    expect(cookieFor(done)).not.toBe('');
  });

  test('forgot answers 202 for both known and unknown emails; reset rotates via token', async () => {
    deliveries.passwordReset.length = 0;
    expect((await http.request('/auth/password/forgot', post({ email: 'ghost@example.test' }))).status).toBe(202);
    expect((await http.request('/auth/password/forgot', post({ email: 'tess@example.test' }))).status).toBe(202);
    expect(deliveries.passwordReset).toHaveLength(1);

    expect(
      (
        await http.request(
          '/auth/password/reset',
          post({ token: deliveries.passwordReset[0], password: RESET_PASSWORD }),
        )
      ).status,
    ).toBe(204);
    expect(
      (
        await http.request(
          '/auth/password/reset',
          post({ token: deliveries.passwordReset[0], password: RESET_PASSWORD }),
        )
      ).status,
    ).toBe(422);
  });

  test('email verify endpoint stamps the address; wrong tokens are 422', async () => {
    const user = await service.register({ name: 'Eve', email: 'eve@example.test', password: PASSWORD });
    const token = await service.requestEmailVerification(user);
    deliveries.emailVerification.length = 0;
    expect((await http.request('/auth/email/verify', post({ token }))).status).toBe(200);
    expect((await http.request('/auth/email/verify', post({ token }))).status).toBe(422);
  });

  test('the verified() middleware admits verified users and rejects unverified ones', async () => {
    const guard = createHttpKernel(app, { exposeInternalErrors: true, resolveActor: authActorResolver(app) })
      .route('/auth', defineAuthRoutes({ service: AUTH_SERVICE, session: config.auth.session }))
      .get('/verified-only', verified(), (c) => c.text('welcome'));

    const login = await guard.request('/auth/login', post({ email: 'eve@example.test', password: PASSWORD }));
    const eveCookie = cookieFor(login);

    // Eve verified herself in the previous test; a fresh user has not.
    await service.register({ name: 'Unv', email: 'unverified@example.test', password: PASSWORD });
    const unverified = await guard.request(
      '/auth/login',
      post({ email: 'unverified@example.test', password: PASSWORD }),
    );
    const unverifiedCookie = cookieFor(unverified);

    expect(
      (
        await guard.request('/verified-only', {
          headers: { cookie: `${defaultAuthConfig.session.cookie}=${eveCookie}` },
        })
      ).status,
    ).toBe(200);
    const denied = await guard.request('/verified-only', {
      headers: { cookie: `${defaultAuthConfig.session.cookie}=${unverifiedCookie}` },
    });
    expect(denied.status).toBe(403);
    expect((await guard.request('/verified-only')).status).toBe(401);
  });
});
