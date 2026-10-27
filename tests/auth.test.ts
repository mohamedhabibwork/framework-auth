import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { createConnection, type DatabaseConnection } from '@framework/database';
import { createTestDatabase, requireTestDatabaseUrl, type TestDatabase } from '@framework/testing';
import { eq } from 'drizzle-orm';
import type { UserRecord } from '../src';
import {
  AuthService,
  BunPasswordHasher,
  DatabaseUserProvider,
  defaultAuthConfig,
  PgSessionStore,
  PgTokenStore,
  users,
} from '../src';

let database: TestDatabase;
let connection: DatabaseConnection;
let service: AuthService;
let registered: UserRecord;

const DEPS = () => ({
  hasher: new BunPasswordHasher(),
  users: new DatabaseUserProvider(connection),
  sessions: new PgSessionStore(connection),
  tokens: new PgTokenStore(connection),
  sessionTtlSeconds: defaultAuthConfig.session.ttlSeconds,
  tokenTtlSeconds: defaultAuthConfig.token.ttlSeconds,
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
  await connection.sql`create index sessions_user_id_idx on sessions (user_id)`;
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
  await connection.sql`create index api_tokens_user_id_idx on api_tokens (user_id)`;
  service = new AuthService(DEPS());
  registered = await service.register({ name: 'Ada', email: 'ada@example.test', password: 'correct horse battery' });
});

afterAll(async () => {
  await connection.close();
  await database.drop();
});

describe('Password hashing', () => {
  test('argon2id hashes verify and never repeat (salted)', async () => {
    const hasher = new BunPasswordHasher();
    const hash = await hasher.hash('s3cret-password');
    expect(hash).not.toContain('s3cret');
    expect(await hasher.verify('s3cret-password', hash)).toBe(true);
    expect(await hasher.verify('wrong-password', hash)).toBe(false);
    expect(await hasher.hash('s3cret-password')).not.toBe(hash);
  });
});

describe('Session store', () => {
  test('create/find round-trips the cookie value and joins the user', async () => {
    const store = new PgSessionStore(connection);
    const issued = await store.create(registered.id, 60);
    expect(issued.token.startsWith('fw_sess_')).toBe(true);
    const resolved = await store.find(issued.token);
    expect(resolved?.session.id).toBe(issued.session.id);
    expect(resolved?.user.email).toBe('ada@example.test');

    expect(await store.find('fw_sess_not-a-real-token')).toBeNull();
  });

  test('expired sessions are filtered and pruned', async () => {
    const store = new PgSessionStore(connection);
    const issued = await store.create(registered.id, 3600);
    await connection.sql`update sessions set expires_at = now() - interval '1 minute' where id = ${issued.session.id}`;
    expect(await store.find(issued.token)).toBeNull();
    expect(await store.prune()).toBe(1);
    expect(await store.prune()).toBe(0);
  });

  test('countExpired reports expired sessions without deleting them', async () => {
    const store = new PgSessionStore(connection);
    const before = await store.countExpired();
    const issued = await store.create(registered.id, 3600);
    await connection.sql`update sessions set expires_at = now() - interval '1 minute' where id = ${issued.session.id}`;
    expect(await store.countExpired()).toBe(before + 1);
    expect(await store.prune()).toBe(1);
    expect(await store.countExpired()).toBe(before);
  });

  test('rotate invalidates the old token atomically', async () => {
    const store = new PgSessionStore(connection);
    const first = await store.create(registered.id, 3600);
    const second = await store.rotate(first.token, 3600);
    if (!second) throw new Error('rotate returned null for a live token');
    expect(second.token).not.toBe(first.token);
    expect(await store.find(first.token)).toBeNull();
    expect((await store.find(second.token))?.session.id).toBe(second.session.id);

    // Unknown token: rotation is a no-op returning null (idempotent).
    expect(await store.rotate('fw_sess_unknown', 60)).toBeNull();
  });

  test('touch renews the sliding window', async () => {
    const store = new PgSessionStore(connection);
    const issued = await store.create(registered.id, 2);
    await store.touch(issued.session.id, 3600);
    const resolved = await store.find(issued.token);
    if (!resolved) throw new Error('session did not resolve after touch');
    const remaining = Date.parse(resolved.session.expiresAt) - Date.now();
    expect(remaining).toBeGreaterThan(3_000_000);
  });

  test('revoke targets one token; revokeAllForUser removes the rest', async () => {
    const store = new PgSessionStore(connection);
    const a = await store.create(registered.id, 3600);
    const b = await store.create(registered.id, 3600);
    expect(await store.revoke(a.token)).toBe(true);
    expect(await store.find(a.token)).toBeNull();
    expect(await store.find(b.token)).not.toBeNull();
    expect(await store.revokeAllForUser(registered.id)).toBeGreaterThanOrEqual(1);
    expect(await store.find(b.token)).toBeNull();
    expect(await store.revokeAllForUser(registered.id)).toBe(0);
  });
});

describe('API token store', () => {
  test('issue/find round-trips abilities; plaintext never stored', async () => {
    const store = new PgTokenStore(connection);
    const issued = await store.issue(registered.id, 'ci', ['notes.view'], null);
    expect(issued.plaintext.startsWith('fw_pat_')).toBe(true);
    const resolved = await store.find(issued.plaintext);
    expect(resolved?.token.name).toBe('ci');
    expect(resolved?.token.abilities).toEqual(['notes.view']);
    expect(resolved?.user.id).toBe(registered.id);

    const rows = await connection.sql<
      { token_hash: string }[]
    >`select token_hash from api_tokens where id = ${issued.token.id}`;
    expect(rows[0]?.token_hash.startsWith('fw_pat_')).toBe(false);
  });

  test('expired and revoked tokens stop resolving', async () => {
    const store = new PgTokenStore(connection);
    const expired = await store.issue(registered.id, 'expired', ['*'], 3600);
    await connection.sql`update api_tokens set expires_at = now() - interval '1 minute' where id = ${expired.token.id}`;
    expect(await store.find(expired.plaintext)).toBeNull();

    const revoked = await store.issue(registered.id, 'revoked', ['*'], null);
    expect(await store.revoke(revoked.token.id, registered.id)).toBe(true);
    expect(await store.find(revoked.plaintext)).toBeNull();
    // Listing only shows unrevoked tokens; revocation is idempotent-safe.
    expect((await store.listForUser(registered.id)).some((t) => t.id === revoked.token.id)).toBe(false);
    expect(await store.revoke(revoked.token.id, registered.id)).toBe(false);
  });

  test('revoke enforces ownership', async () => {
    const store = new PgTokenStore(connection);
    const other = await service.register({ name: 'Bob', email: 'bob@example.test', password: 'other-password-1' });
    const issued = await store.issue(registered.id, 'mine', ['*'], null);
    expect(await store.revoke(issued.token.id, other.id)).toBe(false);
    expect(await store.find(issued.plaintext)).not.toBeNull();
  });
});

describe('Auth service', () => {
  test('register stores a hash; duplicate emails raise the unique violation', async () => {
    expect(registered.passwordHash.startsWith('$argon2')).toBe(true);
    const failure = await service.register({ name: 'Clone', email: 'ada@example.test', password: 'whatever-123' }).then(
      () => null,
      (error: Error & { cause?: { code?: string } }) => error,
    );
    // Drizzle wraps driver errors; the SQLSTATE surfaces through the cause.
    expect(failure?.cause?.code ?? (failure as { code?: string })?.code).toBe('23505');
  });

  test('attempt verifies credentials and starts a session; failures return null', async () => {
    const ok = await service.attempt('ada@example.test', 'correct horse battery');
    expect(ok?.user.id).toBe(registered.id);
    expect(ok?.sessionToken.startsWith('fw_sess_')).toBe(true);

    expect(await service.attempt('ada@example.test', 'wrong password')).toBeNull();
    expect(await service.attempt('nobody@example.test', 'wrong password')).toBeNull();
  });

  test('issueToken honors explicit and configured lifetimes', async () => {
    const issued = await service.issueToken(registered, { name: 'explicit', ttlSeconds: 60 });
    expect(issued.token.abilities).toEqual(['*']);
    expect(Date.parse(issued.token.expiresAt ?? '') - Date.now()).toBeLessThan(70_000);

    const forever = await service.issueToken(registered, { name: 'forever', ttlSeconds: null });
    expect(forever.token.expiresAt).toBeNull();

    const scoped = await service.issueToken(registered, { name: 'scoped', abilities: ['notes.view'] });
    expect(scoped.token.abilities).toEqual(['notes.view']);
  });

  test('logout revokes the principal credential it authenticated with', async () => {
    const attempt = await service.attempt('ada@example.test', 'correct horse battery');
    if (!attempt) throw new Error('attempt failed for known credentials');
    const sessionPrincipal = {
      id: registered.id,
      via: 'session',
      abilities: ['*'],
      user: registered,
      sessionId: attempt.sessionId,
    } as const;
    expect(await service.logout(sessionPrincipal)).toBe(true);
    expect(await new PgSessionStore(connection).find(attempt.sessionToken)).toBeNull();

    const issued = await service.issueToken(registered, { name: 'logout-me' });
    const tokenPrincipal = {
      id: registered.id,
      via: 'api-token',
      abilities: ['*'],
      user: registered,
      tokenId: issued.token.id,
    } as const;
    expect(await service.logout(tokenPrincipal)).toBe(true);
    expect(await new PgTokenStore(connection).find(issued.plaintext)).toBeNull();
  });

  test('revokeAll* wipes every credential of a user', async () => {
    await service.attempt('ada@example.test', 'correct horse battery');
    await service.issueToken(registered, { name: 'wipe' });
    expect(await service.revokeAllSessions(registered.id)).toBeGreaterThanOrEqual(1);
    expect(await service.revokeAllTokens(registered.id)).toBeGreaterThanOrEqual(1);
    expect(await service.revokeAllSessions(registered.id)).toBe(0);
    expect(await service.revokeAllTokens(registered.id)).toBe(0);
  });
});

describe('User provider', () => {
  test('findById and findByEmail resolve records', async () => {
    const provider = new DatabaseUserProvider(connection);
    expect((await provider.findById(registered.id))?.email).toBe('ada@example.test');
    expect((await provider.findByEmail('ada@example.test'))?.id).toBe(registered.id);
    expect(await provider.findById(crypto.randomUUID())).toBeNull();
  });

  test('cascading deletes remove sessions and tokens with the user', async () => {
    const provider = new DatabaseUserProvider(connection);
    const temp = await service.register({ name: 'Temp', email: 'temp@example.test', password: 'temp-password-1' });
    await service.attempt('temp@example.test', 'temp-password-1');
    await service.issueToken(temp, { name: 'temp-token' });
    await connection.db.delete(users).where(eq(users.id, temp.id));
    expect(await provider.findById(temp.id)).toBeNull();
    const orphanSessions = await connection.sql<
      { count: number }[]
    >`select count(*)::int as count from sessions where user_id = ${temp.id}`;
    const orphanTokens = await connection.sql<
      { count: number }[]
    >`select count(*)::int as count from api_tokens where user_id = ${temp.id}`;
    expect(orphanSessions[0]?.count).toBe(0);
    expect(orphanTokens[0]?.count).toBe(0);
  });
});
