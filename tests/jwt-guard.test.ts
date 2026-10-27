import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import type { Actor } from '@framework/core';
import { createConnection, type DatabaseConnection } from '@framework/database';
import {
  createTestDatabase,
  requireTestDatabaseUrl,
  serveOnEphemeralPort,
  type TestDatabase,
} from '@framework/testing';
import type { Context } from 'hono';
import type { JSONWebKeySet } from 'jose';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { createAuthActorResolver, createJwtPrincipalResolver, DatabaseUserProvider, defaultAuthConfig } from '../src';
import { AuthService } from '../src/auth-service';
import { BunPasswordHasher, PgSessionStore, PgTokenStore } from '../src/index';

const PASSWORD = 'correct horse battery';

let database: TestDatabase;
let connection: DatabaseConnection;
let userId: string;

/** RS256 signing keys: the "current" pair and the "rotated-in" pair. */
let currentKeys: CryptoKeyPair;
let rotatedKeys: CryptoKeyPair;

const jwksWith = async (pairs: readonly { kid: string; keys: CryptoKeyPair }[]): Promise<JSONWebKeySet> => ({
  keys: await Promise.all(
    pairs.map(async ({ kid, keys }) => ({ ...(await exportJWK(keys.publicKey)), kid, alg: 'RS256', use: 'sig' })),
  ),
});

/** Signs an access token the way an identity provider would. */
const signToken = async (
  keys: CryptoKeyPair,
  kid: string,
  claims: Record<string, string>,
  issAud: { issuer?: string; audience?: string } = {},
): Promise<string> =>
  new SignJWT(claims)
    .setProtectedHeader({ alg: 'RS256', kid })
    .setIssuedAt()
    .setIssuer(issAud.issuer ?? 'https://idp.example')
    .setAudience(issAud.audience ?? 'api')
    .setExpirationTime('10m')
    .sign(keys.privateKey);

/** Minimal context double: the guard only reads the authorization header. */
const contextWith = (headers: Record<string, string>): Context => {
  const request = new Request('https://in-process.test/whoami', { headers });
  return {
    req: { header: (name: string) => headers[name.toLowerCase()] ?? request.headers.get(name) },
    set: () => undefined,
    get: () => undefined,
  } as unknown as Context;
};

beforeAll(async () => {
  database = await createTestDatabase({ adminUrl: requireTestDatabaseUrl() });
  connection = createConnection({ url: database.url, maxConnections: 2 });
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
  const service = new AuthService({
    hasher: new BunPasswordHasher(),
    users: new DatabaseUserProvider(connection),
    sessions: new PgSessionStore(connection),
    tokens: new PgTokenStore(connection),
    sessionTtlSeconds: defaultAuthConfig.session.ttlSeconds,
    tokenTtlSeconds: defaultAuthConfig.token.ttlSeconds,
  });
  const user = await service.register({ name: 'Jo', email: 'jo@example.test', password: PASSWORD });
  userId = user.id;
  currentKeys = await generateKeyPair('RS256', { extractable: true });
  rotatedKeys = await generateKeyPair('RS256', { extractable: true });
});

afterAll(async () => {
  await connection.close();
  await database.drop();
});

describe('JWT principal resolver (inline JWKS)', () => {
  const authConfig = {
    ...defaultAuthConfig,
    jwt: { ...defaultAuthConfig.jwt, issuer: 'https://idp.example', audience: 'api' },
  };
  /** The resolver takes the jwt *section*, matching what the actor resolver passes. */
  const config = authConfig.jwt;
  // Built lazily: `connection` only exists after beforeAll.
  const users = () => new DatabaseUserProvider(connection);

  test('a valid RS256 token with matching iss/aud/sub resolves the local user', async () => {
    const jwks = await jwksWith([{ kid: 'key-1', keys: currentKeys }]);
    const resolveJwt = createJwtPrincipalResolver({ config, keys: { jwks }, users: users() });
    const token = await signToken(currentKeys, 'key-1', { sub: userId, scope: 'notes.read' });

    const principal = await resolveJwt(`Bearer ${token}`);
    expect(principal?.id).toBe(userId);
    expect(principal?.via).toBe('jwt');
    expect(principal?.abilities).toEqual(['notes.read']);
  });

  test('wrong audience, wrong issuer, unsigned garbage and foreign subjects all stay anonymous', async () => {
    const jwks = await jwksWith([{ kid: 'key-1', keys: currentKeys }]);
    const resolveJwt = createJwtPrincipalResolver({ config, keys: { jwks }, users: users() });

    const wrongAud = await new SignJWT({})
      .setProtectedHeader({ alg: 'RS256', kid: 'key-1' })
      .setIssuer('https://idp.example')
      .setAudience('other-api')
      .setSubject(userId)
      .setExpirationTime('10m')
      .sign(currentKeys.privateKey);
    const wrongIss = await new SignJWT({})
      .setProtectedHeader({ alg: 'RS256', kid: 'key-1' })
      .setIssuer('https://evil.example')
      .setAudience('api')
      .setSubject(userId)
      .setExpirationTime('10m')
      .sign(currentKeys.privateKey);
    const foreign = await new SignJWT({})
      .setProtectedHeader({ alg: 'RS256', kid: 'key-1' })
      .setIssuer('https://idp.example')
      .setAudience('api')
      .setSubject('00000000-0000-4000-8000-000000000099')
      .setExpirationTime('10m')
      .sign(currentKeys.privateKey);

    expect(await resolveJwt(`Bearer ${wrongAud}`)).toBeNull();
    expect(await resolveJwt(`Bearer ${wrongIss}`)).toBeNull();
    expect(await resolveJwt(`Bearer ${foreign}`)).toBeNull();
    expect(await resolveJwt('Bearer not.a.jwt')).toBeNull();
    expect(await resolveJwt('Basic dXNlcjpwYXNz')).toBeNull();
    expect(await resolveJwt(undefined)).toBeNull();
  });

  test('tokens signed by an unknown key (wrong kid) are rejected', async () => {
    const jwks = await jwksWith([{ kid: 'key-1', keys: currentKeys }]);
    const resolveJwt = createJwtPrincipalResolver({ config, keys: { jwks }, users: users() });
    const forged = await signToken(rotatedKeys, 'key-1', { sub: userId });
    expect(await resolveJwt(`Bearer ${forged}`)).toBeNull();
  });

  test('a missing key source fails loudly instead of silently trusting nothing', () => {
    expect(() => createJwtPrincipalResolver({ config, keys: {}, users: users() })).toThrow(/key material/);
  });
});

describe('JWT guard through the actor resolver with a remote JWKS (rotation)', () => {
  let jwks: JSONWebKeySet;
  let server: ReturnType<typeof serveOnEphemeralPort>;
  let resolver: (c: Context) => Actor | Promise<Actor>;

  beforeAll(async () => {
    jwks = await jwksWith([{ kid: 'key-1', keys: currentKeys }]);
    server = serveOnEphemeralPort(
      () => new Response(JSON.stringify(jwks), { headers: { 'content-type': 'application/json' } }),
    );
    const config = {
      ...defaultAuthConfig,
      guards: ['jwt'] as const,
      jwt: { jwksUri: server.baseUrl, issuer: '', audience: '' },
    };
    resolver = createAuthActorResolver(
      { config, sessions: new PgSessionStore(connection), tokens: new PgTokenStore(connection) },
      {
        users: new DatabaseUserProvider(connection),
        jwtKeys: { cooldownDurationMs: 0 }, // rotation is exercised immediately
      },
    );
  });

  afterAll(async () => {
    await server.stop();
  });

  test('resolves a token against the remote JWKS', async () => {
    const token = await signToken(currentKeys, 'key-1', { sub: userId });
    const actor = await resolver(contextWith({ authorization: `Bearer ${token}` }));
    expect(actor.id).toBe(userId);
  });

  test('rotation: after the JWKS publishes a new key, its tokens verify and old ones keep working', async () => {
    jwks = await jwksWith([
      { kid: 'key-1', keys: currentKeys },
      { kid: 'key-2', keys: rotatedKeys },
    ]);
    const newToken = await signToken(rotatedKeys, 'key-2', { sub: userId });
    const actor = await resolver(contextWith({ authorization: `Bearer ${newToken}` }));
    expect(actor.id).toBe(userId);
  });
});
