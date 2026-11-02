/**
 * Every interface and type alias of `@framework/auth` in one place.
 * Runtime values (classes, tokens, functions) live in their own modules.
 */

import type { RateLimiter } from '@framework/cache';
import type { Register } from '@framework/core';
import type { DatabaseConnection, SelectOf } from '@framework/database';
import type { FrameworkEnv } from '@framework/http';
import type { AnyPgColumn, PgTable } from 'drizzle-orm/pg-core';
import type { Context } from 'hono';

// -- Configuration -----------------------------------------------------------

export type BuiltInAuthGuardName = 'session' | 'api-token' | 'jwt';

/** Built-in guards plus any the application declares as `Register.guards`. */
export type AuthGuardName =
  | BuiltInAuthGuardName
  | (Register extends { readonly guards: infer TGuards extends string } ? TGuards : never);

/** Validated `auth` section of the application configuration. */
export interface AuthConfig {
  /** Guards consulted in order; the first match wins. */
  readonly guards: readonly AuthGuardName[];
  readonly session: {
    /** Cookie name carrying the opaque session token. */
    readonly cookie: string;
    /** Sliding lifetime: every authenticated use extends to a full window. */
    readonly ttlSeconds: number;
    /** Emit the Secure cookie attribute (enable in production). */
    readonly secure: boolean;
  };
  readonly token: {
    /** Default lifetime after issuance; null means tokens do not expire. */
    readonly ttlSeconds: number | null;
  };
  readonly rateLimit: {
    /** Master switch for login throttling; disabling is an explicit choice, not a silent bypass. */
    readonly enabled: boolean;
    /** Failed logins allowed per email inside one window; the next attempt is answered 429. */
    readonly maxAttempts: number;
    /** Fixed-window length in seconds; the failure counter expires with it. */
    readonly windowSeconds: number;
  };
  /** Email-verification token lifetime. */
  readonly verification: { readonly ttlSeconds: number };
  /** Password-reset token lifetime. */
  readonly passwordReset: { readonly ttlSeconds: number };
  /** Two-step login (TOTP): challenge lifetime and provisioning issuer. */
  readonly twoStep: { readonly challengeTtlSeconds: number; readonly issuer: string };
  /**
   * JWT guard validation. Key material comes from `createAuthProvider({ jwt
   * })` (inline JWKS) or `jwksUri` (remote, rotation-aware); issuer/audience
   * are checked when set. The `sub` claim must match a local user id.
   */
  readonly jwt: {
    readonly jwksUri: string;
    readonly issuer: string;
    readonly audience: string;
  };
}

// -- Records -----------------------------------------------------------------

/** Row of the framework-owned `users` table. */
export type UserRecord = SelectOf<typeof import('./schema/tables').users>;

/** What auth reads from a user row. Applications may add columns, not remove these. */
export interface AuthUser {
  readonly id: string;
  readonly name: string;
  readonly email: string;
  readonly emailVerifiedAt: string | null;
  readonly passwordHash: string;
  readonly totpSecret: string | null;
  readonly createdAt: string;
  readonly updatedAt: string;
}

/**
 * The application's user row when `Register.user` is declared, else
 * {@link UserRecord}. A declared type missing an {@link AuthUser} column is
 * ignored, so declare it as `typeof table.$inferSelect` over `authUserColumns()`.
 */
export type RegisteredAuthUser = Register extends { readonly user: infer TUser extends AuthUser } ? TUser : UserRecord;

/** A Drizzle table whose rows are `TUser`, declared with `authUserColumns()`. */
export type AuthUsersTable<TUser extends AuthUser = RegisteredAuthUser> = PgTable & {
  readonly $inferSelect: TUser;
  readonly id: AnyPgColumn;
  readonly email: AnyPgColumn;
};

/** Row of the framework-owned `sessions` table (never carries the token hash). */
export type SessionRecord = Omit<SelectOf<typeof import('./schema/tables').sessions>, 'tokenHash'>;

/** Row of the framework-owned `api_tokens` table (never carries the token hash). */
export type ApiTokenRecord = Omit<SelectOf<typeof import('./schema/tables').apiTokens>, 'tokenHash'>;

/** Row of the framework-owned `account_tokens` table (never carries the token hash). */
export type AccountTokenRecord = Omit<SelectOf<typeof import('./schema/tables').accountTokens>, 'tokenHash'>;

/** Row of the framework-owned `totp_recovery_codes` table (never carries the hash). */
export type TotpRecoveryCodeRecord = Omit<SelectOf<typeof import('./schema/tables').totpRecoveryCodes>, 'codeHash'>;

/** What a single-use account token is for. */
export type AccountTokenPurpose = 'email-verification' | 'password-reset' | 'two-step';

/** A session row joined with its user, as returned by `SessionStore.find`. */
export interface ResolvedSession<TUser extends AuthUser = RegisteredAuthUser> {
  readonly session: SessionRecord;
  readonly user: TUser;
}

// -- Principal ----------------------------------------------------------------

/**
 * Authenticated identity installed on the request context. Structurally
 * satisfies `@framework/http`'s `PrincipalLike`. Session principals hold
 * `['*']` abilities; API token principals carry their declared abilities.
 */
export interface Principal<TUser extends AuthUser = RegisteredAuthUser> {
  readonly id: string;
  readonly via: AuthGuardName;
  readonly abilities: readonly string[];
  readonly user: TUser;
  /** Present when `via` is `session`. */
  readonly sessionId?: string;
  /** Present when `via` is `api-token`. */
  readonly tokenId?: string;
}

// -- Contracts ----------------------------------------------------------------

/** Authenticates a request; null passes to the next configured guard. */
export type AuthGuard<TUser extends AuthUser = RegisteredAuthUser> = (
  c: Context<FrameworkEnv>,
) => Promise<Principal<TUser> | null>;

/** Password hashing abstraction (argon2id in production, fakes in tests). */
export interface PasswordHasher {
  hash(plain: string): Promise<string>;
  verify(plain: string, hash: string): Promise<boolean>;
}

/**
 * Loads and creates principals. Applications with a custom user store swap
 * this out (`create` backs the default registration route and must persist
 * the already-hashed password).
 */
export interface UserProvider<TUser extends AuthUser = RegisteredAuthUser> {
  findById(id: string): Promise<TUser | null>;
  findByEmail(email: string): Promise<TUser | null>;
  create(input: { readonly name: string; readonly email: string; readonly passwordHash: string }): Promise<TUser>;
  /** Persists a new password hash (password recovery). */
  updatePasswordHash(id: string, passwordHash: string): Promise<void>;
  /** Stamps `email_verified_at` (email verification). */
  markEmailVerified(id: string): Promise<void>;
  /** Writes the base32 TOTP secret (null disables two-step login). */
  setTotpSecret(id: string, secret: string | null): Promise<void>;
}

export interface IssuedSession {
  readonly session: SessionRecord;
  /** Plaintext cookie value; shown once, only the hash is persisted. */
  readonly token: string;
}

/**
 * Server-side session state: creation, resolution (expiry-filtered, user
 * joined), rotation on login, revocation and pruning.
 */
export interface SessionStore<TUser extends AuthUser = RegisteredAuthUser> {
  create(userId: string, ttlSeconds: number): Promise<IssuedSession>;
  find(token: string): Promise<ResolvedSession<TUser> | null>;
  /** Invalidates `currentToken` and creates a fresh session in one transaction. */
  rotate(currentToken: string, ttlSeconds: number): Promise<IssuedSession | null>;
  revoke(token: string): Promise<boolean>;
  revokeById(id: string): Promise<boolean>;
  revokeAllForUser(userId: string): Promise<number>;
  /** Sliding renewal: extends expiry to a fresh window and marks last use. */
  touch(id: string, ttlSeconds: number): Promise<void>;
  /** Removes expired sessions; returns the number deleted. */
  prune(now?: Date): Promise<number>;
  /** Counts expired sessions without deleting them (dry-run reporting). */
  countExpired(now?: Date): Promise<number>;
}

export interface IssuedToken {
  readonly token: ApiTokenRecord;
  /** Plaintext `prefix…` value; shown once, only the hash is persisted. */
  readonly plaintext: string;
}

/**
 * Personal API tokens: hashed at rest, ability-scoped, expirable and
 * revocable. `find` only resolves unrevoked, unexpired tokens.
 */
export interface ApiTokenStore<TUser extends AuthUser = RegisteredAuthUser> {
  issue(userId: string, name: string, abilities: readonly string[], ttlSeconds: number | null): Promise<IssuedToken>;
  find(plaintext: string): Promise<{ readonly token: ApiTokenRecord; readonly user: TUser } | null>;
  listForUser(userId: string): Promise<readonly ApiTokenRecord[]>;
  /** Revokes only when the token belongs to `userId`. */
  revoke(id: string, userId: string): Promise<boolean>;
  revokeAllForUser(userId: string): Promise<number>;
  touch(id: string): Promise<void>;
}

export interface RegisterInput {
  readonly name: string;
  readonly email: string;
  readonly password: string;
}

export interface AttemptResult<TUser extends AuthUser = RegisteredAuthUser> {
  readonly user: TUser;
  readonly sessionId: string;
  readonly sessionToken: string;
}

/** First factor outcome of `AuthService.startLogin`. */
export type LoginStart<TUser extends AuthUser = RegisteredAuthUser> =
  | ({ readonly kind: 'session' } & AttemptResult<TUser>)
  | {
      readonly kind: 'two-step';
      readonly user: TUser /** Single-use, short-lived challenge token. */;
      readonly challenge: string;
    };

export interface IssueTokenInput {
  readonly name: string;
  readonly abilities?: readonly string[];
  /** Overrides the configured default lifetime for this token. */
  readonly ttlSeconds?: number | null;
}

/**
 * Single-use account tokens for email verification, password recovery and
 * the two-step-login challenge: hashed at rest, expiring, consumed
 * atomically (see `PgAccountTokenStore`).
 */
export interface AccountTokenStore {
  /** Issues a fresh token; returns the plaintext (delivered exactly once). */
  issue(userId: string, purpose: AccountTokenPurpose, ttlSeconds: number): Promise<string>;
  /** Atomically consumes a valid token; resolves the owning user id or null. */
  consume(plaintext: string, purpose: AccountTokenPurpose): Promise<string | null>;
}

/**
 * One-time TOTP recovery codes: hashed at rest, single-use under concurrent
 * replay (see `PgRecoveryCodeStore`).
 */
export interface RecoveryCodeStore {
  replaceAll(userId: string, codes: readonly string[]): Promise<void>;
  consume(userId: string, code: string): Promise<boolean>;
  countUnused(userId: string): Promise<number>;
  deleteAll(userId: string): Promise<void>;
}

/** Delivery hooks the application wires to `@framework/notifications`. */
export interface AuthNotifiers<TUser extends AuthUser = RegisteredAuthUser> {
  /** Delivers the email-verification link/token (queued by the app). */
  readonly emailVerification?: (user: TUser, token: string) => Promise<void>;
  /** Delivers the password-reset link/token (queued by the app). */
  readonly passwordReset?: (user: TUser, token: string) => Promise<void>;
}

/**
 * The `AuthService` class (see ./auth-service) is both implementation and
 * public contract; its dependencies are defined here for tests and fakes.
 */
export interface AuthServiceDeps<TUser extends AuthUser = RegisteredAuthUser> {
  readonly hasher: PasswordHasher;
  readonly users: UserProvider<TUser>;
  readonly sessions: SessionStore<TUser>;
  readonly tokens: ApiTokenStore<TUser>;
  /** Single-use verification/recovery/two-step tokens (optional until wired). */
  readonly accountTokens?: AccountTokenStore;
  /** One-time TOTP recovery codes (optional until wired). */
  readonly recoveryCodes?: RecoveryCodeStore;
  /** App delivery hooks for verification/recovery emails (optional). */
  readonly notifiers?: AuthNotifiers<TUser>;
  readonly sessionTtlSeconds: number;
  readonly tokenTtlSeconds: number | null;
  /** Lifetime of email-verification tokens. Default 3600. */
  readonly verificationTtlSeconds?: number;
  /** Lifetime of password-reset tokens. Default 3600. */
  readonly resetTtlSeconds?: number;
  /** Lifetime of the two-step login challenge. Default 300. */
  readonly twoStepChallengeTtlSeconds?: number;
  /** Issuer shown in `otpauth://` provisioning URIs. Default 'Framework'. */
  readonly totpIssuer?: string;
}

/** Options for `createAuthProvider` (see provider.ts). */
export interface AuthProviderOptions<TUser extends AuthUser = RegisteredAuthUser> {
  /** Connection token to build stores on; defaults to `DATABASE`. */
  readonly connection?: Token<DatabaseConnection>;
  /**
   * The application's users table when it adds columns to the framework's.
   * It must be named `users`, because the auth tables' foreign keys point there.
   */
  readonly usersTable?: AuthUsersTable<TUser>;
  /** Replaces the default user store (needed when `create` must set extra required columns). */
  readonly userProvider?: UserProvider<TUser>;
  /** Replaces the default argon2id hasher. */
  readonly hasher?: PasswordHasher;
  /** Replaces the PostgreSQL session or API token store. */
  readonly stores?: {
    readonly sessions?: SessionStore<TUser>;
    readonly tokens?: ApiTokenStore<TUser>;
  };
  /** Guards beyond the built-in ones, by the name `auth.guards` lists them under. */
  readonly guards?: Readonly<Record<string, AuthGuard<TUser>>>;
  /** Delivery hooks handed to the `AuthService` (queued by the app via `@framework/notifications`). */
  readonly notifiers?: AuthNotifiers<TUser>;
  /**
   * JWT guard key material and algorithm allowlist, used when `auth.guards`
   * includes `'jwt'`. Without it (and without `auth.jwt.jwksUri`) the guard
   * fails loudly on first use.
   */
  readonly jwt?: {
    readonly keys?: import('./jwt-guard').JwtKeySource;
    readonly algorithms?: readonly import('./jwt-guard').JwtAlgorithm[];
  };
}

/** Options for `createAuthActorResolver` (see guard.ts). */
export interface AuthGuardDeps<TUser extends AuthUser = RegisteredAuthUser> {
  readonly config: AuthConfig;
  readonly sessions: SessionStore<TUser>;
  readonly tokens: ApiTokenStore<TUser>;
}

import type { Token } from '@framework/core';
import type { MiddlewareHandler } from 'hono';
import type { AuthService } from './auth-service';

export type { AuthService };

/** Options for `defineAuthRoutes` (see routes.ts). */
export interface AuthRoutesDeps {
  /** DI token of the bound `AuthService` (resolved from the request scope). */
  readonly service: Token<AuthService>;
  readonly session: Pick<AuthConfig['session'], 'cookie' | 'ttlSeconds' | 'secure'>;
  /**
   * Login rate-limit knobs (`auth.rateLimit`). Optional for backward
   * compatibility; when omitted the resolved defaults apply (enabled, 5
   * attempts, 60s window).
   */
  readonly rateLimit?: AuthConfig['rateLimit'];
  /**
   * Bound `RateLimiter` from `@framework/cache` (the auth provider publishes
   * the application's limiter as `AUTH_RATE_LIMITER` when `RATE_LIMITER` is
   * bound). Optional for backward compatibility: when absent — or when
   * `rateLimit.enabled` is false — the login endpoint is unlimited. That is an
   * explicit configuration choice, never a silent bypass.
   */
  readonly rateLimiter?: RateLimiter;
  /**
   * Native Hono CSRF middleware guarding the cookie flows. Applications with
   * browser clients pass `csrf({ origin: [...corsOrigins] })`; the default
   * checks same-origin only. JSON clients are unaffected (Hono only
   * challenges form-encoded content types).
   */
  readonly csrf?: MiddlewareHandler;
}
