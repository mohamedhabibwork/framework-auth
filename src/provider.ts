import { RATE_LIMITER } from '@framework/cache';
import { type Application, defineProvider, type ServiceProvider } from '@framework/core';
import { DATABASE, type DatabaseConnection } from '@framework/database';
import type { ActorResolver } from '@framework/http';
import { PgAccountTokenStore } from './account-token-store';
import { AuthService } from './auth-service';
import {
  ACCOUNT_TOKEN_STORE,
  AUTH_RATE_LIMITER,
  AUTH_SERVICE,
  PASSWORD_HASHER,
  RECOVERY_CODE_STORE,
  SESSION_STORE,
  TOKEN_STORE,
  USER_PROVIDER,
} from './constants-tokens';
import { createAuthActorResolver } from './guard';
import { BunPasswordHasher } from './hashing';
import type { JwtAlgorithm, JwtKeySource } from './jwt-guard';
import { PgSessionStore } from './session-store';
import { PgTokenStore } from './token-store';
import { PgRecoveryCodeStore } from './totp-store';
import type { AuthConfig, AuthProviderOptions } from './types';
import { DatabaseUserProvider } from './user-provider';

export {
  ACCOUNT_TOKEN_STORE,
  AUTH_RATE_LIMITER,
  AUTH_SERVICE,
  PASSWORD_HASHER,
  RECOVERY_CODE_STORE,
  SESSION_STORE,
  TOKEN_STORE,
  USER_PROVIDER,
};

/**
 * Registers the auth stack as singletons over the database connection:
 * hasher, user provider, session/token stores, the single-use account-token
 * and recovery-code stores, and the `AuthService`. Applications add it to
 * their provider list after the database provider — and after the cache
 * provider when login rate limiting is wanted: the provider then publishes
 * the application's `RATE_LIMITER` as `AUTH_RATE_LIMITER` for the
 * login-route wiring. When the cache limiter is not bound, or
 * `auth.rateLimit.enabled` is false, limiting stays off — an explicit
 * configuration choice, never a silent bypass.
 *
 * Email verification, password recovery and two-step login are always
 * available: their tables ship with the auth migration and the stores bind
 * unconditionally. Actual email delivery stays an application concern via
 * `AuthService`'s `notifiers` hooks (see `@framework/notifications`).
 */
export function createAuthProvider<TConfig extends { readonly auth: AuthConfig }>(
  options: AuthProviderOptions = {},
): ServiceProvider<TConfig> {
  return defineProvider<TConfig>({
    name: 'auth',
    dependsOn: ['database'],
    register({ container, config }) {
      const auth = config.auth;
      const connection = options.connection ?? DATABASE;
      container.singleton(PASSWORD_HASHER, () => new BunPasswordHasher());
      container.singleton(USER_PROVIDER, (r) => new DatabaseUserProvider(r.resolve<DatabaseConnection>(connection)));
      container.singleton(SESSION_STORE, (r) => new PgSessionStore(r.resolve<DatabaseConnection>(connection)));
      container.singleton(TOKEN_STORE, (r) => new PgTokenStore(r.resolve<DatabaseConnection>(connection)));
      container.singleton(
        ACCOUNT_TOKEN_STORE,
        (r) => new PgAccountTokenStore(r.resolve<DatabaseConnection>(connection)),
      );
      container.singleton(
        RECOVERY_CODE_STORE,
        (r) => new PgRecoveryCodeStore(r.resolve<DatabaseConnection>(connection)),
      );
      container.singleton(
        AUTH_SERVICE,
        (r) =>
          new AuthService({
            hasher: r.resolve(PASSWORD_HASHER),
            users: r.resolve(USER_PROVIDER),
            sessions: r.resolve(SESSION_STORE),
            tokens: r.resolve(TOKEN_STORE),
            accountTokens: r.resolve(ACCOUNT_TOKEN_STORE),
            recoveryCodes: r.resolve(RECOVERY_CODE_STORE),
            notifiers: options.notifiers,
            sessionTtlSeconds: auth.session.ttlSeconds,
            tokenTtlSeconds: auth.token.ttlSeconds,
            verificationTtlSeconds: auth.verification.ttlSeconds,
            resetTtlSeconds: auth.passwordReset.ttlSeconds,
            twoStepChallengeTtlSeconds: auth.twoStep.challengeTtlSeconds,
            totpIssuer: auth.twoStep.issuer,
          }),
      );
      if (auth.rateLimit.enabled && container.has(RATE_LIMITER)) {
        container.value(AUTH_RATE_LIMITER, container.resolve(RATE_LIMITER));
      }
    },
  });
}

/**
 * The `resolveActor` implementation for `createHttpKernel`. Dependencies are
 * resolved from the container on first use (i.e. after boot), so composing
 * the HTTP application before boot stays legal. The same JWT options given
 * here flow into the guard when `auth.guards` includes `'jwt'`.
 */
export function authActorResolver<TConfig extends { readonly auth: AuthConfig }>(
  application: Application<TConfig>,
  options: Pick<AuthProviderOptions, 'jwt'> = {},
): ActorResolver {
  let resolver: ActorResolver | undefined;
  return (c) => {
    resolver ??= createAuthActorResolver(
      {
        config: application.config.auth,
        sessions: application.container.resolve(SESSION_STORE),
        tokens: application.container.resolve(TOKEN_STORE),
      },
      {
        users: application.container.resolve(USER_PROVIDER),
        jwtKeys: options.jwt?.keys,
        jwtAlgorithms: options.jwt?.algorithms,
      },
    );
    return resolver(c);
  };
}

/** JWT guard options accepted by `createAuthProvider` and `authActorResolver`. */
export interface JwtProviderOptions {
  /** Inline key set (alternative to `auth.jwt.jwksUri`). */
  readonly keys?: JwtKeySource;
  /** Verify allowlist; defaults to RS256/ES256/PS256/EdDSA. */
  readonly algorithms?: readonly JwtAlgorithm[];
}
