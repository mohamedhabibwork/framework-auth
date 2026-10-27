import type { RateLimiter } from '@framework/cache';
import { token } from '@framework/core';
import type {
  AccountTokenStore,
  ApiTokenStore,
  AuthService,
  PasswordHasher,
  RecoveryCodeStore,
  SessionStore,
  UserProvider,
} from './types';

export const PASSWORD_HASHER = token<PasswordHasher>('auth.password-hasher');
export const USER_PROVIDER = token<UserProvider>('auth.user-provider');
export const SESSION_STORE = token<SessionStore>('auth.session-store');
export const TOKEN_STORE = token<ApiTokenStore>('auth.token-store');
/** Single-use tokens for email verification, password reset and two-step challenges. */
export const ACCOUNT_TOKEN_STORE = token<AccountTokenStore>('auth.account-token-store');
/** One-time TOTP recovery codes. */
export const RECOVERY_CODE_STORE = token<RecoveryCodeStore>('auth.recovery-code-store');
export const AUTH_SERVICE = token<AuthService>('auth.service');
/**
 * Login rate limiter, published by `createAuthProvider` only when the
 * application bound `@framework/cache`'s `RATE_LIMITER` and
 * `auth.rateLimit.enabled`. Wiring it into `defineAuthRoutes` enables the
 * 429 + Retry-After login throttle.
 */
export const AUTH_RATE_LIMITER = token<RateLimiter>('auth.rate-limiter');
