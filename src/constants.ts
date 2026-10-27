/** Constants of `@framework/auth`: tokens and fixed defaults. */

export { authConfigSchema, defaultAuthConfig } from './config-schema';
export {
  ACCOUNT_TOKEN_STORE,
  AUTH_RATE_LIMITER,
  AUTH_SERVICE,
  PASSWORD_HASHER,
  RECOVERY_CODE_STORE,
  SESSION_STORE,
  TOKEN_STORE,
  USER_PROVIDER,
} from './constants-tokens';

/** Authenticated requests renew sessions at most this often (write throttle). */
export const SESSION_TOUCH_INTERVAL_MS = 60_000;
/** Bytes of entropy in an opaque session/token value (256-bit). */
export const SECRET_BYTES = 32;
