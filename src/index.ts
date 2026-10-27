// Public API of @framework/auth.
// Convention: every interface/type lives in `./types`, every constant in
// `./constants`; runtime values (classes, tokens, functions) stay in their modules.
export { generateAccountToken, hashAccountToken, PgAccountTokenStore } from './account-token-store';
export { AuthService } from './auth-service';
export {
  ACCOUNT_TOKEN_STORE,
  AUTH_RATE_LIMITER,
  AUTH_SERVICE,
  authConfigSchema,
  defaultAuthConfig,
  PASSWORD_HASHER,
  RECOVERY_CODE_STORE,
  SESSION_STORE,
  SESSION_TOUCH_INTERVAL_MS,
  TOKEN_STORE,
  USER_PROVIDER,
} from './constants';
export { type AuthGuardExtras, createAuthActorResolver } from './guard';
export { BunPasswordHasher } from './hashing';
export { createJwtPrincipalResolver, type JwtAlgorithm, type JwtKeySource } from './jwt-guard';
export { requireAbility, requireAuth, verified } from './middleware';
export { authPrincipal, hasAbility } from './principals';
export { authActorResolver, createAuthProvider, type JwtProviderOptions } from './provider';
export {
  createTokenSchema,
  defineAuthRoutes,
  forgotPasswordSchema,
  loginSchema,
  publicUser,
  registerSchema,
  resetPasswordSchema,
  totpCodeSchema,
  twoStepSchema,
  verifyEmailSchema,
} from './routes';
export type { AccountTokenRow, ApiTokenRow, SessionRow, TotpRecoveryCodeRow, UserRow } from './schema/tables';
export { accountTokens, sessions, totpRecoveryCodes, users } from './schema/tables';
export { generateSessionToken, hashToken, PgSessionStore } from './session-store';
export { generateApiToken, hashApiToken, PgTokenStore } from './token-store';
export {
  base32Decode,
  base32Encode,
  generateRecoveryCode,
  generateRecoveryCodes,
  generateTotpSecret,
  hotp,
  normalizeTotpCode,
  totpUri,
  verifyTotp,
} from './totp';
export { hashRecoveryCode, PgRecoveryCodeStore } from './totp-store';
// Grouped conventions: every type in ./types, every constant in ./constants.
export type {
  AccountTokenPurpose,
  AccountTokenRecord,
  AccountTokenStore,
  ApiTokenRecord,
  ApiTokenStore,
  AttemptResult,
  AuthConfig,
  AuthGuardDeps,
  AuthGuardName,
  AuthNotifiers,
  AuthProviderOptions,
  AuthRoutesDeps,
  AuthServiceDeps,
  IssuedSession,
  IssuedToken,
  IssueTokenInput,
  LoginStart,
  PasswordHasher,
  Principal,
  RecoveryCodeStore,
  RegisterInput,
  ResolvedSession,
  SessionRecord,
  SessionStore,
  TotpRecoveryCodeRecord,
  UserProvider,
  UserRecord,
} from './types';
export { DatabaseUserProvider } from './user-provider';
