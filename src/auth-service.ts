import { generateRecoveryCodes, generateTotpSecret, normalizeTotpCode, totpUri, verifyTotp } from './totp';
import type {
  AccountTokenStore,
  ApiTokenRecord,
  AttemptResult,
  AuthNotifiers,
  AuthServiceDeps,
  IssuedToken,
  IssueTokenInput,
  LoginStart,
  PasswordHasher,
  Principal,
  RegisterInput,
  UserRecord,
} from './types';

/** First-attempt dummy hash so unknown emails cost the same as known ones. */
let dummyHash: Promise<string> | undefined;
const timingDummyVerify = (hasher: PasswordHasher, password: string): Promise<boolean> => {
  dummyHash ??= hasher.hash('timing-equalization-placeholder');
  return dummyHash.then((hash) => hasher.verify(password, hash));
};

/**
 * Authentication operations over the framework stores. `attempt` rotates
 * sessions on every login (a stolen pre-login cookie dies at login).
 *
 * Email verification, password recovery and two-step login build on
 * single-use hashed account tokens and require the optional `accountTokens`
 * dep — the methods fail fast with a clear message when the wiring is
 * missing, never silently.
 */
export class AuthService {
  constructor(private readonly deps: AuthServiceDeps) {}

  #accountTokens(): AccountTokenStore {
    if (!this.deps.accountTokens) {
      throw new Error(
        'AuthService: accountTokens dep is not wired; bind PgAccountTokenStore in the auth provider to use verification/recovery/two-step flows',
      );
    }
    return this.deps.accountTokens;
  }

  async register(input: RegisterInput): Promise<UserRecord> {
    const passwordHash = await this.deps.hasher.hash(input.password);
    // Insert directly (provider lookups are read contracts); a duplicate
    // email raises SQLSTATE 23505, which the error handler maps to 409.
    return this.deps.users.create({ ...input, passwordHash });
  }

  async attempt(email: string, password: string): Promise<AttemptResult | null> {
    const start = await this.startLogin(email, password);
    if (start?.kind !== 'session') return null;
    return { user: start.user, sessionId: start.sessionId, sessionToken: start.sessionToken };
  }

  /**
   * Credential check plus second-factor fork: users with TOTP enabled get a
   * single-use short-lived challenge instead of a session — no session
   * exists until `completeTwoStep` verifies the code. Unknown or wrong
   * credentials resolve null after the same dummy-verify work, so response
   * timing does not reveal which failed.
   */
  async startLogin(email: string, password: string): Promise<LoginStart | null> {
    const user = await this.deps.users.findByEmail(email);
    const ok = user
      ? await this.deps.hasher.verify(password, user.passwordHash)
      : await timingDummyVerify(this.deps.hasher, password);
    if (!user || !ok) return null;
    if (user.totpSecret) {
      const challenge = await this.#accountTokens().issue(
        user.id,
        'two-step',
        this.deps.twoStepChallengeTtlSeconds ?? 300,
      );
      return { kind: 'two-step', user, challenge };
    }
    const issued = await this.deps.sessions.create(user.id, this.deps.sessionTtlSeconds);
    return { kind: 'session', user, sessionId: issued.session.id, sessionToken: issued.token };
  }

  /**
   * Second login factor: consumes the challenge up front (one verification
   * attempt per login, so code guessing is bounded by the throttled login
   * rate), then accepts a TOTP code or a one-time recovery code.
   */
  async completeTwoStep(challenge: string, code: string): Promise<AttemptResult | null> {
    const userId = await this.#accountTokens().consume(challenge, 'two-step');
    if (!userId) return null;
    const user = await this.deps.users.findById(userId);
    if (!user?.totpSecret) return null;
    const normalized = normalizeTotpCode(code);
    const ok = verifyTotp(user.totpSecret, normalized) || (await this.consumeRecoveryCode(user.id, code.trim()));
    if (!ok) return null;
    const issued = await this.deps.sessions.create(user.id, this.deps.sessionTtlSeconds);
    return { user, sessionId: issued.session.id, sessionToken: issued.token };
  }

  async issueToken(user: Pick<UserRecord, 'id'>, input: IssueTokenInput): Promise<IssuedToken> {
    return this.deps.tokens.issue(
      user.id,
      input.name,
      input.abilities ?? ['*'],
      input.ttlSeconds === undefined ? this.deps.tokenTtlSeconds : input.ttlSeconds,
    );
  }

  async startSession(userId: string): Promise<{ sessionId: string; sessionToken: string }> {
    const issued = await this.deps.sessions.create(userId, this.deps.sessionTtlSeconds);
    return { sessionId: issued.session.id, sessionToken: issued.token };
  }

  async listTokens(userId: string): Promise<readonly ApiTokenRecord[]> {
    return this.deps.tokens.listForUser(userId);
  }

  async revokeToken(id: string, userId: string): Promise<boolean> {
    return this.deps.tokens.revoke(id, userId);
  }

  async logout(principal: Principal): Promise<boolean> {
    if (principal.via === 'session' && principal.sessionId) {
      return this.deps.sessions.revokeById(principal.sessionId);
    }
    if (principal.via === 'api-token' && principal.tokenId) {
      return this.deps.tokens.revoke(principal.tokenId, principal.id);
    }
    return false;
  }

  async revokeAllSessions(userId: string): Promise<number> {
    return this.deps.sessions.revokeAllForUser(userId);
  }

  async revokeAllTokens(userId: string): Promise<number> {
    return this.deps.tokens.revokeAllForUser(userId);
  }

  // -- Email verification ------------------------------------------------------

  /**
   * Issues the single-use verification token and hands it to the app's
   * `notifiers.emailVerification` hook when present. Returns the plaintext
   * either way (custom delivery, tests); never log or return it in a
   * response.
   */
  async requestEmailVerification(user: UserRecord): Promise<string> {
    const token = await this.#accountTokens().issue(
      user.id,
      'email-verification',
      this.deps.verificationTtlSeconds ?? 3600,
    );
    await this.deps.notifiers?.emailVerification?.(user, token);
    return token;
  }

  /** Consumes the token and stamps `email_verified_at`; null when invalid/used/expired. */
  async verifyEmail(token: string): Promise<UserRecord | null> {
    const userId = await this.#accountTokens().consume(token, 'email-verification');
    if (!userId) return null;
    await this.deps.users.markEmailVerified(userId);
    return this.deps.users.findById(userId);
  }

  // -- Password recovery -------------------------------------------------------

  /**
   * Issues the recovery token for `email` when the account exists and hands
   * it to the app's `notifiers.passwordReset` hook. Unknown emails return
   * normally with no work done beyond the lookup — the route answers an
   * identical 202 either way, so the endpoint never enumerates users.
   */
  async requestPasswordReset(email: string): Promise<void> {
    const user = await this.deps.users.findByEmail(email.trim().toLowerCase());
    if (!user) return;
    const token = await this.#accountTokens().issue(user.id, 'password-reset', this.deps.resetTtlSeconds ?? 3600);
    await this.deps.notifiers?.passwordReset?.(user, token);
  }

  /**
   * Consumes the recovery token, stores the fresh hash and revokes every
   * session and API token — a password reset is a full credential rotation.
   * False for unknown/expired/used tokens (indistinguishable responses).
   */
  async resetPassword(token: string, newPassword: string): Promise<boolean> {
    const userId = await this.#accountTokens().consume(token, 'password-reset');
    if (!userId) return false;
    const passwordHash = await this.deps.hasher.hash(newPassword);
    await this.deps.users.updatePasswordHash(userId, passwordHash);
    await this.deps.sessions.revokeAllForUser(userId);
    await this.deps.tokens.revokeAllForUser(userId);
    return true;
  }

  // -- Two-step (TOTP) lifecycle ----------------------------------------------

  /**
   * Generates (and stores) a pending TOTP secret; enrollment completes only
   * when `enableTotp` verifies the first code, so a lost QR code never
   * locks the account.
   */
  async startTotpEnrollment(user: UserRecord): Promise<{ readonly secret: string; readonly uri: string }> {
    const secret = generateTotpSecret();
    await this.deps.users.setTotpSecret(user.id, secret);
    return { secret, uri: totpUri(secret, user.email, this.deps.totpIssuer ?? 'Framework') };
  }

  /**
   * Activates two-step login: verifies `code` against the pending secret,
   * then issues a fresh set of one-time recovery codes (returned in
   * plaintext exactly once). Null for a wrong code or no pending secret.
   */
  async enableTotp(userId: string, code: string): Promise<readonly string[] | null> {
    const user = await this.deps.users.findById(userId);
    if (!user?.totpSecret || !verifyTotp(user.totpSecret, normalizeTotpCode(code))) return null;
    const codes = generateRecoveryCodes();
    await this.deps.recoveryCodes?.replaceAll(userId, codes);
    return codes;
  }

  /**
   * Disables two-step login after verifying `code` (TOTP or a recovery
   * code): clears the secret and deletes the remaining codes. False when the
   * code does not verify or two-step is not enabled.
   */
  async disableTotp(userId: string, code: string): Promise<boolean> {
    const user = await this.deps.users.findById(userId);
    if (!user?.totpSecret) return false;
    const normalized = normalizeTotpCode(code);
    if (!verifyTotp(user.totpSecret, normalized) && !(await this.consumeRecoveryCode(userId, code.trim()))) {
      return false;
    }
    await this.deps.users.setTotpSecret(userId, null);
    await this.deps.recoveryCodes?.deleteAll(userId);
    return true;
  }

  /** Atomically consumes one recovery code; false when unknown or already used. */
  async consumeRecoveryCode(userId: string, code: string): Promise<boolean> {
    if (!code) return false;
    return (await this.deps.recoveryCodes?.consume(userId, code)) ?? false;
  }

  /** Unused recovery codes remaining for the user. */
  async unusedRecoveryCodes(userId: string): Promise<number> {
    return (await this.deps.recoveryCodes?.countUnused(userId)) ?? 0;
  }
}

/** Notifier hooks surfaced for composition code that builds AuthService deps. */
export type { AuthNotifiers };
