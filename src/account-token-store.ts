import { createHash, randomBytes } from 'node:crypto';
import type { DatabaseConnection } from '@framework/database';
import { and, eq, gt, isNull, sql } from 'drizzle-orm';
import { accountTokens } from './schema/tables';
import type { AccountTokenPurpose, AccountTokenRecord } from './types';

/** 256 bits of entropy (hex) — unguessable, URL-safe. */
export const generateAccountToken = (): string => randomBytes(32).toString('hex');

/** Same hash-at-rest discipline as sessions and API tokens. */
export const hashAccountToken = (value: string): string => createHash('sha256').update(value).digest('hex');

const tokenColumns = {
  id: accountTokens.id,
  userId: accountTokens.userId,
  purpose: accountTokens.purpose,
  expiresAt: accountTokens.expiresAt,
  consumedAt: accountTokens.consumedAt,
  createdAt: accountTokens.createdAt,
  updatedAt: accountTokens.updatedAt,
} as const;

/**
 * PostgreSQL-backed single-use account tokens. Issue supersedes any
 * outstanding token of the same purpose for the user (older ones are
 * consumed), so exactly one live link per mailbox exists at a time.
 * `consume` flips `consumedAt` in SQL under `IS NULL` + expiry guards: two
 * racing requests can never both succeed.
 */
export class PgAccountTokenStore {
  constructor(private readonly connection: DatabaseConnection) {}

  /** Issues a fresh token; returns the plaintext (delivered exactly once). */
  async issue(userId: string, purpose: AccountTokenPurpose, ttlSeconds: number): Promise<string> {
    const plaintext = generateAccountToken();
    await this.connection.db.transaction(async (tx) => {
      // Invalidate outstanding tokens of the same purpose for this user.
      await tx
        .update(accountTokens)
        .set({ consumedAt: sql`now()` })
        .where(
          and(eq(accountTokens.userId, userId), eq(accountTokens.purpose, purpose), isNull(accountTokens.consumedAt)),
        );
      await tx.insert(accountTokens).values({
        userId,
        purpose,
        tokenHash: hashAccountToken(plaintext),
        expiresAt: sql`now() + ${ttlSeconds} * interval '1 second'`,
      });
    });
    return plaintext;
  }

  /**
   * Atomically consumes an unexpired, unconsumed token of `purpose`,
   * returning the owning user id — or null for unknown/expired/used tokens
   * (indistinguishable by design).
   */
  async consume(plaintext: string, purpose: AccountTokenPurpose): Promise<string | null> {
    const rows = await this.connection.db
      .update(accountTokens)
      .set({ consumedAt: sql`now()` })
      .where(
        and(
          eq(accountTokens.tokenHash, hashAccountToken(plaintext)),
          eq(accountTokens.purpose, purpose),
          isNull(accountTokens.consumedAt),
          gt(accountTokens.expiresAt, sql`now()`),
        ),
      )
      .returning({ userId: accountTokens.userId });
    return rows[0]?.userId ?? null;
  }

  /** Latest outstanding token for the user+purpose, if any (tests, admin UX). */
  async latest(userId: string, purpose: AccountTokenPurpose): Promise<AccountTokenRecord | null> {
    const rows = await this.connection.db
      .select(tokenColumns)
      .from(accountTokens)
      .where(
        and(eq(accountTokens.userId, userId), eq(accountTokens.purpose, purpose), isNull(accountTokens.consumedAt)),
      )
      .orderBy(sql`created_at desc`)
      .limit(1);
    return rows[0] ?? null;
  }
}
