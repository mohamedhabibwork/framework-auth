import { createHash } from 'node:crypto';
import type { DatabaseConnection } from '@framework/database';
import { and, eq, isNull, sql } from 'drizzle-orm';
import { totpRecoveryCodes } from './schema/tables';
import type { TotpRecoveryCodeRecord } from './types';

/** Same hash-at-rest discipline as every other auth token. */
export const hashRecoveryCode = (code: string): string => createHash('sha256').update(code).digest('hex');

/**
 * One-time TOTP recovery codes. `consume` flips `usedAt` under an
 * `IS NULL` guard in SQL, so a code is single-use even under concurrent
 * replay. Users get the plaintext list exactly once, at generation time.
 */
export class PgRecoveryCodeStore {
  constructor(private readonly connection: DatabaseConnection) {}

  /** Replaces all of the user's codes with a fresh hashed set. */
  async replaceAll(userId: string, codes: readonly string[]): Promise<void> {
    await this.connection.db.transaction(async (tx) => {
      await tx.delete(totpRecoveryCodes).where(eq(totpRecoveryCodes.userId, userId));
      await tx.insert(totpRecoveryCodes).values(codes.map((code) => ({ userId, codeHash: hashRecoveryCode(code) })));
    });
  }

  /** Atomically consumes one code; true when it was valid and unused. */
  async consume(userId: string, code: string): Promise<boolean> {
    const rows = await this.connection.db
      .update(totpRecoveryCodes)
      .set({ usedAt: sql`now()` })
      .where(
        and(
          eq(totpRecoveryCodes.userId, userId),
          eq(totpRecoveryCodes.codeHash, hashRecoveryCode(code)),
          isNull(totpRecoveryCodes.usedAt),
        ),
      )
      .returning({ id: totpRecoveryCodes.id });
    return rows.length > 0;
  }

  /** Counts unused codes (low-balance warnings, tests). */
  async countUnused(userId: string): Promise<number> {
    const rows = await this.connection.db
      .select({ total: sql<number>`count(*)::int` })
      .from(totpRecoveryCodes)
      .where(and(eq(totpRecoveryCodes.userId, userId), isNull(totpRecoveryCodes.usedAt)));
    return rows[0]?.total ?? 0;
  }

  async deleteAll(userId: string): Promise<void> {
    await this.connection.db.delete(totpRecoveryCodes).where(eq(totpRecoveryCodes.userId, userId));
  }

  async list(userId: string): Promise<readonly TotpRecoveryCodeRecord[]> {
    return this.connection.db.select().from(totpRecoveryCodes).where(eq(totpRecoveryCodes.userId, userId));
  }
}
