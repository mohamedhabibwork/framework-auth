import { createHash, randomBytes } from 'node:crypto';
import type { DatabaseConnection } from '@framework/database';
import { and, eq, gt, isNull, or, sql } from 'drizzle-orm';
import { apiTokens, users } from './schema/tables';
import type { ApiTokenRecord, ApiTokenStore, IssuedToken, UserRecord } from './types';

/** Plaintext prefix + 160 bits of entropy (hex) — recognizable by scanners. */
export const generateApiToken = (prefix: string): string => `${prefix}${randomBytes(20).toString('hex')}`;

/** Same hash-at-rest discipline as sessions. */
export const hashApiToken = (value: string): string => createHash('sha256').update(value).digest('hex');

const tokenColumns = {
  id: apiTokens.id,
  userId: apiTokens.userId,
  name: apiTokens.name,
  abilities: apiTokens.abilities,
  expiresAt: apiTokens.expiresAt,
  lastUsedAt: apiTokens.lastUsedAt,
  revokedAt: apiTokens.revokedAt,
  createdAt: apiTokens.createdAt,
  updatedAt: apiTokens.updatedAt,
} as const;

/**
 * PostgreSQL-backed personal API tokens. `find` resolves only unrevoked,
 * unexpired tokens (checked in SQL) joined with their user.
 */
export class PgTokenStore implements ApiTokenStore {
  constructor(private readonly connection: DatabaseConnection) {}

  async issue(
    userId: string,
    name: string,
    abilities: readonly string[],
    ttlSeconds: number | null,
  ): Promise<IssuedToken> {
    const plaintext = generateApiToken('fw_pat_');
    const rows = await this.connection.db
      .insert(apiTokens)
      .values({
        userId,
        name,
        tokenHash: hashApiToken(plaintext),
        abilities: [...abilities],
        expiresAt: ttlSeconds === null ? null : sql`now() + ${ttlSeconds} * interval '1 second'`,
      })
      .returning(tokenColumns);
    const token = rows[0];
    if (!token) throw new Error('API token insert returned no row');
    return { token, plaintext };
  }

  async find(plaintext: string): Promise<{ token: ApiTokenRecord; user: UserRecord } | null> {
    const rows = await this.connection.db
      .select({ token: tokenColumns, user: users })
      .from(apiTokens)
      .innerJoin(users, eq(users.id, apiTokens.userId))
      .where(
        and(
          eq(apiTokens.tokenHash, hashApiToken(plaintext)),
          isNull(apiTokens.revokedAt),
          or(isNull(apiTokens.expiresAt), gt(apiTokens.expiresAt, sql`now()`)),
        ),
      )
      .limit(1);
    return rows[0] ?? null;
  }

  async listForUser(userId: string): Promise<readonly ApiTokenRecord[]> {
    return this.connection.db
      .select(tokenColumns)
      .from(apiTokens)
      .where(and(eq(apiTokens.userId, userId), isNull(apiTokens.revokedAt)))
      .orderBy(apiTokens.createdAt);
  }

  async revoke(id: string, userId: string): Promise<boolean> {
    const removed = await this.connection.db
      .update(apiTokens)
      .set({ revokedAt: sql`now()` })
      .where(and(eq(apiTokens.id, id), eq(apiTokens.userId, userId), isNull(apiTokens.revokedAt)))
      .returning({ id: apiTokens.id });
    return removed.length > 0;
  }

  async revokeAllForUser(userId: string): Promise<number> {
    const removed = await this.connection.db
      .update(apiTokens)
      .set({ revokedAt: sql`now()` })
      .where(and(eq(apiTokens.userId, userId), isNull(apiTokens.revokedAt)))
      .returning({ id: apiTokens.id });
    return removed.length;
  }

  async touch(id: string): Promise<void> {
    await this.connection.db
      .update(apiTokens)
      .set({ lastUsedAt: sql`now()` })
      .where(eq(apiTokens.id, id));
  }
}
