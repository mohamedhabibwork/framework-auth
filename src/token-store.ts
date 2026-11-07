import { createHash, randomBytes } from 'node:crypto';
import type { DatabaseConnection } from '@framework/database';
import { and, eq, gt, isNull, or, sql } from 'drizzle-orm';
import { apiTokens, defaultUsersTable, type users } from './schema/tables';
import type { ApiTokenRecord, ApiTokenStore, AuthUser, AuthUsersTable, IssuedToken, RegisteredAuthUser } from './types';

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
export class PgTokenStore<TUser extends AuthUser = RegisteredAuthUser> implements ApiTokenStore<TUser> {
  readonly #users: typeof users;

  constructor(
    private readonly connection: DatabaseConnection,
    usersTable: AuthUsersTable<TUser> = defaultUsersTable<TUser>(),
  ) {
    this.#users = usersTable as unknown as typeof users;
  }

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

  async find(plaintext: string): Promise<{ token: ApiTokenRecord; user: TUser } | null> {
    const rows = await this.connection.db
      .select({ token: tokenColumns, user: this.#users })
      .from(apiTokens)
      .innerJoin(this.#users, eq(this.#users.id, apiTokens.userId))
      .where(
        and(
          eq(apiTokens.tokenHash, hashApiToken(plaintext)),
          isNull(apiTokens.revokedAt),
          or(isNull(apiTokens.expiresAt), gt(apiTokens.expiresAt, sql`now()`)),
        ),
      )
      .limit(1);
    const row = rows[0];
    return row ? { token: row.token, user: row.user as unknown as TUser } : null;
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
