import { createHash, randomBytes } from 'node:crypto';
import type { DatabaseConnection } from '@framework/database';
import { and, eq, gt, lt, sql } from 'drizzle-orm';
import { SECRET_BYTES } from './constants';
import { sessions, users } from './schema/tables';
import type { IssuedSession, ResolvedSession, SessionStore } from './types';

/** Opaque cookie value: prefix + 256 bits of entropy (base64url). */
export const generateSessionToken = (): string => `fw_sess_${randomBytes(SECRET_BYTES).toString('base64url')}`;

/** Only hashes are stored, so a database leak never yields usable sessions. */
export const hashToken = (value: string): string => createHash('sha256').update(value).digest('hex');

/** Projection excluding `tokenHash` from every selected session row. */
const sessionColumns = {
  id: sessions.id,
  userId: sessions.userId,
  expiresAt: sessions.expiresAt,
  lastUsedAt: sessions.lastUsedAt,
  createdAt: sessions.createdAt,
  updatedAt: sessions.updatedAt,
} as const;

/**
 * PostgreSQL-backed sessions. Expiry filtering happens in SQL
 * (`expires_at > now()`); string-mode columns come back as written.
 */
export class PgSessionStore implements SessionStore {
  constructor(private readonly connection: DatabaseConnection) {}

  async create(userId: string, ttlSeconds: number): Promise<IssuedSession> {
    const token = generateSessionToken();
    const rows = await this.connection.db
      .insert(sessions)
      .values({ userId, tokenHash: hashToken(token), expiresAt: sql`now() + ${ttlSeconds} * interval '1 second'` })
      .returning(sessionColumns);
    const session = rows[0];
    if (!session) throw new Error('Session insert returned no row');
    return { token, session };
  }

  async find(token: string): Promise<ResolvedSession | null> {
    const rows = await this.connection.db
      .select({ session: sessionColumns, user: users })
      .from(sessions)
      .innerJoin(users, eq(users.id, sessions.userId))
      .where(and(eq(sessions.tokenHash, hashToken(token)), gt(sessions.expiresAt, sql`now()`)))
      .limit(1);
    const row = rows[0];
    return row ? { session: row.session, user: row.user } : null;
  }

  async rotate(currentToken: string, ttlSeconds: number): Promise<IssuedSession | null> {
    return this.connection.db.transaction(async (tx) => {
      // Rotation is the login event: the previous session dies even if the
      // row was already gone (idempotent for reuse after expiry).
      const removed = await tx
        .delete(sessions)
        .where(eq(sessions.tokenHash, hashToken(currentToken)))
        .returning({ userId: sessions.userId });
      const userId = removed[0]?.userId;
      if (!userId) return null;
      const token = generateSessionToken();
      const rows = await tx
        .insert(sessions)
        .values({ userId, tokenHash: hashToken(token), expiresAt: sql`now() + ${ttlSeconds} * interval '1 second'` })
        .returning(sessionColumns);
      const session = rows[0];
      if (!session) throw new Error('Session rotation insert returned no row');
      return { token, session };
    });
  }

  async revoke(token: string): Promise<boolean> {
    const removed = await this.connection.db
      .delete(sessions)
      .where(eq(sessions.tokenHash, hashToken(token)))
      .returning({ id: sessions.id });
    return removed.length > 0;
  }

  async revokeById(id: string): Promise<boolean> {
    const removed = await this.connection.db.delete(sessions).where(eq(sessions.id, id)).returning({ id: sessions.id });
    return removed.length > 0;
  }

  async revokeAllForUser(userId: string): Promise<number> {
    const removed = await this.connection.db
      .delete(sessions)
      .where(eq(sessions.userId, userId))
      .returning({ id: sessions.id });
    return removed.length;
  }

  async touch(id: string, ttlSeconds: number): Promise<void> {
    await this.connection.db
      .update(sessions)
      .set({ lastUsedAt: sql`now()`, expiresAt: sql`now() + ${ttlSeconds} * interval '1 second'` })
      .where(eq(sessions.id, id));
  }

  async prune(now: Date = new Date()): Promise<number> {
    const removed = await this.connection.db
      .delete(sessions)
      .where(lt(sessions.expiresAt, now.toISOString()))
      .returning({ id: sessions.id });
    return removed.length;
  }

  async countExpired(now: Date = new Date()): Promise<number> {
    const rows = await this.connection.db
      .select({ count: sql<number>`count(*)::int` })
      .from(sessions)
      .where(lt(sessions.expiresAt, now.toISOString()));
    return rows[0]?.count ?? 0;
  }
}
