import type { DatabaseConnection } from '@framework/database';
import { eq } from 'drizzle-orm';
import { users } from './schema/tables';
import type { UserProvider, UserRecord } from './types';

/**
 * Default principal loader over the framework-owned `users` table.
 * Applications with a custom user store implement `UserProvider` instead.
 */
export class DatabaseUserProvider implements UserProvider {
  constructor(private readonly connection: DatabaseConnection) {}

  async findById(id: string): Promise<UserRecord | null> {
    const rows = await this.connection.db.select().from(users).where(eq(users.id, id)).limit(1);
    return rows[0] ?? null;
  }

  async findByEmail(email: string): Promise<UserRecord | null> {
    const rows = await this.connection.db.select().from(users).where(eq(users.email, email)).limit(1);
    return rows[0] ?? null;
  }

  async create(input: {
    readonly name: string;
    readonly email: string;
    readonly passwordHash: string;
  }): Promise<UserRecord> {
    const rows = await this.connection.db.insert(users).values(input).returning();
    const user = rows[0];
    if (!user) throw new Error('User insert returned no row');
    return user;
  }

  async updatePasswordHash(id: string, passwordHash: string): Promise<void> {
    await this.connection.db.update(users).set({ passwordHash }).where(eq(users.id, id));
  }

  async markEmailVerified(id: string): Promise<void> {
    await this.connection.db.update(users).set({ emailVerifiedAt: new Date().toISOString() }).where(eq(users.id, id));
  }

  async setTotpSecret(id: string, secret: string | null): Promise<void> {
    await this.connection.db.update(users).set({ totpSecret: secret }).where(eq(users.id, id));
  }
}
