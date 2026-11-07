import type { DatabaseConnection } from '@framework/database';
import { eq } from 'drizzle-orm';
import { defaultUsersTable, type users } from './schema/tables';
import type { AuthUser, AuthUsersTable, RegisteredAuthUser, UserProvider } from './types';

/**
 * Default principal loader over the framework's `users` table or an
 * application's table declared with `authUserColumns()`. Applications with a
 * custom user store implement `UserProvider` instead.
 */
export class DatabaseUserProvider<TUser extends AuthUser = RegisteredAuthUser> implements UserProvider<TUser> {
  // Queries only touch the auth columns; rows keep any others the table adds.
  readonly #users: typeof users;

  constructor(
    private readonly connection: DatabaseConnection,
    usersTable: AuthUsersTable<TUser> = defaultUsersTable<TUser>(),
  ) {
    this.#users = usersTable as unknown as typeof users;
  }

  async findById(id: string): Promise<TUser | null> {
    const rows = await this.connection.db.select().from(this.#users).where(eq(this.#users.id, id)).limit(1);
    return (rows[0] as unknown as TUser | undefined) ?? null;
  }

  async findByEmail(email: string): Promise<TUser | null> {
    const rows = await this.connection.db.select().from(this.#users).where(eq(this.#users.email, email)).limit(1);
    return (rows[0] as unknown as TUser | undefined) ?? null;
  }

  async create(input: {
    readonly name: string;
    readonly email: string;
    readonly passwordHash: string;
  }): Promise<TUser> {
    const rows = await this.connection.db.insert(this.#users).values(input).returning();
    const user = rows[0];
    if (!user) throw new Error('User insert returned no row');
    return user as unknown as TUser;
  }

  async updatePasswordHash(id: string, passwordHash: string): Promise<void> {
    await this.connection.db.update(this.#users).set({ passwordHash }).where(eq(this.#users.id, id));
  }

  async markEmailVerified(id: string): Promise<void> {
    await this.connection.db
      .update(this.#users)
      .set({ emailVerifiedAt: new Date().toISOString() })
      .where(eq(this.#users.id, id));
  }

  async setTotpSecret(id: string, secret: string | null): Promise<void> {
    await this.connection.db.update(this.#users).set({ totpSecret: secret }).where(eq(this.#users.id, id));
  }
}
