import type { InferSelectModel } from 'drizzle-orm';
import { index, pgTable, text, timestamp, uuid } from 'drizzle-orm/pg-core';

/**
 * Framework-owned identity tables. Applications re-export them from their
 * schema index so Drizzle Kit generates their migration with the app's other
 * tables (same pattern as `audit_logs`). Applications with a custom user
 * store keep their own table and swap the `UserProvider` instead.
 */
export const users = pgTable('users', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: text('name').notNull(),
  email: text('email').notNull().unique(),
  emailVerifiedAt: timestamp('email_verified_at', { withTimezone: true, mode: 'string' }),
  passwordHash: text('password_hash').notNull(),
  /** Base32 TOTP shared secret; null until the user enables two-step login. */
  totpSecret: text('totp_secret'),
  createdAt: timestamp('created_at', { withTimezone: true, mode: 'string' }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true, mode: 'string' })
    .notNull()
    .defaultNow()
    .$onUpdate(() => new Date().toISOString()),
});

/**
 * Server-side session state. The cookie carries an opaque random value; only
 * its SHA-256 hash is stored, so a database leak never yields usable
 * sessions. Revocation/rotation deletes rows — no soft state to leak.
 */
export const sessions = pgTable(
  'sessions',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    tokenHash: text('token_hash').notNull().unique(),
    expiresAt: timestamp('expires_at', { withTimezone: true, mode: 'string' }).notNull(),
    lastUsedAt: timestamp('last_used_at', { withTimezone: true, mode: 'string' }).notNull().defaultNow(),
    createdAt: timestamp('created_at', { withTimezone: true, mode: 'string' }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true, mode: 'string' })
      .notNull()
      .defaultNow()
      .$onUpdate(() => new Date().toISOString()),
  },
  (table) => [index('sessions_user_id_idx').on(table.userId)],
);

/**
 * Personal API tokens (Bearer). Plaintext is shown once at issuance; only the
 * SHA-256 hash is persisted. Abilities are opaque strings by convention
 * `<resource>.<ability>`; `*` grants everything.
 */
export const apiTokens = pgTable(
  'api_tokens',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    name: text('name').notNull(),
    tokenHash: text('token_hash').notNull().unique(),
    abilities: text('abilities').array().notNull(),
    expiresAt: timestamp('expires_at', { withTimezone: true, mode: 'string' }),
    lastUsedAt: timestamp('last_used_at', { withTimezone: true, mode: 'string' }).notNull().defaultNow(),
    revokedAt: timestamp('revoked_at', { withTimezone: true, mode: 'string' }),
    createdAt: timestamp('created_at', { withTimezone: true, mode: 'string' }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true, mode: 'string' })
      .notNull()
      .defaultNow()
      .$onUpdate(() => new Date().toISOString()),
  },
  (table) => [index('api_tokens_user_id_idx').on(table.userId)],
);

export type UserRow = InferSelectModel<typeof users>;
export type SessionRow = InferSelectModel<typeof sessions>;
export type ApiTokenRow = InferSelectModel<typeof apiTokens>;

/**
 * Single-use account tokens for email verification and password recovery.
 * The plaintext is shown/delivered once; only its SHA-256 hash is stored.
 * `consumedAt` makes every token single-use — a replay after consumption
 * misses the SQL guard and resolves to nothing.
 */
export const accountTokens = pgTable(
  'account_tokens',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    /** `'email-verification' | 'password-reset'` (checked in SQL, not FK-enforced). */
    purpose: text('purpose').notNull(),
    tokenHash: text('token_hash').notNull().unique(),
    expiresAt: timestamp('expires_at', { withTimezone: true, mode: 'string' }).notNull(),
    consumedAt: timestamp('consumed_at', { withTimezone: true, mode: 'string' }),
    createdAt: timestamp('created_at', { withTimezone: true, mode: 'string' }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true, mode: 'string' })
      .notNull()
      .defaultNow()
      .$onUpdate(() => new Date().toISOString()),
  },
  (table) => [index('account_tokens_user_id_idx').on(table.userId)],
);

/** One-time TOTP recovery codes; only their SHA-256 hashes are stored. */
export const totpRecoveryCodes = pgTable(
  'totp_recovery_codes',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    codeHash: text('code_hash').notNull().unique(),
    usedAt: timestamp('used_at', { withTimezone: true, mode: 'string' }),
    createdAt: timestamp('created_at', { withTimezone: true, mode: 'string' }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true, mode: 'string' })
      .notNull()
      .defaultNow()
      .$onUpdate(() => new Date().toISOString()),
  },
  (table) => [index('totp_recovery_codes_user_id_idx').on(table.userId)],
);

export type AccountTokenRow = InferSelectModel<typeof accountTokens>;
export type TotpRecoveryCodeRow = InferSelectModel<typeof totpRecoveryCodes>;
