/**
 * Compiled by its own `tsc` program (see `generic-user.test.ts`): augmenting
 * `Register` is global to a program, so it cannot live in the monorepo's.
 */
import {
  AUTH_SERVICE,
  type AuthGuard,
  authUserColumns,
  authPrincipal,
  createAuthProvider,
  type Principal,
  type RegisteredAuthUser,
  USER_PROVIDER,
} from '@framework/auth';
import { Container } from '@framework/core';
import type { FrameworkEnv } from '@framework/http';
import { pgTable, text } from 'drizzle-orm/pg-core';
import type { Context } from 'hono';

const appUsers = pgTable('users', { ...authUserColumns(), plan: text('plan').notNull().default('free') });

declare module '@framework/core' {
  interface Register {
    user: typeof appUsers.$inferSelect;
    guards: 'partner-api';
  }
}

export const provider = createAuthProvider({ usersTable: appUsers });

const container = new Container();

export const registered: Promise<string> = container
  .resolve(AUTH_SERVICE)
  .register({ name: 'A', email: 'a@example.com', password: 'secret' })
  .then((user) => user.plan);

export const found: Promise<string | undefined> = container
  .resolve(USER_PROVIDER)
  .findById('1')
  .then((user) => user?.plan);

export function fromContext(c: Context<FrameworkEnv>): string | undefined {
  const fromVariable: string | undefined = c.get('principal')?.user?.plan;
  const full: Principal | null = authPrincipal(c);
  return fromVariable ?? full?.user.plan;
}

export const partnerGuard: AuthGuard = async () => null;

export const via: Principal['via'] = 'partner-api';
// @ts-expect-error not a registered guard
export const unknownVia: Principal['via'] = 'carrier-pigeon';

export function wrongColumn(user: RegisteredAuthUser): string {
  // @ts-expect-error not a column of the app's users table
  return user.nope;
}
