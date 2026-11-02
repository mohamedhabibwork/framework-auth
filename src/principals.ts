import type { FrameworkEnv } from '@framework/http';
import type { Context } from 'hono';

export { hasAbility } from '@framework/http';

/**
 * Narrows the http-level principal to this package's full shape (or null).
 * `TUser` defaults to `Register.user`; pass it where the app has not declared one.
 */
export function authPrincipal<TUser extends AuthUser = RegisteredAuthUser>(
  c: Context<FrameworkEnv>,
): Principal<TUser> | null {
  const principal = c.get('principal');
  return principal && 'via' in principal ? (principal as unknown as Principal<TUser>) : null;
}

import type { AuthUser, Principal, RegisteredAuthUser } from './types';
