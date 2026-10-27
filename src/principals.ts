import type { FrameworkEnv } from '@framework/http';
import type { Context } from 'hono';

export { hasAbility } from '@framework/http';

/** Narrows the http-level principal to this package's full shape (or null). */
export function authPrincipal(c: Context<FrameworkEnv>): Principal | null {
  const principal = c.get('principal');
  return principal && 'via' in principal ? (principal as Principal) : null;
}

import type { Principal } from './types';
