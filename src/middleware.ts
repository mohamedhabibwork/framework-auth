import { forbidden, requireAuth, unauthenticated } from '@framework/http';
import { createMiddleware } from 'hono/factory';
import { authPrincipal, hasAbility } from './principals';

export { requireAuth };

/**
 * Route middleware requiring an authenticated principal whose abilities
 * grant `ability` (convention `<resource>.<ability>`; `*` grants all).
 * Anonymous requests get 401; authenticated-but-unable get 403.
 */
export const requireAbility = (ability: string) =>
  createMiddleware(async (c, next) => {
    const principal = authPrincipal(c);
    if (!principal) throw unauthenticated();
    if (!hasAbility(principal, ability)) throw forbidden();
    await next();
  });

/**
 * Route middleware requiring a verified email address. Anonymous → 401,
 * authenticated-but-unverified → 403. Mount behind `requireAuth`-guarded
 * routes whose handlers rely on `principal.user.emailVerifiedAt`.
 */
export const verified = () =>
  createMiddleware(async (c, next) => {
    const principal = authPrincipal(c);
    if (!principal) throw unauthenticated();
    if (!principal.user.emailVerifiedAt) throw forbidden('Email verification required');
    await next();
  });
