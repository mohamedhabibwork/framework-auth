import { type Actor, ANONYMOUS_ACTOR } from '@framework/core';
import type { ActorResolver } from '@framework/http';
import { getCookie } from 'hono/cookie';
import { SESSION_TOUCH_INTERVAL_MS } from './constants';
import { createJwtPrincipalResolver, type JwtAlgorithm, type JwtKeySource } from './jwt-guard';
import type { AuthGuardDeps, Principal, UserProvider } from './types';

const THROTTLE_MS = SESSION_TOUCH_INTERVAL_MS;

const toActor = (principal: Principal): Actor => ({ id: principal.id, type: 'user' });

/** Guard-specific material beyond config and the DB stores. */
export interface AuthGuardExtras {
  /** Inline JWT key material (remote `jwksUri` comes from config instead). */
  readonly jwtKeys?: JwtKeySource;
  /** Verify allowlist; defaults to RS256/ES256/PS256/EdDSA. */
  readonly jwtAlgorithms?: readonly JwtAlgorithm[];
  /** Principal loader for the JWT guard (defaults to the bound USER_PROVIDER). */
  readonly users?: UserProvider;
}

/**
 * Authenticates the request before its scope is created (the kernel calls
 * this from the `resolveActor` hook), so the execution context — and every
 * `currentActor()`/`logger()` call in the chain — already carries the real
 * identity. Installs the full `Principal` on the context for policies.
 *
 * Guards are consulted in config order (default: session cookie, then
 * Bearer token; `jwt` adds stateless RS/ES/PS/EdDSA verification over a
 * JWKS); the first match wins. One lookup per request.
 */
export function createAuthActorResolver(deps: AuthGuardDeps, extras: AuthGuardExtras = {}): ActorResolver {
  const { config, sessions, tokens } = deps;

  const resolveSession = async (cookieValue: string | undefined): Promise<Principal | null> => {
    if (!cookieValue) return null;
    const resolved = await sessions.find(cookieValue);
    if (!resolved) return null;
    // Sliding renewal, throttled to at most one UPDATE per interval.
    if (Date.now() - Date.parse(resolved.session.lastUsedAt) > THROTTLE_MS) {
      await sessions.touch(resolved.session.id, config.session.ttlSeconds);
    }
    return {
      id: resolved.user.id,
      via: 'session',
      abilities: ['*'],
      user: resolved.user,
      sessionId: resolved.session.id,
    };
  };

  const resolveToken = async (header: string | undefined): Promise<Principal | null> => {
    if (!header?.startsWith('Bearer ')) return null;
    const resolved = await tokens.find(header.slice('Bearer '.length).trim());
    if (!resolved) return null;
    await tokens.touch(resolved.token.id);
    return {
      id: resolved.user.id,
      via: 'api-token',
      abilities: resolved.token.abilities,
      user: resolved.user,
      tokenId: resolved.token.id,
    };
  };

  // Built lazily so apps without the jwt guard never touch jose key setup —
  // and so a misconfigured jwt guard fails loudly on first use, not silently.
  let resolveJwt: ((header: string | undefined) => Promise<Principal | null>) | undefined;
  const jwtFor = (): ((header: string | undefined) => Promise<Principal | null>) => {
    if (!resolveJwt) {
      if (!extras.users) throw new Error('auth guard "jwt" requires a user provider (extras.users)');
      resolveJwt = createJwtPrincipalResolver({
        config: config.jwt,
        keys: {
          jwksUri: config.jwt.jwksUri || undefined,
          jwks: extras.jwtKeys?.jwks,
          cooldownDurationMs: extras.jwtKeys?.cooldownDurationMs,
        },
        users: extras.users,
        algorithms: extras.jwtAlgorithms,
      });
    }
    return resolveJwt;
  };

  return async (c) => {
    for (const guard of config.guards) {
      const principal =
        guard === 'session'
          ? await resolveSession(getCookie(c, config.session.cookie))
          : guard === 'jwt'
            ? await jwtFor()(c.req.header('authorization'))
            : await resolveToken(c.req.header('authorization'));
      if (principal) {
        c.set('principal', principal);
        return toActor(principal);
      }
    }
    return ANONYMOUS_ACTOR;
  };
}
