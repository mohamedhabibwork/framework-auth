import { type Actor, ANONYMOUS_ACTOR, FrameworkError } from '@framework/core';
import type { ActorResolver, PrincipalLike } from '@framework/http';
import { getCookie } from 'hono/cookie';
import { SESSION_TOUCH_INTERVAL_MS } from './constants';
import { createJwtPrincipalResolver, type JwtAlgorithm, type JwtKeySource } from './jwt-guard';
import type {
  AuthGuard,
  AuthGuardDeps,
  AuthUser,
  BuiltInAuthGuardName,
  Principal,
  RegisteredAuthUser,
  UserProvider,
} from './types';

const THROTTLE_MS = SESSION_TOUCH_INTERVAL_MS;
const BUILT_IN_GUARDS: readonly BuiltInAuthGuardName[] = ['session', 'api-token', 'jwt'];

/** Fails when `auth.guards` names a guard that is neither built in nor supplied. */
export function assertKnownGuards(names: readonly string[], custom: Readonly<Record<string, unknown>> = {}): void {
  const known = new Set<string>([...BUILT_IN_GUARDS, ...Object.keys(custom)]);
  for (const name of names) {
    if (!known.has(name)) {
      throw new FrameworkError(
        'AUTH_GUARD_UNKNOWN',
        `auth.guards lists "${name}", but no such guard exists; pass it as createAuthProvider({ guards })`,
      );
    }
  }
}

const toActor = (principal: PrincipalLike): Actor => ({ id: principal.id, type: 'user' });

/** Guard-specific material beyond config and the DB stores. */
export interface AuthGuardExtras<TUser extends AuthUser = RegisteredAuthUser> {
  /** Inline JWT key material (remote `jwksUri` comes from config instead). */
  readonly jwtKeys?: JwtKeySource;
  /** Verify allowlist; defaults to RS256/ES256/PS256/EdDSA. */
  readonly jwtAlgorithms?: readonly JwtAlgorithm[];
  /** Principal loader for the JWT guard (defaults to the bound USER_PROVIDER). */
  readonly users?: UserProvider<TUser>;
  /** Guards beyond the built-in ones, by the name `config.guards` lists them under. */
  readonly guards?: Readonly<Record<string, AuthGuard<TUser>>>;
}

/**
 * Authenticates the request before its scope is created (the kernel calls
 * this from the `resolveActor` hook), so the execution context — and every
 * `currentActor()`/`logger()` call in the chain — already carries the real
 * identity. Installs the full `Principal` on the context for policies.
 *
 * Guards are consulted in config order (default: session cookie, then
 * Bearer token; `jwt` adds stateless RS/ES/PS/EdDSA verification over a
 * JWKS); the first match wins. One lookup per request. A custom guard with a
 * built-in's name replaces it.
 */
export function createAuthActorResolver<TUser extends AuthUser = RegisteredAuthUser>(
  deps: AuthGuardDeps<TUser>,
  extras: AuthGuardExtras<TUser> = {},
): ActorResolver {
  const { config, sessions, tokens } = deps;
  assertKnownGuards(config.guards, extras.guards);

  const resolveSession = async (cookieValue: string | undefined): Promise<Principal<TUser> | null> => {
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

  const resolveToken = async (header: string | undefined): Promise<Principal<TUser> | null> => {
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
  let resolveJwt: ((header: string | undefined) => Promise<Principal<TUser> | null>) | undefined;
  const jwtFor = (): ((header: string | undefined) => Promise<Principal<TUser> | null>) => {
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

  const guards = new Map<string, AuthGuard<TUser>>([
    ['session', (c) => resolveSession(getCookie(c, config.session.cookie))],
    ['api-token', (c) => resolveToken(c.req.header('authorization'))],
    ['jwt', (c) => jwtFor()(c.req.header('authorization'))],
    ...Object.entries(extras.guards ?? {}),
  ]);
  const chain = config.guards.flatMap((name) => guards.get(name) ?? []);

  return async (c) => {
    for (const guard of chain) {
      const principal = await guard(c);
      if (principal) {
        const installed = principal as unknown as PrincipalLike;
        c.set('principal', installed);
        return toActor(installed);
      }
    }
    return ANONYMOUS_ACTOR;
  };
}
