import type { JSONWebKeySet, JWSAlgorithm } from 'jose';
import { createLocalJWKSet, createRemoteJWKSet, jwtVerify } from 'jose';
import type { AuthConfig, Principal, UserProvider } from './types';

export type JwtAlgorithm = JWSAlgorithm;

const DEFAULT_ALGORITHMS: readonly JwtAlgorithm[] = ['RS256', 'ES256', 'PS256', 'EdDSA'];

/** Key material for the JWT guard: a remote JWKS endpoint or inline keys. */
export interface JwtKeySource {
  /** URL of the identity provider's JWKS endpoint (rotation-aware: unknown `kid`s refetch). */
  readonly jwksUri?: string;
  /** Inline key set for self-managed signing keys (tests, single-tenant setups). */
  readonly jwks?: JSONWebKeySet;
  /** Minimum interval between remote JWKS fetches, in ms. Default 30_000. */
  readonly cooldownDurationMs?: number;
}

export interface JwtGuardDeps {
  readonly config: AuthConfig['jwt'];
  readonly keys: JwtKeySource;
  readonly users: UserProvider;
  readonly algorithms?: readonly JwtAlgorithm[];
}

/**
 * Abilities carried by the token: the `scope` claim (space-delimited,
 * OAuth 2.0 style) or an `abilities` array claim; tokens with neither get
 * `*` — matching session principals. Applications that want claim-scoped
 * JWTs put one of those claims in their access tokens.
 */
const abilitiesFrom = (payload: Record<string, unknown>): readonly string[] => {
  const scope = payload.scope;
  if (typeof scope === 'string' && scope.trim()) return scope.trim().split(/\s+/);
  const abilities = payload.abilities;
  if (Array.isArray(abilities) && abilities.every((a) => typeof a === 'string')) return abilities as string[];
  return ['*'];
};

/**
 * JWT Bearer guard over `jose`: RS/ES/PS/EdDSA verification against a JWKS
 * with `kid` lookup, `iss`/`aud` checks and rotation support (the remote
 * key set refetches when it meets an unknown `kid`). The `sub` claim must
 * match a local user id — JWTs authenticate existing accounts, they never
 * provision one. Any verification failure resolves null (the request stays
 * anonymous; route guards answer 401).
 */
export function createJwtPrincipalResolver(
  deps: JwtGuardDeps,
): (header: string | undefined) => Promise<Principal | null> {
  const { jwksUri, jwks } = deps.keys;
  if (!jwksUri && !jwks) {
    throw new Error(
      'auth guard "jwt" requires key material: set auth.jwt.jwksUri (remote JWKS, rotation-aware) or pass inline keys via createAuthProvider({ jwt: { jwks } })',
    );
  }
  const algorithms = deps.algorithms ?? DEFAULT_ALGORITHMS;
  // jose caches remote keys and refreshes on unknown kid — rotation-safe.
  const keyStore = jwksUri
    ? createRemoteJWKSet(new URL(jwksUri), { cooldownDuration: deps.keys.cooldownDurationMs ?? 30_000 })
    : createLocalJWKSet(jwks as JSONWebKeySet);

  return async (header) => {
    if (!header?.startsWith('Bearer ')) return null;
    const token = header.slice('Bearer '.length).trim();
    if (!token) return null;
    let payload: Record<string, unknown>;
    try {
      const verified = await jwtVerify(token, keyStore, {
        algorithms: [...algorithms],
        issuer: deps.config.issuer || undefined,
        audience: deps.config.audience || undefined,
      });
      payload = verified.payload as Record<string, unknown>;
    } catch {
      return null;
    }
    const sub = payload.sub;
    if (typeof sub !== 'string' || !sub) return null;
    const user = await deps.users.findById(sub);
    if (!user) return null;
    return { id: user.id, via: 'jwt', abilities: abilitiesFrom(payload), user };
  };
}
