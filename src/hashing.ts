import type { PasswordHasher } from './types';

/**
 * Argon2id hashing via Bun's native implementation (Bun is the validated
 * runtime; see ADR-1). Hashes embed salt and parameters, so verification
 * needs no sidecar metadata.
 */
export class BunPasswordHasher implements PasswordHasher {
  hash(plain: string): Promise<string> {
    return Bun.password.hash(plain, { algorithm: 'argon2id' });
  }

  verify(plain: string, hash: string): Promise<boolean> {
    return Bun.password.verify(plain, hash);
  }
}
