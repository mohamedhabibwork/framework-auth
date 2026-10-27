import { createHmac, randomBytes, randomInt, timingSafeEqual } from 'node:crypto';

// -- Base32 (RFC 4648, no padding) -------------------------------------------

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let output = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += ALPHABET[(value << (5 - bits)) & 31];
  return output;
}

export function base32Decode(encoded: string): Buffer {
  const clean = encoded.toUpperCase().replace(/=+$/g, '').replace(/\s+/g, '');
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];
  for (const char of clean) {
    const idx = ALPHABET.indexOf(char);
    if (idx === -1) throw new Error(`invalid base32 character: ${char}`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

// -- HOTP / TOTP (RFC 4226 / RFC 6238 §5) --------------------------------------
//
// The framework provisions the RFC 6238 SHA-256 variant only. HMAC-SHA-1 is
// deliberately not offered: it is the weak-digest legacy variant, and this
// framework's security policy excludes weak-digest primitives. The trade-off
// is authenticator interoperability — every modern app (Aegis, 1Password,
// Bitwarden, FreeOTP, Ente Auth) supports `algorithm=SHA256`, while Google
// Authenticator implements the legacy variant only; provisioning URIs state
// the algorithm explicitly so unsupported apps fail visibly at enrollment,
// not silently at login. Security rests on the 256-bit shared secret plus
// the per-window 10^6 code space, never on hash collision resistance.

/** Provisioning algorithms of the RFC 6238 §5 variants (no legacy digest). */
export type TotpAlgorithm = 'SHA256' | 'SHA512';

const HASHES: Readonly<Record<TotpAlgorithm, 'sha256' | 'sha512'>> = {
  SHA256: 'sha256',
  SHA512: 'sha512',
};

/** New enrollments provision this algorithm. */
export const DEFAULT_TOTP_ALGORITHM: TotpAlgorithm = 'SHA256';

const hmac = (key: Buffer, counter: bigint, algorithm: TotpAlgorithm): Buffer => {
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(counter);
  return createHmac(HASHES[algorithm], key).update(message).digest();
};

const dynamicTruncate = (digest: Buffer): number => {
  const offset = (digest.at(-1) ?? 0) & 0x0f;
  const octet = (index: number): number => digest[offset + index] ?? 0;
  const binary = ((octet(0) & 0x7f) << 24) | ((octet(1) & 0xff) << 16) | ((octet(2) & 0xff) << 8) | (octet(3) & 0xff);
  return binary % 10 ** 6;
};

export const hotp = (
  secret: Buffer,
  counter: bigint,
  options: { readonly algorithm?: TotpAlgorithm; readonly digits?: number } = {},
): string => {
  const digits = options.digits ?? 6;
  return dynamicTruncate(hmac(secret, counter, options.algorithm ?? DEFAULT_TOTP_ALGORITHM))
    .toString()
    .padStart(digits, '0');
};

/**
 * Verifies a TOTP for `secret` at time `now`, allowing ±`window` steps of
 * clock drift (default ±1 = ±30s). Comparison is constant-time; the digits
 * comparison happens only for matching counter windows.
 */
export const verifyTotp = (
  secretBase32: string,
  code: string,
  options: {
    readonly now?: number;
    readonly stepSeconds?: number;
    readonly window?: number;
    readonly digits?: number;
    readonly algorithm?: TotpAlgorithm;
  } = {},
): boolean => {
  const stepSeconds = options.stepSeconds ?? 30;
  const window = options.window ?? 1;
  const digits = options.digits ?? 6;
  if (!new RegExp(`^\\d{${digits}}$`).test(code)) return false;
  let secret: Buffer;
  try {
    secret = base32Decode(secretBase32);
  } catch {
    return false;
  }
  if (secret.length === 0) return false;
  const counter = BigInt(Math.floor((options.now ?? Date.now()) / 1000 / stepSeconds));
  for (let drift = -window; drift <= window; drift += 1) {
    const candidate = Buffer.from(hotp(secret, counter + BigInt(drift), { algorithm: options.algorithm, digits }));
    const provided = Buffer.from(code);
    if (candidate.length === provided.length && timingSafeEqual(candidate, provided)) return true;
  }
  return false;
};

/** 256-bit base32 secret, sized for the SHA-256 variant. */
export const generateTotpSecret = (): string => base32Encode(randomBytes(32));

/** `otpauth://` provisioning URI for authenticator apps (algorithm stated explicitly). */
export const totpUri = (
  secret: string,
  account: string,
  issuer: string,
  algorithm: TotpAlgorithm = DEFAULT_TOTP_ALGORITHM,
): string =>
  `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(account)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=${algorithm}&digits=6&period=30`;

// -- Recovery codes ------------------------------------------------------------

/** `xxxx-xxxx` lowercase alphanumeric (unambiguous set), 8 chars ≈ 40 bits. */
export const generateRecoveryCode = (): string => {
  const alphabet = 'abcdefghjkmnpqrstuvwxyz23456789';
  let code = '';
  for (let i = 0; i < 8; i += 1) {
    if (i === 4) code += '-';
    code += alphabet[randomInt(alphabet.length)];
  }
  return code;
};

export const generateRecoveryCodes = (count = 10): readonly string[] =>
  Array.from({ length: count }, () => generateRecoveryCode());

/** Normalizes user input: trims, lowercases, drops separators/spaces. */
export const normalizeTotpCode = (code: string): string => code.trim().toLowerCase().replace(/[\s-]/g, '');
