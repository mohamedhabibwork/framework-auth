import { describe, expect, test } from 'bun:test';
import { createCacheProvider, RATE_LIMITER } from '@framework/cache';
import { Application, defineProvider } from '@framework/core';
import { AUTH_RATE_LIMITER, type AuthConfig, createAuthProvider, defaultAuthConfig } from '../src';

type Config = { readonly auth: AuthConfig; readonly cache: { readonly driver: 'memory' } };

const config: Config = {
  auth: { ...defaultAuthConfig, rateLimit: { ...defaultAuthConfig.rateLimit, enabled: true } },
  cache: { driver: 'memory' },
};

describe('auth provider ordering', () => {
  test('publishes the cache rate limiter even when listed before the cache provider', async () => {
    const app = new Application<Config>({
      config,
      providers: [
        createAuthProvider<Config>(),
        defineProvider<Config>({ name: 'database', register: () => {} }),
        createCacheProvider<Config>((c) => c.cache),
      ],
    });

    expect(app.providerNames.indexOf('cache')).toBeLessThan(app.providerNames.indexOf('auth'));
    await app.boot();
    expect(app.container.resolve(AUTH_RATE_LIMITER)).toBe(app.container.resolve(RATE_LIMITER));
    await app.shutdown();
  });
});
