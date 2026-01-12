// Unified auth server entry point (Node.js/Hono) using shared modules
// This is the OAuth authorization server (typically runs on PORT+1)
// From Spotify MCP

import type { HttpBindings } from '@hono/node-server';
import { Hono } from 'hono';
import { buildOAuthRoutes } from '../adapters/http-hono/routes.oauth.js';
import { parseConfig } from '../shared/config/env.js';
import { buildAuthorizationServerMetadata } from '../shared/oauth/discovery.js';
import { getTokenStore } from '../shared/storage/singleton.js';
import { corsMiddleware } from './middlewares/cors.js';

export function buildAuthApp(): Hono<{ Bindings: HttpBindings }> {
  const app = new Hono<{ Bindings: HttpBindings }>();

  // Parse config from process.env
  const config = parseConfig(process.env as Record<string, unknown>);

  // Initialize storage (shared singleton to keep MCP+Auth in sync)
  const store = getTokenStore();

  // Middleware
  app.use('*', corsMiddleware());

  // Add discovery endpoint
  // IMPORTANT: Advertise OUR proxy endpoints, not the provider's directly!
  app.get('/.well-known/oauth-authorization-server', (c) => {
    const here = config.AUTH_RESOURCE_URI
      ? new URL(config.AUTH_RESOURCE_URI)
      : new URL(c.req.url);
    // For auth server, use same origin but different port
    const authPort = Number(here.port || (here.protocol === 'https:' ? 443 : 80)) + 1;
    const base = config.AUTH_RESOURCE_URI
      ? `${here.protocol}//${here.hostname}:${authPort}`
      : `${here.protocol}//${here.host}`;
    const scopes = config.OAUTH_SCOPES.split(' ').filter(Boolean);

    const metadata = buildAuthorizationServerMetadata(base, scopes, {
      // Use our endpoints - they proxy to the provider
      authorizationEndpoint: `${base}/authorize`,
      tokenEndpoint: `${base}/token`,
      revocationEndpoint: `${base}/revoke`,
    });

    return c.json(metadata);
  });

  // Mount OAuth routes
  app.route('/', buildOAuthRoutes(store, config));

  return app;
}
