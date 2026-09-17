# Mosaic MCP Kit

`@kapio/mosaic-mcp` is the shared frame for MCP servers that sign people in through a [Mosaic](https://kapio.eu) instance. A server brings its tools; the kit brings everything around them:

- Streamable HTTP transport: `POST /mcp` (JSON or SSE), sessions via `Mcp-Session-Id`, CORS, `GET /health`
- Sign-in through Mosaic: Bearer access tokens checked against the instance JWKS (EdDSA, `iss`, `aud`, `exp`, `nbf`)
- OAuth discovery (RFC 9728): `/.well-known/oauth-protected-resource[/mcp]` and `WWW-Authenticate: Bearer resource_metadata="…"` on 401
- Static token ways for the transition and the emergency access, compared in constant time
- One JSON log line per `tools/call` with the person, never arguments, results or token values

No runtime dependency: `node:http` and `node:crypto`, Node 20 or newer.

## Use

```js
const { createMcpServer } = require('@kapio/mosaic-mcp');
const McpHandler = require('./mcp-handler');

let app;
try {
  app = createMcpServer({
    service: 'kapio-harvest-mcp',
    version: '1.1.0',
    protocol: '2025-11-25',
    handler: new McpHandler(),
    extraHealth: () => ({ harvest: true }),
    tokens: [{ name: 'notzugang', value: process.env.MCP_ACCESS_TOKEN }]
  });
} catch (err) {
  console.error(`FATAL: ${err.message}`);
  process.exit(1);
}
app.listen(process.env.PORT || 8080);
```

| Environment      | Example                                    | Required |
| ---------------- | ------------------------------------------ | -------- |
| `OAUTH_ISSUER`   | `https://mosaic.kapio.eu/api/auth`         | yes      |
| `MCP_RESOURCE`   | `https://harvest-mcp.kapio.eu/mcp`         | yes      |
| `ALLOWED_ORIGINS`| `https://claude.ai` (default)              | no       |

Without `OAUTH_ISSUER` or `MCP_RESOURCE`, `createMcpServer` throws `ConfigError` and the server must not start.

## API

### `createMcpServer(options)`

| Option            | Meaning                                                                                                  |
| ----------------- | -------------------------------------------------------------------------------------------------------- |
| `service`         | name in health and log                                                                                   |
| `handler`         | object with `handleRequest(request, sessionId, identity)`; returns the JSON-RPC response or `null` (202) |
| `version`, `protocol` | shown in `/health`                                                                                   |
| `extraHealth`     | function returning service fields for `/health`                                                          |
| `tokens`          | `[{ name, value, instances?, write? }]`, static token ways; entries without value are dropped            |
| `allowQueryToken` | `true` accepts `?token=` for static tokens; Mosaic tokens are only accepted by header                    |
| `issuer`, `resource`, `allowedOrigins`, `jwks`, `log`, `env` | overrides, mainly for tests                                   |

Returns `{ server, listen(port), close(), describe(), issuer, resource, metadataUrl }`. `describe()` gives `{ service, version, protocol, resource, issuer, metadataUrl }` for a registrar.

`identity` passed to the handler:

| Way           | Shape                                                        |
| ------------- | ------------------------------------------------------------ |
| Mosaic token  | `{ via: 'oauth', email, sub, azp, scope }`                   |
| static token  | `{ via: '<token name>', scope: <the token entry>, query }`   |

The server decides what `scope.instances` and `scope.write` allow; the kit only finds the entry.

### `verifyAccessToken(token, { issuer, resource, jwks, now? })`

Resolves `{ sub, email, azp, exp, scope }` or rejects with `TokenError` whose `reason` is one of `malformed`, `alg`, `kid`, `signature`, `iss`, `aud`, `exp`, `nbf`, `jwks`.

| Rule        | Check                                                                    |
| ----------- | ------------------------------------------------------------------------ |
| algorithm   | `EdDSA` only, key chosen by `kid`                                        |
| issuer      | `iss` equals the one configured issuer exactly                           |
| audience    | `aud` (string or array) contains the resource                            |
| lifetime    | `exp` required; `exp` and `nbf` with 60 s leeway                         |

`jwks` is a client from `createJwksClient({ uri })` or a plain `{ keys }` document.

### `createJwksClient({ uri, fetch?, now?, ttlMs?, minRefreshMs? })`

Caches the key set for ten minutes. An unknown `kid` reloads once, at most once per minute, then counts as unknown. With the issuer unreachable, cached keys keep working.

### `matchToken(given, tokens)`

Returns the matching entry or `null`. Compares SHA-256 digests with `timingSafeEqual` against every entry without leaving early.

## Call log

One line on stdout per `tools/call`:

```json
{"ts":"2026-09-17T08:00:00.000Z","service":"kapio-harvest-mcp","event":"tools/call","tool":"harvest_list_projects","via":"oauth","ok":true,"email":"person@example.com","sub":"…","azp":"…"}
```

Static token ways log `query: true|false` and the user agent capped at 120 bytes instead of `email`/`sub`/`azp`.

## Transition from URL tokens

1. A server switches to the kit with `allowQueryToken: true` and keeps its static tokens.
2. When the call log shows seven days without `"query":true`, `allowQueryToken` goes in its own commit.
3. What stays: scoped tokens by header for automations without a person, and the emergency token by header (`via: "notzugang"`).

## Shared test cases

`fixtures/verify-cases.json` holds signed tokens with expected outcomes at a fixed clock. Other implementations (the Python agent template) run the same file and pin it by `fixtures/verify-cases.json.sha256`. Regenerate only on purpose with `npm run fixtures`.

## Release

A tag `v<version>` matching `package.json` publishes to npm with provenance (`.github/workflows/publish.yml`).

## License

MIT
