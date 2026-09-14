# DuckDuckGo Search MCP Server

[![PyPI version](https://img.shields.io/pypi/v/duckduckgo-mcp-server)](https://pypi.org/project/duckduckgo-mcp-server/)
[![PyPI downloads](https://img.shields.io/pypi/dm/duckduckgo-mcp-server)](https://pypi.org/project/duckduckgo-mcp-server/)
[![Python versions](https://img.shields.io/pypi/pyversions/duckduckgo-mcp-server)](https://pypi.org/project/duckduckgo-mcp-server/)

A Model Context Protocol (MCP) server that provides web search capabilities through DuckDuckGo, with additional features for content fetching and parsing.

## Quick Start

```bash
uvx duckduckgo-mcp-server
```

## Features

- **Web Search**: Search DuckDuckGo with advanced rate limiting and result formatting
- **Content Fetching**: Retrieve and parse webpage content with intelligent text extraction
- **Long URL Shortening**: Over-long result URLs become short `ref://` tokens that `fetch_content` accepts directly, saving context
- **Rate Limiting**: Built-in protection against rate limits for both search and content fetching, including a per-host cap
- **Untrusted-content fencing**: Web content is returned inside id-tagged blocks so a page cannot impersonate the server's own output
- **Hardened fetching**: Response size ceiling, content-type filtering, URL length cap, SSRF guard, and an optional token-only URL policy
- **Error Handling**: Comprehensive error handling and logging
- **LLM-Friendly Output**: Results formatted specifically for large language model consumption

## Installation

Install from PyPI using `uv`:

```bash
uv pip install duckduckgo-mcp-server
```

## Usage

### Running with Claude Desktop

1. Download [Claude Desktop](https://claude.ai/download)
2. Create or edit your Claude Desktop configuration:
   - On macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
   - On Windows: `%APPDATA%\Claude\claude_desktop_config.json`

Add the following configuration:

**Basic Configuration (No SafeSearch, No Default Region):**
```json
{
    "mcpServers": {
        "ddg-search": {
            "command": "uvx",
            "args": ["duckduckgo-mcp-server"]
        }
    }
}
```

**With SafeSearch and Region Configuration:**
```json
{
    "mcpServers": {
        "ddg-search": {
            "command": "uvx",
            "args": ["duckduckgo-mcp-server"],
            "env": {
                "DDG_SAFE_SEARCH": "STRICT",
                "DDG_REGION": "cn-zh"
            }
        }
    }
}
```

**Common options** (every setting is listed in [Configuration](#configuration)):
- `DDG_SAFE_SEARCH`: SafeSearch filtering level - `STRICT` (kp=1), `MODERATE` (kp=-1, default), or `OFF` (kp=-2).
- `DDG_REGION`: Default region/language code - e.g. `us-en`, `cn-zh`, `jp-ja`, or `wt-wt` for no region. Leave empty for DuckDuckGo's default.

3. Restart Claude Desktop

### Running with Claude Code

1. Download [Claude Code](https://github.com/anthropics/claude-code)
2. Ensure [`uvenv`](https://github.com/robinvandernoord/uvenv) is installed and the `uvx` command is available
3. Add the MCP server: `claude mcp add ddg-search uvx duckduckgo-mcp-server`

### Running with SSE or Streamable HTTP

The server supports alternative transports for use with other MCP clients:

```bash
# SSE transport
uvx duckduckgo-mcp-server --transport sse

# Streamable HTTP transport
uvx duckduckgo-mcp-server --transport streamable-http
```

The default transport is `stdio`, which is used by Claude Desktop and Claude Code.

When running with `sse` or `streamable-http`, override the default bind address (`127.0.0.1:8000`) with the `--host` and `--port` flags.

Binding to anything other than loopback **requires** an explicit `Host`/`Origin` allow-list — the server refuses to start otherwise. See [Running behind a reverse proxy or in Docker](#running-behind-a-reverse-proxy-or-in-docker) for why:

```bash
uvx duckduckgo-mcp-server --transport streamable-http --host 0.0.0.0 --port 7070 \
  --allowed-hosts ddg-mcp.example.com "ddg-mcp.example.com:*"
```

> **These transports have no authentication.** Anyone who can reach the port can run searches and fetch pages through this server. Bind to loopback unless you have put authentication in front of it.

#### Running behind a reverse proxy or in Docker

The MCP SDK auto-enables DNS-rebinding protection **only when the bind address is loopback** (`127.0.0.1`, `localhost`, `::1`), accepting `Host`/`Origin` headers for localhost. Behind a reverse proxy or in a container the client's `Host` header won't match, so requests fail with **`421 Misdirected Request`**.

For any other bind address the SDK applies *no* Host or Origin validation at all unless it is configured. That is why this server refuses to start on a non-loopback address without an allow-list — otherwise any website the user visits could drive the server over CORS.

Fix it by allow-listing the host(s) and origin(s) clients actually use (preferred over disabling protection). Values support `host`, `host:port`, and wildcard-port `host:*`:

```bash
uvx duckduckgo-mcp-server --transport streamable-http --host 0.0.0.0 --port 7070 \
  --allowed-hosts ddg-mcp.example.com "ddg-mcp.example.com:*" \
  --allowed-origins "https://ddg-mcp.example.com"
```

Equivalent environment variables (comma-separated) are also available: `DDG_ALLOWED_HOSTS`, `DDG_ALLOWED_ORIGINS`.

> **`--allowed-origins` on its own will not start.** The SDK validates `Host` before `Origin`, against an allow-list that would be empty - so an origins-only configuration answers `421` to *every* request, including from the origin you allow-listed. Always pass `--allowed-hosts` as well. (This applied to loopback binds too, since supplying any settings suppresses the SDK's localhost default.)

As a last resort you can turn the check off entirely with `--disable-dns-rebinding-protection` (or `DDG_DISABLE_DNS_REBINDING_PROTECTION=1`). Prefer an allow-list — disabling protection removes a defense against DNS-rebinding attacks.

On a loopback bind with nothing configured, the SDK's localhost-only default applies and no allow-list is needed. On any other bind you must pass an allow-list or explicitly disable the check; the server will not start silently unprotected.

CORS is scoped to `--allowed-origins`. When no origins are configured the CORS middleware is not installed at all, so browser pages cannot read this server's responses.

#### Running behind a TLS-intercepting proxy

Corporate proxies that re-sign HTTPS traffic with their own CA (via `HTTPS_PROXY`) cause outbound requests to fail with certificate verification errors, because the HTTP clients don't trust the proxy's self-signed CA (and httpx no longer reads the `SSL_CERT_FILE` environment variable). Point the server at your proxy's CA bundle:

```bash
uvx duckduckgo-mcp-server --ca-certs /path/to/proxy-ca.pem
```

Or set `DDG_CA_CERTS=/path/to/proxy-ca.pem`. The bundle is used by both the `search` and `fetch_content` tools, on the httpx and curl backends alike.

As a last resort, `--no-ssl-verify` (or `DDG_SSL_VERIFY=0`) disables certificate verification entirely. This exposes traffic to interception by anyone on the network path — prefer `--ca-certs`.

### Running in a container

The repo ships a `Dockerfile`, and CI publishes a multi-arch image to GHCR. Build it yourself:

```bash
podman build -t duckduckgo-mcp-server .
```

Or pull the published image:

```bash
podman pull ghcr.io/georgs-tumans/duckduckgo-mcp-server:latest
```

Swap `podman` for `docker` throughout if that is what you run.

#### Wiring it into an MCP client

A ready-to-copy config is in [`example.mcp.json`](example.mcp.json). Copy the `ddg-search` entry into your client's config - LM Studio's `mcp.json`, Claude Desktop's `claude_desktop_config.json`, or a project `.mcp.json`:

```json
{
  "mcpServers": {
    "ddg-search": {
      "command": "podman",
      "args": [
        "run", "-i", "--rm",
        "--read-only", "--tmpfs", "/tmp",
        "--cap-drop=ALL", "--security-opt=no-new-privileges",
        "--user", "1000:1000",
        "--memory=512m", "--pids-limit=128",
        "-e", "DDG_SAFE_SEARCH=MODERATE",
        "-e", "DDG_PARSE_MODE=markdown",
        "-e", "DDG_MAX_CONTENT_BYTES=5000000",
        "-e", "DDG_FETCH_HOST_RPM=6",
        "ghcr.io/georgs-tumans/duckduckgo-mcp-server:latest"
      ]
    }
  }
}
```

To use the stricter [token-only URL policy](#notes-on-the-security-settings), add `"-e", "DDG_FETCH_URL_POLICY=tokens"` - but read the tradeoff first: the model will no longer be able to follow links inside a page or fetch URLs you paste.

#### Two things that trip people up

**`-i` is required.** The server speaks MCP over stdio, so the container needs stdin held open. Without `-i` it appears to start and then hangs with no error.

**The `env` block does not reach the container.** In an `.mcp.json`, `env` sets variables for the `podman` process, not for the process inside the container. Either pass values inline in `args` as above, or forward them by bare name:

```json
"args": ["run", "-i", "--rm", "-e", "DDG_SAFE_SEARCH", "ghcr.io/georgs-tumans/duckduckgo-mcp-server:latest"],
"env": { "DDG_SAFE_SEARCH": "STRICT" }
```

A bare `-e NAME` (no `=`) forwards the value from the surrounding environment; `-e NAME=value` sets it directly and ignores the `env` block.

#### About the hardening flags

`--read-only`, `--cap-drop=ALL`, `--security-opt=no-new-privileges` and `--user 1000:1000` are ordinary least-privilege settings; the image is built to run fine under all of them, writing nothing outside `/tmp`.

`--memory=512m` is defence-in-depth for response size. The server already caps downloads at `DDG_MAX_CONTENT_BYTES`, but a memory ceiling means a pathological page gets the *container* OOM-killed rather than pressuring the host. The two are complementary. (On rootless Podman, memory limits need cgroups v2 delegation; if yours warns and ignores the flag, the in-process cap still applies.)

**The container is not an SSRF boundary.** Rootless Podman networking can still reach your LAN, so leave `DDG_ALLOW_PRIVATE_URLS` unset - the server's own guard is what keeps `fetch_content` away from internal addresses, not the container.

### Backends (bypassing bot detection)

Some sites — and, as of recently, DuckDuckGo's own search endpoint (`html.duckduckgo.com`) — block the default `httpx` client because of its distinctive TLS fingerprint, regardless of User-Agent. Cloudflare Bot Management and similar filters key on the JA3/TLS handshake, not on headers, so `html.duckduckgo.com` may answer `httpx` with an empty **HTTP 202** page (silently yielding "no results"). An opt-in backend, `curl` (implemented via `curl_cffi`), impersonates a real Chrome browser's TLS handshake and passes through those checks.

Both the `search` tool and the `fetch_content` tool support these backends.

**Installation:**

```bash
# Default install (httpx only)
uv pip install duckduckgo-mcp-server

# With the optional browser backend
uv pip install "duckduckgo-mcp-server[browser]"
```

**Backend options:**

| Value  | Behavior                                                                                  | Needs `[browser]` |
| ------ | ----------------------------------------------------------------------------------------- | ----------------- |
| `httpx` | Lightweight async HTTP. Default. Works on most sites.                                     | no                |
| `curl` | Uses `curl_cffi` with Chrome 131 TLS impersonation. Passes TLS-fingerprint-based filters. | yes               |
| `auto` | Tries `httpx` first; on 403 or a Cloudflare challenge response, retries with `curl`.      | yes               |

**Two ways to configure the backend:**

1. **Server-wide default** via the `--fetch-backend` CLI flag (applies to every `fetch_content` call):

   ```bash
   # Default behavior — uses httpx
   uvx duckduckgo-mcp-server

   # Force curl for every fetch (requires the [browser] extra)
   uvx --with "duckduckgo-mcp-server[browser]" duckduckgo-mcp-server --fetch-backend curl

   # Try httpx first, fall back to curl on 403 / Cloudflare challenge
   uvx --with "duckduckgo-mcp-server[browser]" duckduckgo-mcp-server --fetch-backend auto
   ```

2. **Per-call override** via the `backend` argument on the `fetch_content` tool (overrides the CLI default for that single call). The tool exposes `backend` in its input schema, so an MCP client can choose `"httpx"`, `"curl"`, or `"auto"` on a fetch-by-fetch basis.

For `fetch_content`, the default stays `httpx` so users who don't need the impersonation don't pay for the extra dependency.

#### Search backend

Because DuckDuckGo's search endpoint now fingerprint-blocks plain `httpx`, the `search` tool defaults to **`auto`**: it tries `httpx` first and falls back to `curl` when it detects a block (HTTP 202/403). The fallback only works if the `[browser]` extra is installed; otherwise search returns a message telling you to install it.

Configure the search backend with the `--search-backend` CLI flag or the `DDG_SEARCH_BACKEND` environment variable (`auto` (default) / `httpx` / `curl`):

```bash
# Recommended: install the browser extra so the auto fallback can impersonate Chrome
uvx --with "duckduckgo-mcp-server[browser]" duckduckgo-mcp-server

# Force curl for every search
uvx --with "duckduckgo-mcp-server[browser]" duckduckgo-mcp-server --search-backend curl

# Opt out of the fallback (legacy behavior — may return no results while blocked)
uvx duckduckgo-mcp-server --search-backend httpx
```

### Development

For local development:

```bash
# Install dependencies
uv sync

# Run with the MCP Inspector
mcp dev src/duckduckgo_mcp_server/server.py

# Install locally for testing with Claude Desktop
mcp install src/duckduckgo_mcp_server/server.py

# Run all tests
uv run python -m pytest src/duckduckgo_mcp_server/ -v

# Run only unit tests
uv run python -m pytest src/duckduckgo_mcp_server/test_server.py -v

# Run only e2e tests
uv run python -m pytest src/duckduckgo_mcp_server/test_e2e.py -v
```

## Configuration

Every setting can be supplied as an environment variable - the usual way to configure an MCP server, via the `env` block in your client config. Most also have a CLI flag, and **a CLI flag overrides the environment variable**; where the table shows `-` in the flag column, the environment variable is the only way to set it.

### Search

| Environment variable | CLI flag | Default | What it does |
| --- | --- | --- | --- |
| `DDG_SAFE_SEARCH` | - | `MODERATE` | SafeSearch level: `STRICT`, `MODERATE`, `OFF`. |
| `DDG_REGION` | - | none | Default region/language, e.g. `us-en`, `de-de`, `jp-ja`, `wt-wt` for none. |
| `DDG_SEARCH_BACKEND` | `--search-backend` | `auto` | HTTP backend for search: `httpx`, `curl`, `auto`. `curl` and the `auto` fallback need the `[browser]` extra. |
| `DDG_SEARCH_RPM` | `--search-rpm` | `30` | Search requests per minute. |
| `DDG_REF_URL_THRESHOLD` | `--ref-url-threshold` | `120` | Result URLs longer than this become `ref://` tokens. `0` always shows full URLs. |

### Fetching pages

| Environment variable | CLI flag | Default | What it does |
| --- | --- | --- | --- |
| `DDG_FETCH_BACKEND` | `--fetch-backend` | `httpx` | HTTP backend for `fetch_content`: `httpx`, `curl`, `auto`. |
| `DDG_PARSE_MODE` | `--parse-mode` | `text` | Default extractor: `text`, `main`, `markdown`. A per-call `parse_mode` overrides it. |
| `DDG_FETCH_RPM` | `--fetch-rpm` | `20` | Global fetch requests per minute. |
| `DDG_FETCH_HOST_RPM` | `--fetch-host-rpm` | `6` | Per-host fetch cap, so one site cannot spend the whole budget. `0` disables. |
| `DDG_RATE_LIMIT_STRATEGY` | `--rate-limit-strategy` | `sliding` | `sliding` (60s window) or `token_bucket` (burst, then smooth). |
| `DDG_CACHE_TTL` | `--cache-ttl` | `300` | Seconds a parsed page stays cached, so paginated reads reuse one download. `0` disables. |
| `DDG_CACHE_MAX_ENTRIES` | `--cache-max-entries` | `64` | Maximum cached pages (LRU). `0` disables. |
| `DDG_CACHE_MAX_BYTES` | `--cache-max-bytes` | `16000000` | Total size budget for cached text, so a few huge pages cannot dominate memory. `0` disables. |

### Security

| Environment variable | CLI flag | Default | What it does |
| --- | --- | --- | --- |
| `DDG_MAX_CONTENT_BYTES` | `--max-content-bytes` | `5000000` | Bytes read from one response before the rest is dropped. `0` for no limit. |
| `DDG_MAX_URL_LENGTH` | `--max-url-length` | `2048` | Refuse URLs longer than this, redirect targets included. `0` disables. |
| `DDG_FETCH_URL_POLICY` | `--fetch-url-policy` | `any` | `any` allows any public http(s) URL. `tokens` accepts only `ref://` tokens this server issued. See below. |
| `DDG_CONTENT_ENVELOPE` | `--content-envelope` | `on` | Wrap web content in id-tagged `<untrusted-content>` blocks so it cannot impersonate the server's own output. |
| `DDG_ALLOW_PRIVATE_URLS` | `--allow-private-urls` | off | Allow `fetch_content` to reach loopback/private/link-local/metadata addresses. Leave off unless you trust the caller. |
| `DDG_SSL_VERIFY` | `--no-ssl-verify` | `1` | Set `0` to disable TLS verification entirely. Discouraged; prefer `DDG_CA_CERTS`. |
| `DDG_CA_CERTS` | `--ca-certs` | none | PEM CA bundle for outbound TLS, for TLS-intercepting proxies. |

### HTTP transports only (`--transport sse` / `streamable-http`)

These do nothing under the default `stdio` transport.

| Environment variable | CLI flag | Default | What it does |
| --- | --- | --- | --- |
| `DDG_ALLOWED_HOSTS` | `--allowed-hosts` | none | Allowed `Host` values. Accepts `host`, `host:port`, `host:*`. |
| `DDG_ALLOWED_ORIGINS` | `--allowed-origins` | none | Allowed `Origin` values. **Requires `DDG_ALLOWED_HOSTS` too** (see below). Also scopes CORS; with none set, CORS is not enabled at all. Wildcard-port values are honoured for CORS as well as Host. |
| `DDG_DISABLE_DNS_REBINDING_PROTECTION` | `--disable-dns-rebinding-protection` | off | Turn Host/Origin validation off entirely. Prefer an allow-list. |
| - | `--host` / `--port` | `127.0.0.1` / `8000` | Bind address. **A non-loopback bind requires an allow-list or the server refuses to start** - see [Running behind a reverse proxy or in Docker](#running-behind-a-reverse-proxy-or-in-docker). |

### Notes on the security settings

**`DDG_FETCH_URL_POLICY=tokens` has a real usability cost.** Under `tokens`, `fetch_content` accepts only `ref://` tokens that this server issued from its own search results. That means the model **cannot follow a link it found inside a fetched page**, and **cannot fetch a URL you pasted into the chat**. Only results from its own searches are reachable.

That restriction is the point. The way an injected instruction gets data out of a model's context is by building a URL containing it (`https://attacker.example/?d=<secret>`). Tokens are issued *before* any secret is known, so the model holds opaque handles with no field to encode data into. A residual channel remains - an attacker can pre-place many links and signal roughly a byte per fetch by which one is chosen - so this narrows the channel by orders of magnitude rather than proving it closed. `DDG_MAX_URL_LENGTH` and `DDG_FETCH_HOST_RPM` constrain what is left.

**What `tokens` does not cover.** It restricts `fetch_content` URLs only. The `search` tool still takes a free-form query, so an injected instruction could ask the model to search for a secret and that text would reach DuckDuckGo. That is a far weaker channel than an attacker-chosen URL - the data goes to DuckDuckGo, who the attacker cannot query for it - but it is not closed, and this setting should not be read as "no data can leave".

Use `tokens` when this server shares an agent with tools that hold secrets. Leave it at `any` for ordinary browsing where you want to paste URLs.

**Hidden-text stripping has a known limit.** Content hidden by inline `style` attributes (`display:none`, `visibility:hidden`, `opacity:0`, off-screen positioning), `hidden`/`aria-hidden` elements, `<template>`, `<noscript>`, HTML comments, and zero-width/bidi characters is removed in every parse mode. Text hidden by an *external stylesheet or a `<style>` block* - true white-on-white - is **not** detected; that needs full CSS cascade resolution and is out of scope.

**The HTTP transports have no authentication.** Anyone who can reach the port can search and fetch through this server. Bind to loopback unless you have put authentication in front of it.

**`DDG_FETCH_HOST_RPM` defaults to `6`, not off.** Upstream defaults this to `0` (disabled); this fork enables it because it throttles the exfiltration channel described above. Set it to `0` for the upstream behaviour.

## Available Tools

### 1. Search Tool

```python
async def search(query: str, max_results: int = 10, region: str = "") -> str
```

Performs a web search on DuckDuckGo and returns formatted results.

**Parameters:**
- `query`: Search query string
- `max_results`: Maximum number of results to return (default: 10)
- `region`: (Optional) Region/language code to override the default. Leave empty to use the configured default region.

**Region Code Examples:**
- `us-en`: United States (English)
- `cn-zh`: China (Chinese)
- `jp-ja`: Japan (Japanese)
- `de-de`: Germany (German)
- `fr-fr`: France (French)
- `wt-wt`: No specific region

**Returns:**
Formatted string containing search results with titles, URLs, and snippets.

**Example Usage:**
- Search with default settings: `search("python tutorial")`
- Search with specific region: `search("latest news", region="jp-ja")` for Japanese news

### 2. Content Fetching Tool

```python
async def fetch_content(
    url: str,
    start_index: int = 0,
    max_length: int = 8000,
    backend: Optional[str] = None,
    parse_mode: Optional[str] = None,
) -> str
```

Fetches and parses content from a webpage.

**Parameters:**
- `url`: The webpage URL to fetch content from, or a `ref://<id>` token from search results
- `start_index`: Character offset to start reading from (for pagination)
- `max_length`: Maximum number of characters to return
- `backend`: Optional per-call override of the default fetch backend (`"httpx"`, `"curl"`, or `"auto"`). When omitted, uses whatever was set via `--fetch-backend` at server startup.
- `parse_mode`: Optional per-call extractor (`"text"`, `"main"`, or `"markdown"`). When omitted, uses `DDG_PARSE_MODE` / `--parse-mode` (default `text`).

**Returns:**
Cleaned and formatted text content from the webpage. The parsed full page is cached in memory (default 5 minutes) so later pages via `start_index` do not re-download. Metadata includes `cache=hit` or `cache=miss` when the cache is enabled.

> **SSRF protection:** By default `fetch_content` refuses URLs that resolve to
> loopback, private (RFC1918), link-local (including the `169.254.169.254` cloud
> metadata endpoint), reserved, multicast, or unspecified addresses, and it
> re-validates every redirect hop. Only `http`/`https` URLs are allowed. For
> trusted local deployments that need to fetch internal hosts, disable the guard
> with `DDG_ALLOW_PRIVATE_URLS=1` or `--allow-private-urls`. See
> [SECURITY.md](SECURITY.md) for details.

### 3. Link Expansion Tool

```python
async def expand_link(token: str) -> str
```

Search results replace URLs longer than `DDG_REF_URL_THRESHOLD` characters (default 120) with short, stable `ref://<id>` tokens so long tracking-laden links do not eat context. `fetch_content` accepts a token in place of a URL, so the model only needs this tool when it has to show or cite the real link.

**Parameters:**
- `token`: A `ref://<id>` token exactly as it appeared in search results (the bare id also works)

**Returns:**
The full original URL, or an error if the token is unknown. Tokens live in memory for the lifetime of the server process (bounded by an LRU cap), so they are forgotten on restart.

## Features in Detail

### Rate Limiting

- Search: 30 requests per minute by default (`DDG_SEARCH_RPM` / `--search-rpm`)
- Content fetching: 20 requests per minute globally (`DDG_FETCH_RPM` / `--fetch-rpm`)
- Per-host fetch cap, 6 per minute by default (`DDG_FETCH_HOST_RPM` / `--fetch-host-rpm`; `0` disables)
- Strategies: `sliding` (default) or `token_bucket` via `DDG_RATE_LIMIT_STRATEGY` / `--rate-limit-strategy`
- HTTP 429 responses honor `Retry-After` (capped at 30s) and retry once
- Cache hits on `fetch_content` skip both the download and the fetch rate limiter

### Content cache

- In-memory TTL cache of the fully parsed page (before pagination)
- Default TTL 300 seconds, 64 entries, least-recently-used eviction
- Also bounded by total size (`DDG_CACHE_MAX_BYTES`, default 16 MB) so a few very large pages cannot dominate memory
- Errors are never cached
- Configure with `DDG_CACHE_TTL` / `DDG_CACHE_MAX_ENTRIES` / `DDG_CACHE_MAX_BYTES` or the matching flags
- Set any of them to `0` to disable that limit

### Result Processing

- Removes ads and irrelevant content
- Cleans up DuckDuckGo redirect URLs
- Formats results for optimal LLM consumption
- Truncates long content appropriately

### Content parsing modes

`fetch_content` accepts `parse_mode`:

| Mode | Behavior |
| --- | --- |
| `text` | Historical default. Strip chrome, return flattened page text. |
| `main` | Keep the primary `article` / `main` / content container only. |
| `markdown` | Same primary content, rendered as lightweight markdown (headings, lists, links, code). |

### Content Safety

- **Untrusted-content envelope**: search results and fetched pages are returned inside `<untrusted-content id="...">` blocks with a random per-call id. Anything outside the matching closing tag - such as the `[Content info: ...]` footer - comes from this server and cannot be forged by a page. Disable with `DDG_CONTENT_ENVELOPE=off`.
- **Hidden-text stripping**: HTML comments, `<template>`/`<noscript>`, `hidden`/`aria-hidden` elements, inline-styled invisible elements, and zero-width/bidi characters are removed in every parse mode. See the limit noted under [Configuration](#notes-on-the-security-settings).
- **Download limits**: responses are streamed and abandoned past `DDG_MAX_CONTENT_BYTES`, oversized `Content-Length` is refused up front, and non-text content types are not parsed.
- **SSRF guard**: `fetch_content` refuses loopback, private, link-local, and cloud-metadata addresses by default, revalidating every redirect hop.

- **SafeSearch Filtering**: Configured at server startup via `DDG_SAFE_SEARCH` environment variable
  - Controlled by administrators, not modifiable by AI assistants
  - Filters inappropriate content based on the selected level
  - Uses DuckDuckGo's official `kp` parameter

- **Region Localization**:
  - Default region set via `DDG_REGION` environment variable
  - Can be overridden per search request by AI assistants
  - Improves result relevance for specific geographic regions

### Error Handling

- Comprehensive error catching and reporting
- Detailed logging through MCP context
- Graceful degradation on rate limits or timeouts

## Contributing

Issues and pull requests are welcome!

## License

This project is licensed under the MIT License.

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=nickclyde/duckduckgo-mcp-server&type=Date)](https://star-history.com/#nickclyde/duckduckgo-mcp-server&Date)
