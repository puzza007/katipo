# HTTP/3 httpbin Test Server

This directory contains a docker-compose setup for running a local httpbin server with HTTP/3 support using Caddy as a reverse proxy.

## Quick Start

```bash
cd test/http3-httpbin
docker-compose up -d
```

The server will be available at `https://localhost:8443`

## Testing HTTP/3

Test with curl (requires HTTP/3 support, e.g., homebrew curl on macOS):

```bash
# Test HTTP/3
/opt/homebrew/opt/curl/bin/curl --http3 -k https://localhost:8443/get

# Test HTTP/2 (fallback)
curl --http2 -k https://localhost:8443/get

# Test HTTP/1.1
curl --http1.1 -k https://localhost:8443/get

# Verify HTTP/3 is being used
/opt/homebrew/opt/curl/bin/curl --http3 -k -s https://localhost:8443/status/200 -w "\nHTTP Version: %{http_version}\n"
```

## Running Katipo Tests

The test suite expects httpbin to be running at `https://localhost:8443`.

### Run all tests (HTTP/1.1 and HTTP/2)

```bash
rebar3 ct
```

### Run with HTTP/3 tests

HTTP/3 tests require curl built with HTTP/3 support (ngtcp2/nghttp3 or quiche).
Set `KATIPO_TEST_HTTP3` to enable the HTTP/3 test group:

```bash
KATIPO_TEST_HTTP3=true rebar3 ct
```

## Stopping

```bash
docker-compose down
```

## Architecture

- **Caddy** (port 8443): HTTP/3-capable reverse proxy with auto-generated TLS certificates
- **httpbin** (internal port 80): Python httpbin API server with WSGI wrapper

Caddy automatically:
- Enables HTTP/3 (QUIC) on UDP port 443 (mapped to 8443)
- Generates self-signed TLS certificates for localhost
- Proxies requests to the httpbin backend
