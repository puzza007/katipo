# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Katipo is an HTTP/HTTP2 client library for Erlang built around libcurl-multi and libevent. It provides high-performance HTTP client capabilities with connection pooling, pipelining, and multiplexing support.

**Version 2.0.0** introduces breaking changes that modernize observability by replacing the old metrics system with telemetry events compatible with OpenTelemetry.

## Development Commands

### Building
```bash
# Fetch dependencies and compile
rebar3 compile

# The C native extension will be automatically compiled via make hooks
```

### Testing
```bash
# Run all tests
rebar3 ct

# Run a specific test suite
rebar3 ct --suite=katipo_SUITE

# Run tests with coverage
rebar3 cover
```

### Code Quality
```bash
# Run linting
rebar3 lint

# Run dialyzer (static analysis)
rebar3 dialyzer

# Check for undefined functions
rebar3 xref
```

### Documentation
```bash
# Generate documentation
rebar3 edoc
```

### Interactive Shell
```bash
# Start an Erlang shell with katipo loaded
rebar3 shell
```

## Architecture Overview

### Core Structure
- **Erlang Application** (`src/`): Main Erlang/OTP application implementing the HTTP client API
- **Native Extension** (`c_src/`): C code that interfaces with libcurl-multi and libevent for high-performance networking
- **Connection Pooling**: Built on `worker_pool` library for efficient connection management
- **Telemetry Integration**: Emits telemetry events for metrics and observability with detailed timing data from libcurl

### Dependencies
- `worker_pool` (6.0.1) - Connection pooling and worker management
- `telemetry` (~1.0) - Event emission for metrics and observability

### Key Components
1. **katipo.erl**: Main API module providing HTTP methods (get, post, put, head, options)
2. **katipo_pool.erl**: Pool management for connection handling
3. **katipo_worker.erl**: Worker processes that interact with the C port
4. **katipo_telemetry.erl**: Telemetry events for metrics and observability
5. **katipo.c**: Native C extension using libcurl-multi and libevent

### Request Flow
1. Client calls `katipo:Method/3` or `katipo:req/2`
2. Request is dispatched to a worker from the pool
3. Worker communicates with C port via Erlang port protocol
4. C code uses libcurl-multi for actual HTTP operations and collects timing metrics
5. Response is parsed and returned to the client
6. Telemetry events are emitted with detailed timing metrics and metadata

### Telemetry Events

**Events Emitted:**
- `[katipo, request, stop]` - Successful/completed HTTP requests
- `[katipo, request, error]` - Failed HTTP requests

**Timing Measurements** (all in milliseconds):
- `duration` - Total request duration (includes Erlang overhead)
- `namelookup_time` - DNS lookup time
- `connect_time` - TCP connection establishment time
- `appconnect_time` - SSL/TLS handshake time (HTTPS only)
- `pretransfer_time` - Time until transfer starts
- `redirect_time` - Time spent on redirects
- `starttransfer_time` - Time until first byte received
- `response_body_size` - Size of response body in bytes

**Metadata Included:**
- `method` - HTTP method (get, post, etc.)
- `url` - Request URL
- `status` - HTTP status code (success only)
- `error` - Error code (failures only)
- `scheme` - URL scheme (http/https)
- `host` - Server hostname
- `port` - Server port (if specified)

### Configuration Detection
The build system uses `rebar.config.script` to detect the installed libcurl version and conditionally enable features based on availability.

## System Dependencies

Before developing, ensure these are installed:
- libevent-dev
- libcurl4-openssl-dev
- make
- curl
- libssl-dev
- gcc

## Breaking Changes (v2.0.0)

**Removed:**
- `mod_metrics` application configuration option
- `return_metrics` request option
- `metrics` dependency (folsom/exometer support)
- Metrics data in response maps

**Added:**
- Telemetry events with richer data
- OpenTelemetry-compatible semantic conventions
- Real-time event emission (no need to poll responses)

## Migration Guide

**Before (v1.x):**
```erlang
{ok, #{status := 200, metrics := Metrics}} =
    katipo:get(Pool, URL, #{return_metrics => true}).
```

**After (v2.x):**
```erlang
telemetry:attach(handler_id, [katipo, request, stop],
    fun(Event, Measurements, Metadata, Config) ->
        % All timing data available in Measurements
        % Additional metadata in Metadata
    end, undefined).
```

## Important Notes

- Minimum OTP version: 23.0
- The project uses rebar3 as its build tool
- C compilation is handled automatically via pre/post hooks in rebar.config
- HTTP pipelining modes: `nothing`, `http1`, or `multiplex`
- All curl options are mapped to Erlang-friendly atoms/values
- Telemetry events are emitted for all HTTP requests with detailed timing metrics from libcurl
- See `examples/telemetry_opentelemetry.erl` for OpenTelemetry integration
- Tests include both unit tests (`katipo_telemetry_SUITE`) and integration tests (`katipo_SUITE` telemetry group)