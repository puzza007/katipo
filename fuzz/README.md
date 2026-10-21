# Fuzzing the C port

libFuzzer targets for `c_src/katipo.c`. Each target compiles the port
into itself (`fuzz_common.h`), so its static functions are reachable,
`main` is renamed out of the way and `errx` aborts: the pipe from Erlang
is trusted, so the targets only feed the port what Erlang could send,
and the port dying on that is a bug.

| Target | What it drives | Checked |
|---|---|---|
| `fuzz_headers` | `header_cb` + `encode_headers`, one call per header line | the encoded list matches a model: lines since the last status line, CR/LF/NUL replaced, trailers dropped |
| `fuzz_request` | `handle_frame` with requests, cancels and flow grants shaped as `katipo_worker` sends them | no `bad_opts` reply to a valid request; the in-flight list and stream windows match a model |

## Running

Everything runs in the `katipo-fuzz` image (`fuzz/Dockerfile`: clang 20,
AFL++, libcurl, libevent and ei). `fuzz/docker.sh` builds it on first use
and runs a command in it as you.

```sh
python3 fuzz/seeds/make_seeds.py          # seed fuzz/corpus/<target>/
fuzz/docker.sh fuzz/build.sh libfuzzer    # ASan + UBSan + libFuzzer
fuzz/docker.sh fuzz/out/libfuzzer/fuzz_headers -dict=fuzz/http.dict \
    -fork=8 fuzz/corpus/fuzz_headers
fuzz/docker.sh fuzz/out/libfuzzer/fuzz_request -rss_limit_mb=2048 \
    -fork=8 fuzz/corpus/fuzz_request
```

`build.sh` also builds `afl` and `cmplog` binaries for `afl-fuzz`,
`coverage` binaries for `llvm-cov`, and `replay` binaries that run saved
inputs (files or directories) without libFuzzer:

```sh
fuzz/docker.sh fuzz/build.sh replay
fuzz/docker.sh fuzz/out/replay/fuzz_request crash-<hash>
```

## Found so far

- Integer options of 2^31 or more were rejected by the port as
  `bad_opts` after passing validation (`fuzz_request`); now rejected in
  `katipo_req`.
- Large `update_flow/3` grants overflowed the stream window
  (`fuzz_request`, UBSan); now bounded in Erlang and saturated in C.

After both fixes, 10 hours of `-fork` runs (16 jobs on `fuzz_request`,
8 on `fuzz_headers`; 3.0 and 15.0 billion inputs) found nothing more.
The corpora reach `header_cb`, `encode_headers`, `handle_frame`,
`parse_eopts` and `new_conn`; the transfer callbacks (`write_cb`,
`check_multi_info`, the `send_*_to_erlang` replies), the socket
callbacks and the framing in `erl_input` are not reached by any target
yet.
