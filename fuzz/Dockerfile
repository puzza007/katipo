# Fuzzing toolchain for the katipo C port: clang 20 with libFuzzer and the
# sanitizers, AFL++, and the C libraries the port links against. Erlang is
# only needed for ei.h/libei.a and the seed-corpus escript.
FROM aflplusplus/aflplusplus:stable

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      erlang-dev erlang-base libcurl4-openssl-dev libevent-dev pkg-config && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /katipo
