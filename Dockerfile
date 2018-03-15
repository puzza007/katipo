FROM puzza007/katipo_build

MAINTAINER Paul Oliver

COPY . /katipo

RUN cd /katipo && rebar3 update && rebar3 ct && rebar3 dialyzer
