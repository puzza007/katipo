FROM puzza007/katipo_build

MAINTAINER Paul Oliver

COPY . /katipo

RUN cd /katipo && make update test dialyzer
