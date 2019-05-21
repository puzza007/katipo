FROM ubuntu:19.04

MAINTAINER Paul Oliver

RUN apt-get -qq update \
    && apt-get -qq -y install wget gnupg \
    && wget https://packages.erlang-solutions.com/erlang-solutions_1.0_all.deb \
    && dpkg -i erlang-solutions_1.0_all.deb \
    && rm erlang-solutions_1.0_all.deb

RUN apt-get -qq update \
    && DEBIAN_FRONTEND=noninteractive \
       apt-get -qq -y install \
               libevent-dev \
               libcurl4-openssl-dev \
               erlang \
               make \
               curl \
               libssl-dev \
               gcc \
               docker \
    && rm -rf /var/lib/apt/lists/* \
    && curl --location https://github.com/erlang/rebar3/releases/download/3.10.0/rebar3 > /usr/local/bin/rebar3 \
    && chmod 755 /usr/local/bin/rebar3
