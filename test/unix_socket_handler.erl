-module(unix_socket_handler).

-export([init/2]).

init(Req0, Opts) ->
    Method = cowboy_req:method(Req0),
    Req = echo(Method, Req0),
    {ok, Req, Opts}.

echo(<<"GET">>, Req) ->
    cowboy_req:reply(
      200,
      #{<<"content-type">> => <<"text/plain; charset=utf-8">>},
      <<"unix domain">>,
      Req).
