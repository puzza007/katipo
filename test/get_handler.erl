-module(get_handler).

-export([init/2]).

init(Req, Opts) ->
    Req2 = cowboy_req:reply(200, Req),
    {ok, Req2, Opts}.
