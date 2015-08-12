-module(get_handler).

-export([init/3]).
-export([handle/2]).
-export([terminate/3]).

init(_, Req, _) ->
    {ok, Req, no_state}.

handle(Req, State) ->
    Req2 = cowboy_req:reply(200, Req),
    {ok, Req2, State}.

terminate(_, _, _) ->
    ok.
