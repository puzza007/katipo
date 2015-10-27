-module(katipo_session).

-export([new/0]).
-export([new/1]).
-export([update/2]).
-export([req/2]).

-record(state, {opts = #{} :: katipo:request()}).

-opaque session() :: #state{}.

-export_type([session/0]).

-spec new() -> session().
new() ->
    new(#{}).

-spec new(katipo:request()) -> session().
new(Opts) when is_map(Opts) ->
    #state{opts = Opts}.

-spec update(katipo:request(), session()) -> session().
update(Opts, State=#state{}) when is_map(Opts) ->
    Opts2 = merge(State#state.opts, Opts),
    State#state{opts=Opts2}.

-spec req(katipo:request(), session()) -> {katipo:response(), session()}.
req(Req, State=#state{opts=Opts}) when is_map(Req) ->
    Req2 = merge(Opts, Req),
    Res = katipo:req(Req2),
    Opts2 = case Res of
                {ok, #{cookiejar := CookieJar}} ->
                    Opts#{cookiejar => CookieJar};
                {error, #{}} ->
                    Opts
            end,
    {Res, State#state{opts=Opts2}}.

merge(Opts, Req) when is_map(Req) andalso is_map(Opts) ->
    Merged = maps:merge(Opts, Req),
    case maps:get(headers, Req, undefined) of
        undefined ->
            Merged;
        ReqHeaders ->
            OptsHeaders = maps:get(headers, Opts, []),
            MergedHeaders = merge_headers(OptsHeaders, ReqHeaders),
            Merged#{headers => MergedHeaders}
    end.

merge_headers(OptsHeaders, ReqHeaders) ->
    merge_headers(OptsHeaders, ReqHeaders, OptsHeaders).

merge_headers(_, [], Merged) ->
    Merged;
merge_headers(OptsHeaders, [{K, _V}=H|Rest], Merged) ->
    Merged2 = lists:keyreplace(K, 1, Merged, H),
    merge_headers(OptsHeaders, Rest, Merged2).
