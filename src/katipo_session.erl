-module(katipo_session).

-export([new/1]).
-export([new/2]).
-export([update/2]).
-export([req/2]).

-record(state, {pool_name :: katipo_pool:name(),
                opts = #{} :: katipo:request()}).

-opaque session() :: #state{}.

-type session_result() :: {ok, session()} | {error, map()}.

-export_type([session/0]).
-export_type([session_result/0]).

-spec new(katipo_pool:name()) -> session_result().
new(PoolName) ->
    new(PoolName, #{}).

-spec new(katipo_pool:name(), katipo:request()) -> session_result().
new(PoolName, Opts) when is_atom(PoolName) andalso is_map(Opts) ->
    State = #state{pool_name=PoolName, opts = Opts},
    check_opts(State).

-spec update(katipo:request(), session()) -> session_result().
update(Opts, State=#state{}) ->
    Opts2 = merge(State#state.opts, Opts),
    State2 = State#state{opts=Opts2},
    check_opts(State2).

check_opts(State=#state{opts=Opts}) ->
    case katipo:check_opts(Opts) of
        ok ->
            {ok, State};
        {error, _} = Error ->
            Error
    end.

-spec req(katipo:request(), session()) -> {katipo:response(), session()}.
req(Req, State=#state{pool_name=PoolName, opts=Opts}) when is_map(Req) ->
    Req2 = merge(Opts, Req),
    Res = katipo:req(PoolName, Req2),
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
