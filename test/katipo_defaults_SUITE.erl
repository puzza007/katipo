-module(katipo_defaults_SUITE).

%% A pool's default request options (katipo_pool's `defaults'): how they
%% merge into requests, and that they live exactly as long as the pool.
%% Requests go to katipo_script_server, which reports what it received. No
%% httpbin server is required.

-export([all/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([end_per_testcase/2]).

-export([relative_url_joins_base/1]).
-export([absolute_url_stands/1]).
-export([base_url_alone/1]).
-export([headers_merge/1]).
-export([option_wins/1]).
-export([async_gets_defaults/1]).
-export([bad_defaults/1]).
-export([gone_after_stop/1]).
-export([kept_across_pool_restart/1]).
-export([refuses_other_generations/1]).
-export([unresolvable_url/1]).
-export([credentials_stay_on_origin/1]).
-export([no_pool/1]).
-export([header_error_position/1]).
-export([hidden_from_status/1]).
-export([default_retry_skips_streams/1]).
-export([served_after_rebuild/1]).
-export([default_url_joins_base/1]).
-export([tls_identity_stays_on_origin/1]).
-export([old_worker_upgraded/1]).

-include_lib("common_test/include/ct.hrl").
-include("../src/katipo_internal.hrl").

-define(WAIT, 5000).

all() ->
    [relative_url_joins_base, absolute_url_stands, base_url_alone, headers_merge,
     option_wins, async_gets_defaults, bad_defaults, gone_after_stop,
     kept_across_pool_restart, refuses_other_generations, unresolvable_url,
     credentials_stay_on_origin, no_pool, header_error_position, hidden_from_status,
     default_retry_skips_streams, served_after_rebuild, default_url_joins_base,
     tls_identity_stays_on_origin, old_worker_upgraded].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(katipo),
    Config.

end_per_suite(Config) ->
    Config.

end_per_testcase(TestCase, _Config) ->
    [katipo_script_server:stop(S) || S <- get_servers()],
    ok = katipo_pool:stop(TestCase).

relative_url_joins_base(_Config) ->
    {Server, Base} = server(<<"v1/">>),
    {ok, _} = katipo_pool:start(?FUNCTION_NAME, 1, [{defaults, #{base_url => Base}}]),
    {ok, #{status := 200}} = katipo:get(?FUNCTION_NAME, <<"items?a=1">>),
    <<"GET /v1/items?a=1 ", _/binary>> = head(Server),
    {ok, #{status := 200}} = katipo:get(?FUNCTION_NAME, <<"/top">>),
    <<"GET /top ", _/binary>> = head(Server),
    %% A query uri_string rejects but curl sends is kept as given.
    {ok, #{status := 200}} = katipo:get(?FUNCTION_NAME, <<"items?filter[s]=x">>),
    <<"GET /v1/items?filter[s]=x ", _/binary>> = head(Server).

absolute_url_stands(_Config) ->
    {_A, Base} = server(<<>>),
    {B, UrlB} = server(<<"b">>),
    {ok, _} = katipo_pool:start(?FUNCTION_NAME, 1, [{defaults, #{base_url => Base}}]),
    {ok, #{status := 200}} = katipo:get(?FUNCTION_NAME, UrlB),
    <<"GET /b ", _/binary>> = head(B),
    {ok, #{status := 200}} = katipo:get(?FUNCTION_NAME, <<UrlB/binary, "?f[a]=1">>),
    <<"GET /b?f[a]=1 ", _/binary>> = head(B).

base_url_alone(_Config) ->
    {Server, Base} = server(<<"only">>),
    {ok, _} = katipo_pool:start(?FUNCTION_NAME, 1, [{defaults, #{base_url => Base}}]),
    {ok, #{status := 200}} = katipo:req(?FUNCTION_NAME, #{}),
    <<"GET /only ", _/binary>> = head(Server).

%% A request header replaces a default one of the same name, in any case;
%% the other defaults go too.
headers_merge(_Config) ->
    {Server, Base} = server(<<>>),
    Defaults = #{base_url => Base,
                 headers => [{<<"X-A">>, <<"1">>}, {<<"X-B">>, <<"2">>}]},
    {ok, _} = katipo_pool:start(?FUNCTION_NAME, 1, [{defaults, Defaults}]),
    {ok, #{status := 200}} =
        katipo:get(?FUNCTION_NAME, <<"/">>, #{headers => [{<<"x-b">>, <<"3">>}]}),
    Head = head(Server),
    {match, _} = re:run(Head, <<"\r\nX-A: 1(\r\n|$)">>),
    {match, _} = re:run(Head, <<"\r\nx-b: 3(\r\n|$)">>),
    nomatch = re:run(Head, <<"X-B: 2">>),
    {ok, #{status := 200}} = katipo:get(?FUNCTION_NAME, <<"/">>),
    {match, _} = re:run(head(Server), <<"\r\nX-B: 2(\r\n|$)">>).

%% A default method applies where a request gives none, and loses to one it
%% gives.
option_wins(_Config) ->
    {Server, Base} = server(<<>>),
    {ok, _} = katipo_pool:start(?FUNCTION_NAME, 1,
                                [{defaults, #{base_url => Base, method => options}}]),
    {ok, #{status := 200}} = katipo:req(?FUNCTION_NAME, #{url => <<"/">>}),
    <<"OPTIONS / ", _/binary>> = head(Server),
    {ok, #{status := 200}} = katipo:req(?FUNCTION_NAME, #{url => <<"/">>, method => get}),
    <<"GET / ", _/binary>> = head(Server).

async_gets_defaults(_Config) ->
    {Server, Base} = server(<<"v1/">>),
    {ok, _} = katipo_pool:start(?FUNCTION_NAME, 1, [{defaults, #{base_url => Base}}]),
    {ok, Ref} = katipo:async_get(?FUNCTION_NAME, <<"items">>),
    {ok, #{status := 200}} = katipo:await(Ref, ?WAIT),
    <<"GET /v1/items ", _/binary>> = head(Server).

%% Bad defaults fail the start, naming all that is wrong, and leave nothing.
bad_defaults(_Config) ->
    [begin
         {error, #{code := bad_opts, message := Message}} =
             katipo_pool:start(?FUNCTION_NAME, 1, [{defaults, D}]),
         [{match, _} = re:run(Message, N) || N <- Named],
         undefined = whereis(?FUNCTION_NAME)
     end
     || {D, Named} <- [{#{base_url => <<"/relative">>}, [<<"base_url">>]},
                       {#{base_url => <<"https:///v1/">>}, [<<"base_url">>]},
                       {#{base_url => <<"ftp://h/">>}, [<<"base_url">>]},
                       {#{base_url => <<"https://h:99999/">>}, [<<"base_url">>]},
                       {#{base_url => <<"https://h/%zz">>}, [<<"base_url">>]},
                       {#{base_url => <<"https://h/?q=1">>}, [<<"base_url">>]},
                       {#{base_url => "http://a.example/"}, [<<"base_url">>]},
                       {#{base_url => <<"/r">>, timeout_ms => 0},
                        [<<"base_url">>, <<"timeout_ms">>]},
                       %% Options that would break every synchronous request.
                       {#{stream => true, reply_to => self(), stream_window => 1,
                          body => <<"b">>},
                        [<<"stream,">>, <<"reply_to">>, <<"stream_window">>, <<"body">>]},
                       {not_a_map, [<<"defaults">>]}]].

%% Stopping the pool takes its defaults: a request then finds no pool, and a
%% pool started again under the name has its own.
gone_after_stop(_Config) ->
    {Server, Base} = server(<<"first">>),
    {ok, _} = katipo_pool:start(?FUNCTION_NAME, 1, [{defaults, #{base_url => Base}}]),
    ok = katipo_pool:stop(?FUNCTION_NAME),
    {'EXIT', no_workers} = (catch katipo:req(?FUNCTION_NAME, #{})),
    {ok, _} = katipo_pool:start(?FUNCTION_NAME, 1,
                                [{defaults, #{base_url => <<Base/binary, "/again">>}}]),
    {ok, #{status := 200}} = katipo:req(?FUNCTION_NAME, #{}),
    <<"GET /first/again ", _/binary>> = head(Server).

%% A pool whose workers crash past its restart intensity is restarted by
%% wpool from the same options, so with the same defaults and generation.
kept_across_pool_restart(_Config) ->
    {Server, Base} = server(<<"kept">>),
    {ok, Wpool} = katipo_pool:start(?FUNCTION_NAME, 1, [{defaults, #{base_url => Base}}]),
    wait_for(fun() -> whereis(?FUNCTION_NAME) =/= Wpool orelse crash_worker(?FUNCTION_NAME) end),
    wait_for(fun() -> is_pid(whereis(?FUNCTION_NAME)) andalso worker_up(?FUNCTION_NAME) end),
    {ok, #{status := 200}} = katipo:req(?FUNCTION_NAME, #{}),
    <<"GET /kept ", _/binary>> = head(Server).

crash_worker(Pool) ->
    case catch wpool:get_workers(Pool) of
        [W] when is_atom(W) ->
            case whereis(W) of
                undefined -> ok;
                Pid -> exit(Pid, kill)
            end,
            false;
        _ -> false
    end.

worker_up(Pool) ->
    case catch wpool:get_workers(Pool) of
        [W] -> is_pid(whereis(W));
        _ -> false
    end.

%% A request read from another pool with the name carries that pool's
%% generation, and one with options wpool rebuilt carries none: a worker
%% refuses both, so a request never runs without its own pool's defaults.
%% Sent to the worker by hand, as a caller racing a stop and a start would.
refuses_other_generations(_Config) ->
    {Server, Base} = server(<<>>),
    {ok, _} = katipo_pool:start(?FUNCTION_NAME, 1, [{defaults, #{base_url => Base}}]),
    {ok, Req} = katipo_req:build_req(#{url => Base}, sync),
    [Worker] = wpool:get_workers(?FUNCTION_NAME),
    [stale = gen_server:call(Worker, Req#req{gen = G}) || G <- [undefined, make_ref()]],
    {ok, #{status := 200}} = katipo:req(?FUNCTION_NAME, #{}),
    _ = head(Server).

%% A relative path is resolved whatever bytes it holds, and sent as the
%% absolute url it resolves to would be.
unresolvable_url(_Config) ->
    {Server, Base} = server(<<"v1/">>),
    {ok, _} = katipo_pool:start(?FUNCTION_NAME, 1, [{defaults, #{base_url => Base}}]),
    Line = fun(Url) ->
                   {ok, #{status := 200}} = katipo:get(?FUNCTION_NAME, Url),
                   hd(binary:split(head(Server), <<"\r\n">>))
           end,
    [{Url, Same, Same} = {Url, Line(<<Base/binary, Path/binary>>), Line(Url)}
     || {Url, Path} <- [{<<"search/caf\xc3\xa9">>, <<"search/caf\xc3\xa9">>},
                        {<<"items/{id}">>, <<"items/{id}">>},
                        {<<"a|b">>, <<"a|b">>},
                        {<<"f[0]">>, <<"f[0]">>},
                        {<<"x/../it[ems">>, <<"it[ems">>},
                        {<<"../../up/./{a}">>, <<"../up/{a}">>}]].

%% Default headers and credentials go only to base_url's origin, however
%% the url names it; other defaults go everywhere.
credentials_stay_on_origin(_Config) ->
    {Home, Base} = server(<<>>),
    {Other, OtherUrl} = server(<<>>),
    Defaults = #{base_url => Base, userpwd => <<"u:p">>,
                 headers => [{<<"X-Key">>, <<"s3cr3t">>}], method => options},
    {ok, _} = katipo_pool:start(?FUNCTION_NAME, 1, [{defaults, Defaults}]),
    Port = fun(Url) -> integer_to_binary(maps:get(port, uri_string:parse(Url))) end,
    [begin
         {ok, #{status := 200}} = katipo:req(?FUNCTION_NAME, #{url => Url}),
         Head = head(Other),
         <<"OPTIONS ", _/binary>> = Head,
         nomatch = re:run(Head, <<"(?i)x-key|authorization">>)
     end
     || Url <- [OtherUrl, <<"//127.0.0.1:", (Port(OtherUrl))/binary, "/x">>,
                %% No origin to be told from the path: still not base_url's.
                <<OtherUrl/binary, "%zz">>]],
    [begin
         {ok, #{status := 200}} = katipo:req(?FUNCTION_NAME, #{url => Url}),
         Head = head(Home),
         {match, _} = re:run(Head, <<"\r\nX-Key: s3cr3t(\r\n|$)">>),
         {match, _} = re:run(Head, <<"\r\nAuthorization: Basic ">>)
     end
     || Url <- [<<"/x">>, <<"HTTP://127.0.0.1:", (Port(Base))/binary, "/x?f[a]=1">>]].

%% With no pool running a request exits no_workers, as wpool's calls do,
%% rather than being checked without the defaults it would have had.
no_pool(_Config) ->
    {'EXIT', no_workers} = (catch katipo:req(?FUNCTION_NAME, #{})),
    {'EXIT', no_workers} = (catch katipo:async_req(?FUNCTION_NAME, #{})),
    ok.

%% A bad request header is named at its place in the request's own list.
header_error_position(_Config) ->
    {_Server, Base} = server(<<>>),
    Defaults = #{base_url => Base, headers => [{<<"X-A">>, <<"1">>}, {<<"X-B">>, <<"2">>}]},
    {ok, _} = katipo_pool:start(?FUNCTION_NAME, 1, [{defaults, Defaults}]),
    {error, #{code := bad_opts, message := Message}} =
        katipo:get(?FUNCTION_NAME, <<"/">>, #{headers => [{<<"X-C">>, <<"3">>}, bad]}),
    {match, _} = re:run(Message, <<"invalid_header,2}">>),
    %% An improper list is named too, not a crash.
    {error, #{code := bad_opts}} =
        katipo:get(?FUNCTION_NAME, <<"/">>, #{headers => [{<<"X-C">>, <<"3">>} | bad]}).

%% The defaults may hold credentials, so neither an idle worker's status nor
%% the pool's stats shows them.
hidden_from_status(_Config) ->
    {_Server, Base} = server(<<>>),
    Defaults = #{base_url => Base, headers => [{<<"Authorization">>, <<"Bearer s3cr3t">>}]},
    {ok, _} = katipo_pool:start(?FUNCTION_NAME, 1, [{defaults, Defaults}]),
    [Worker] = wpool:get_workers(?FUNCTION_NAME),
    Shown = io_lib:format("~p", [{sys:get_status(Worker), wpool:stats(?FUNCTION_NAME)}]),
    nomatch = string:find(Shown, "s3cr3t").

%% A default retry policy is dropped for a request that streams, which
%% could never be retried, rather than failing it.
default_retry_skips_streams(_Config) ->
    {Server, Base} = server(<<>>),
    {ok, _} = katipo_pool:start(?FUNCTION_NAME, 1,
                                [{defaults, #{base_url => Base, retry => true}}]),
    {ok, Ref} = katipo:async_req(?FUNCTION_NAME, #{url => <<"/s">>, stream => true}),
    <<"GET /s ", _/binary>> = head(Server),
    receive {katipo_done, Ref, _} -> ok
    after ?WAIT -> ct:fail(no_stream_end)
    end,
    %% One given by the request is still refused.
    {error, #{code := bad_opts}} =
        katipo:async_req(?FUNCTION_NAME, #{url => <<"/s">>, stream => true, retry => true}).

%% wpool rebuilds a pool's record without its options if it finds the
%% name but not the record, as a caller racing the pool's first start can,
%% and keeps the rebuilt one; the pool goes on serving with its defaults.
served_after_rebuild(_Config) ->
    {Server, Base} = server(<<"rebuilt">>),
    {ok, _} = katipo_pool:start(?FUNCTION_NAME, 1, [{defaults, #{base_url => Base}}]),
    true = persistent_term:erase({wpool_pool, ?FUNCTION_NAME}),
    [begin
         {ok, #{status := 200}} = katipo:req(?FUNCTION_NAME, #{}),
         <<"GET /rebuilt ", _/binary>> = head(Server)
     end || _ <- [rebuild, rebuilt]],
    {ok, Ref} = katipo:async_req(?FUNCTION_NAME, #{}),
    {ok, #{status := 200}} = katipo:await(Ref, ?WAIT),
    <<"GET /rebuilt ", _/binary>> = head(Server).

%% A default url is resolved against base_url, as a request's is.
default_url_joins_base(_Config) ->
    {Server, Base} = server(<<"v1/">>),
    {ok, _} = katipo_pool:start(?FUNCTION_NAME, 1,
                                [{defaults, #{base_url => Base, url => <<"health">>}}]),
    {ok, #{status := 200}} = katipo:req(?FUNCTION_NAME, #{}),
    <<"GET /v1/health ", _/binary>> = head(Server),
    {ok, #{status := 200}} = katipo:get(?FUNCTION_NAME, <<"items">>),
    <<"GET /v1/items ", _/binary>> = head(Server).

%% A default client certificate and key are for base_url's origin too.
tls_identity_stays_on_origin(_Config) ->
    Tls = #{sslcert => <<"c.pem">>, sslkey => <<"k.pem">>, sslkey_blob => <<"k">>,
            keypasswd => <<"p">>},
    Base = <<"https://partner.example/v1/">>,
    {ok, _} = katipo_pool:start(?FUNCTION_NAME, 1, [{defaults, Tls#{base_url => Base}}]),
    {ok, Home, _} = katipo_defaults:merge_into(?FUNCTION_NAME, #{url => <<"x">>}),
    Tls = maps:with(maps:keys(Tls), Home),
    {ok, Other, _} = katipo_defaults:merge_into(?FUNCTION_NAME,
                                                #{url => <<"https://other.example/">>}),
    [] = maps:keys(maps:with(maps:keys(Tls), Other)).

%% A worker from before pool defaults is upgraded to one whose pool has
%% none, as its pool's options carry none: it admits a request with no
%% generation. A full worker shows that without a port: it refuses with
%% overload rather than stale.
old_worker_upgraded(_Config) ->
    {ok, State} = katipo_worker:code_change(old, {state, port, #{k => v}, #{}, 1}, []),
    {ok, Req} = katipo_req:build_req(#{url => <<"http://h/">>}, sync),
    {reply, {overload, _}, State} = katipo_worker:handle_call(Req, {self(), make_ref()}, State).

server(Path) ->
    {ok, Server, Port} = katipo_script_server:start([]),
    put(servers, [Server | get_servers()]),
    {Server, <<(katipo_script_server:url(Port))/binary, Path/binary>>}.

get_servers() ->
    case get(servers) of
        undefined -> [];
        Servers -> Servers
    end.

head(Server) ->
    receive {script_request, Server, Head, _Body} -> Head
    after ?WAIT -> ct:fail(no_request)
    end.

%% Poll until F holds.
wait_for(F) ->
    wait_for(F, 100).

wait_for(_F, 0) ->
    ct:fail(timeout);
wait_for(F, N) ->
    case F() of
        true -> ok;
        false -> timer:sleep(20), wait_for(F, N - 1)
    end.
