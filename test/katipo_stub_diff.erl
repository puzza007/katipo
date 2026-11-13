-module(katipo_stub_diff).

%% Differential property: a stub pool behaves as a real one. Each case is
%% a request and the response a server gives it, run twice: on a pool
%% whose C port and curl send it to katipo_prop_server, scripted to give
%% that response, and on a stub pool whose Handler gives it. The caller
%% must see the same outcome -- the response, or the error, buffered or
%% streamed -- and the server and the Handler the same request: method,
%% url, headers less those curl adds for the connection, and body.
%%
%% Requests vary in method, headers (repeated, blank, a Content-Type of
%% their own, overriding a pool default), body (bytes, iolists, forms,
%% files, and streamed uploads chunked or of a declared length, right or
%% wrong), how they are sent (sync, async, streamed with or without a
%% window) and max_body_size; responses in status, headers with and
%% without surrounding whitespace, and body size. The generators are
%% katipo_prop_SUITE's, so they reach the same edges.

-include_lib("proper/include/proper.hrl").

-export([prop_same/1]).
-export([setup/0]).
-export([teardown/1]).

-define(REAL, katipo_stub_diff_real).
-define(STUB, katipo_stub_diff_stub).
-define(TABLE, katipo_stub_diff).
-define(P, katipo_prop_SUITE).
-define(WAIT, 60000).

%% Both pools, with the same defaults: the server's url as base_url, and
%% a header that requests sometimes give their own value for.
setup() ->
    {ok, Server, Port} = katipo_prop_server:start(),
    Base = katipo_prop_server:url(Port, <<>>),
    Self = self(),
    Holder = spawn(fun() ->
                           ?TABLE = ets:new(?TABLE, [named_table, public]),
                           Self ! {?TABLE, self()},
                           receive stop -> ok end
                   end),
    receive {?TABLE, Holder} -> ok end,
    Defaults = {defaults, #{base_url => Base, headers => [{<<"X-Default">>, <<"d">>}]}},
    {ok, _} = katipo_pool:start(?REAL, 2, [Defaults]),
    {ok, _} = katipo_pool:start(?STUB, 2, [Defaults, {stub, handler(Base)}]),
    #{server => Server, port => Port, base => Base, holder => Holder}.

teardown(#{server := Server, holder := Holder}) ->
    ok = katipo_pool:stop(?REAL),
    ok = katipo_pool:stop(?STUB),
    Holder ! stop,
    katipo_prop_server:stop(Server).

%% The stub's Handler: the response scripted for the url's key, after
%% recording the request as given.
handler(Base) ->
    fun(Req = #{url := Url}) ->
            <<Base:(byte_size(Base))/binary, Key/binary>> = Url,
            [{_, Response}] = ets:take(?TABLE, Key),
            true = ets:insert(?TABLE, {{received, Key}, Req}),
            Response
    end.

prop_same(#{port := Port, base := Base}) ->
    ?FORALL(Case, test_case(),
            begin
                {RealOut, RealReq} = real(Port, Base, Case),
                {StubOut, StubReq} = stub(Base, Case),
                ?WHENFAIL(io:format("case ~P~nreal ~P~n     ~P~nstub ~P~n     ~P~n",
                                    [Case, 25, RealOut, 25, RealReq, 25,
                                     StubOut, 25, StubReq, 25]),
                          aggregate([{kind(Case), outcome_kind(RealOut)}],
                                    RealOut =:= StubOut andalso
                                        same_request(RealReq, StubReq)))
            end).

kind(#{mode := Mode, body := Body}) ->
    {mode_kind(Mode), body_kind(Body)}.

mode_kind({stream, infinity}) -> stream;
mode_kind({stream, _}) -> windowed;
mode_kind(M) -> M.

body_kind({upload, _, {length, _}}) -> {upload, wrong_length};
body_kind({upload, _, Length}) -> {upload, Length};
body_kind({Kind, _}) -> Kind;
body_kind(_) -> bytes.

outcome_kind({ok, _, _, _}) -> ok;
outcome_kind({error, Code}) -> Code;
outcome_kind(Other) -> Other.

%% =====================================================================
%% Running a case
%% =====================================================================

real(Port, Base, Case = #{response := Response, method := Method}) ->
    Key = ?P:key(),
    _ = katipo_prop_server:script(Port, Key, {echo, raw(Method, Response)}),
    Out = run(?REAL, Base, Key, Case),
    Req = try katipo_prop_server:received(Key)
          catch error:{badmatch, []} -> none
          end,
    {Out, Req}.

stub(Base, Case = #{response := Response}) ->
    Key = ?P:key(),
    true = ets:insert(?TABLE, {Key, stub_response(Response)}),
    Out = run(?STUB, Base, Key, Case),
    Req = case ets:take(?TABLE, {received, Key}) of
              [{_, R}] -> R;
              [] -> none
          end,
    ets:delete(?TABLE, Key),
    {Out, Req}.

raw(Method, #{status := Status, headers := Headers, body := Body}) ->
    Bytes = iolist_to_binary(Body),
    iolist_to_binary(
      [<<"HTTP/1.1 ">>, integer_to_binary(Status), <<" X\r\n">>,
       [[K, <<":">>, Pre, V, Post, <<"\r\n">>] || {K, Pre, V, Post} <- Headers],
       <<"content-length: ">>, integer_to_binary(byte_size(Bytes)), <<"\r\n\r\n">>,
       case Method of head -> <<>>; _ -> Bytes end]).

stub_response(#{status := Status, headers := Headers, body := Body}) ->
    #{status => Status,
      headers => [{K, [Pre, V, Post]} || {K, Pre, V, Post} <- Headers],
      body => Body}.

run(Pool, Base, Key, Case = #{mode := sync}) ->
    outcome(katipo:req(Pool, opts(Base, Key, Case)));
run(Pool, Base, Key, Case = #{mode := Mode, body := Body}) ->
    Stream = case Mode of
                 {stream, infinity} -> #{stream => true};
                 {stream, W} -> #{stream => true, stream_window => W};
                 async -> #{}
             end,
    case katipo:async_req(Pool, maps:merge(opts(Base, Key, Case), Stream)) of
        {ok, Ref} ->
            Upload = case Body of {upload, Chunks, _} -> Chunks; _ -> [] end,
            Window = case Mode of {stream, W2} -> W2; _ -> infinity end,
            collect(Pool, Ref, Upload, Window, Window, undefined, []);
        {error, #{code := Code}} ->
            {error, Code}
    end.

opts(Base, Key, #{url := Absolute, method := Method, headers := Headers, body := Body,
            max_body_size := Max}) ->
    Url = case Absolute of
              true -> <<Base/binary, Key/binary>>;
              false -> Key
          end,
    Opts = #{url => Url, method => Method, headers => Headers,
             body => body(Body), timeout_ms => ?WAIT},
    case Max of
        none -> Opts;
        _ -> Opts#{max_body_size => Max}
    end.

body({upload, Chunks, exact}) ->
    {stream, #{length => iolist_size(Chunks)}};
body({upload, _Chunks, {length, N}}) ->
    {stream, #{length => N}};
body({upload, _Chunks, chunked}) ->
    {stream, #{}};
body(Body) ->
    ?P:unwrap(Body).

%% The messages of an async request, as one outcome: each demand answered
%% with the next chunk, or eof. With a window, Credits are those left of
%% what was granted: a window's worth is granted only once they are all
%% spent, the first time after a pause in which no chunk may come, as the
%% transfer must be paused then.
collect(Pool, Ref, Upload, Window, Credits, Head, Acc) ->
    receive
        {katipo_body_demand, Ref} ->
            case Upload of
                [Chunk | Rest] ->
                    ok = katipo:send_body(Pool, Ref, Chunk),
                    collect(Pool, Ref, Rest, Window, Credits, Head, Acc);
                [] ->
                    ok = katipo:send_body(Pool, Ref, eof),
                    collect(Pool, Ref, [], Window, Credits, Head, Acc)
            end;
        {katipo_response, Ref, Response} ->
            outcome({ok, Response});
        {katipo_error, Ref, Error} when Head =:= undefined ->
            outcome({error, Error});
        {katipo_error, Ref, #{code := Code}} ->
            {error_after_headers, Code, lists:reverse(Acc)};
        {katipo_headers, Ref, #{status := S, headers := H}} when Head =:= undefined ->
            collect(Pool, Ref, Upload, Window, Credits, {S, H}, Acc);
        {katipo_chunk, Ref, Chunk} when Head =/= undefined, Chunk =/= <<>> ->
            case Credits of
                infinity ->
                    collect(Pool, Ref, Upload, Window, Credits, Head, [Chunk | Acc]);
                1 ->
                    case paused(Ref, length(Acc) + 1 =:= Window) of
                        true ->
                            ok = katipo:update_flow(Pool, Ref, Window),
                            collect(Pool, Ref, Upload, Window, Window, Head, [Chunk | Acc]);
                        false ->
                            {window_overrun, Window}
                    end;
                _ when Credits > 1 ->
                    collect(Pool, Ref, Upload, Window, Credits - 1, Head, [Chunk | Acc])
            end;
        {katipo_done, Ref, #{status := S}} when Head =/= undefined ->
            {S, H} = Head,
            outcome({ok, #{status => S, headers => H,
                           body => iolist_to_binary(lists:reverse(Acc))}});
        Other when element(2, Other) =:= Ref ->
            {unexpected, Other}
    after ?WAIT ->
            no_outcome
    end.

%% Whether no chunk comes while the window is spent, checked the first
%% time it is.
paused(_Ref, false) ->
    true;
paused(Ref, true) ->
    receive {katipo_chunk, Ref, _} = Chunk -> self() ! Chunk, false
    after 20 -> true
    end.

%% A response, less the framing headers the server adds, or an error's
%% code: the stub's messages are its own. A streamed request that fails
%% must have been given nothing first (collect/7).
outcome({ok, #{status := Status, headers := Headers, body := Body}}) ->
    {ok, Status, [H || H = {K, _} <- Headers,
                       katipo_req:header_name(K) =/= <<"content-length">>], Body};
outcome({error, #{code := Code}}) ->
    {error, Code}.

%% The request the server got, less the headers curl adds for the
%% connection, against the one the Handler got. curl's own Accept and
%% Accept-Encoding go unless the request gives its own. The Content-Type curl adds may be put
%% anywhere among the headers, so headers are compared as a multiset, and
%% the rest in order.
same_request(none, none) ->
    true;
same_request({Method, Got, Body},
             #{method := M, headers := Headers, body := Body}) ->
    Named = [katipo_req:header_name(K) || {K, _} <- Headers],
    Real = [H || H = {K, _} <- Got, not connection(K),
                 not lists:member(katipo_req:header_name(K), [<<"accept">>, <<"accept-encoding">>])
                     orelse lists:member(katipo_req:header_name(K), Named)],
    Method =:= string:uppercase(atom_to_binary(M))
        andalso lists:sort(Real) =:= lists:sort(Headers)
        andalso without_type(Real) =:= without_type(Headers);
same_request(_, _) ->
    false.

connection(K) ->
    lists:member(katipo_req:header_name(K),
                 [<<"host">>, <<"content-length">>, <<"transfer-encoding">>, <<"expect">>]).

without_type(Headers) ->
    [H || H = {K, _} <- Headers, katipo_req:header_name(K) =/= <<"content-type">>].

%% =====================================================================
%% Generators
%% =====================================================================

test_case() ->
    ?LET({Method, Headers, Body, Response, Absolute},
         {?P:method(), headers(), body(), response(), frequency([{4, false}, {1, true}])},
         ?LET({Mode, Max}, {mode(Body), max_body_size(Response)},
              #{method => Method, headers => Headers, body => Body, response => Response,
                url => Absolute, mode => Mode, max_body_size => Max})).

%% katipo_prop_SUITE's, with sometimes a header of a blank value, which
%% curl does not send, and the pool's default given a value of its own.
headers() ->
    ?LET({Headers, Type, Blank, Default},
         {?P:req_headers(), ?P:user_content_type(),
          frequency([{3, exactly([])},
                     {1, ?LET({K, V}, {?P:header_name(), elements([<<>>, <<" ">>, <<"\t">>])},
                              [{K, V}])},
                     {1, exactly([{<<"Accept">>, <<>>}])},
                     {1, exactly([{<<"Accept">>, <<"text/plain">>}])}]),
          frequency([{4, exactly([])}, {1, exactly([{<<"x-default">>, <<"mine">>}])}])},
         Headers ++ Type ++ Blank ++ Default).

body() ->
    frequency([{6, ?P:req_body()}, {3, upload()}]).

%% A streamed upload: its chunks, some empty, and its length: declared
%% exactly, not at all, or wrongly.
upload() ->
    ?LET(Chunks, list(?P:io_binary()),
         ?LET(Length, frequency([{3, exactly(exact)}, {3, exactly(chunked)},
                                 {1, ?LET(D, elements([-2, -1, 1, 7]),
                                          {length, max(0, iolist_size(Chunks) + D)})}]),
              {upload, Chunks, Length})).

%% An upload can only go async.
mode({upload, _, _}) ->
    frequency([{1, exactly(async)}, {1, stream()}]);
mode(_) ->
    frequency([{2, exactly(sync)}, {1, exactly(async)}, {2, stream()}]).

stream() ->
    {stream, frequency([{1, exactly(infinity)}, {2, range(1, 4)}])}.

%% None mostly, else close to the body's size, either side.
max_body_size(#{body := Body}) ->
    Size = iolist_size(Body),
    frequency([{3, exactly(none)},
               {1, ?LET(D, range(-2, 2), max(0, Size + D))}]).

%% No 1xx, 204 or 304, which carry no body, or redirects, which the stub
%% does not follow.
response() ->
    ?LET({Status, Headers, Body, Cuts},
         {elements([200, 201, 202, 203, 206, 400, 401, 404, 409, 418, 429, 500, 503]),
          ?LET(N, range(0, 6), vector(N, {?P:header_name(), ?P:ows(), value(), ?P:ows()})),
          ?P:resp_body(), list(range(1, 5000))},
         #{status => Status, headers => Headers, body => cut(Body, Cuts)}).

value() ->
    frequency([{1, exactly(<<>>)}, {8, ?P:req_value()}]).

%% The body as a list of pieces, as a Handler may give it.
cut(Body, []) ->
    Body;
cut(<<>>, _) ->
    [];
cut(Body, [N | Ns]) when N >= byte_size(Body) ->
    [Body | cut(<<>>, Ns)];
cut(Body, [N | Ns]) ->
    <<Piece:N/binary, Rest/binary>> = Body,
    [Piece | cut(Rest, Ns)].
