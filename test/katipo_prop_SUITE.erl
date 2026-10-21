-module(katipo_prop_SUITE).

%% Property tests, end to end through the C port against a local scripted
%% server (katipo_prop_server), so the C encoder and decoder are under
%% test rather than models of them:
%%
%%   * response bodies (the body frame) arrive byte-for-byte, buffered and
%%     streamed, whether framed by Content-Length, chunked or the closing
%%     connection, and a kept body references at most twice its own size;
%%   * requests -- method, headers, and binary, iolist or form bodies --
%%     arrive at the server exactly as given;
%%   * response headers are parsed as RFC 9110 says (names as sent, values
%%     with surrounding OWS trimmed, obs-fold continuations joined with a
%%     single space, and nothing else changed), and after
%%     1xx responses and followed redirects only the final response's
%%     headers are returned, never its trailers or another response's;
%%   * span URL sanitising never leaks userinfo, query or fragment, and
%%     never crashes on arbitrary input.
%%
%% Generators are weighted toward edges, and generators_cover_edges checks
%% by sampling that they actually reach them.

-include_lib("common_test/include/ct.hrl").
-include_lib("proper/include/proper.hrl").

-compile(export_all).
-compile(nowarn_export_all).

-define(POOL, katipo_prop_pool).
-define(NUMTESTS, 300).
%% Binaries this small live on the heap, where referenced_byte_size/1
%% counts something other than the bytes a sub-binary pins.
-define(HEAP_BIN_LIMIT, 64).
%% curl sends Expect: 100-continue for request bodies over 1 MiB.
-define(EXPECT_THRESHOLD, 1048576).
%% The marker every generated secret starts with. Hosts and paths have no
%% upper case outside percent-encodings, whose hex digits (0-9, A-F) cannot
%% spell it, so it cannot appear in them by chance.
-define(SECRET, "S3CR3T").

all() ->
    [generators_cover_edges,
     buffered_body_round_trips,
     streamed_body_round_trips,
     request_round_trips,
     response_headers_parsed,
     span_url_sanitised,
     span_url_never_crashes].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(katipo),
    {ok, _} = katipo_pool:start(?POOL, 2, []),
    {ok, Server, Port} = katipo_prop_server:start(),
    [{server, Server}, {port, Port} | Config].

end_per_suite(Config) ->
    ok = katipo_pool:stop(?POOL),
    ok = katipo_prop_server:stop(?config(server, Config)),
    application:stop(katipo),
    Config.

run(Prop) ->
    case proper:quickcheck(Prop, [{numtests, ?NUMTESTS},
                                  {to_file, user},
                                  long_result]) of
        true -> ok;
        CounterExample -> ct:fail({property_failed, CounterExample})
    end.

%% =====================================================================
%% Response bodies
%% =====================================================================

buffered_body_round_trips(Config) ->
    Port = ?config(port, Config),
    run(?FORALL({Body, Headers, Framing}, {resp_body(), resp_body_headers(), framing()},
                begin
                    Url = raw_response(Port, Body, Headers, Framing),
                    {ok, #{status := 200, headers := Got, body := B}} =
                        katipo:get(?POOL, Url),
                    B =:= Body andalso own_headers(Got) =:= Headers
                        andalso bounded(B)
                end)).

streamed_body_round_trips(Config) ->
    Port = ?config(port, Config),
    run(?FORALL({Body, Headers, Framing}, {resp_body(), resp_body_headers(), framing()},
                begin
                    Url = raw_response(Port, Body, Headers, Framing),
                    {ok, Ref} = katipo:async_get(?POOL, Url, #{stream => true}),
                    {200, Got, Chunks} = collect(Ref),
                    iolist_to_binary(Chunks) =:= Body
                        andalso own_headers(Got) =:= Headers
                        andalso lists:all(fun bounded/1, Chunks)
                end)).

%% The body framed by Content-Length, by chunked transfer coding, or by
%% the server closing the connection.
raw_response(Port, Body, Headers, Framing) ->
    Head = [<<"HTTP/1.1 200 OK\r\n">>,
            [[K, <<": ">>, V, <<"\r\n">>] || {K, V} <- Headers]],
    Script =
        case Framing of
            content_length ->
                {raw, [Head, <<"content-length: ">>, integer_to_binary(byte_size(Body)),
                       <<"\r\n\r\n">>, Body]};
            {chunked, Sizes, Case, Ext, Trailers} ->
                {raw, [Head, <<"transfer-encoding: chunked\r\n\r\n">>,
                       chunks(Body, Sizes, Case, Ext), <<"0\r\n">>,
                       header_lines(Trailers), <<"\r\n">>]};
            close ->
                {raw_close, [Head, <<"connection: close\r\n\r\n">>, Body]}
        end,
    katipo_prop_server:script(Port, key(), iolist_to_binary_script(Script)).

iolist_to_binary_script({Kind, IoData}) -> {Kind, iolist_to_binary(IoData)}.

%% Cut Body into chunks of the given sizes, cycling through them.
chunks(<<>>, _Sizes, _Case, _Ext) ->
    [];
chunks(Body, [Size | Sizes], Case, Ext) ->
    N = min(Size, byte_size(Body)),
    <<Chunk:N/binary, Rest/binary>> = Body,
    Hex = case Case of
              upper -> integer_to_binary(N, 16);
              lower -> string:lowercase(integer_to_binary(N, 16))
          end,
    [Hex, Ext, <<"\r\n">>, Chunk, <<"\r\n">>
     | chunks(Rest, Sizes ++ [Size], Case, Ext)].

%% A kept body is the frame's sub-binary only when it is at least half the
%% frame, and a copy of exactly its own size otherwise.
bounded(B) when byte_size(B) =< ?HEAP_BIN_LIMIT ->
    true;
bounded(B) ->
    binary:referenced_byte_size(B) =< 2 * byte_size(B).

%% The headers a response came back with, less the framing ones the test
%% adds: exactly the generated ones, so a trailer that leaks in fails.
own_headers(Got) ->
    [H || H = {K, _} <- Got,
          not lists:member(string:lowercase(K), [<<"content-length">>,
                                                 <<"transfer-encoding">>,
                                                 <<"connection">>])].

collect(Ref) ->
    receive
        {katipo_headers, Ref, #{status := Status, headers := Headers}} ->
            {Status, Headers, collect_chunks(Ref, [])}
    after 10000 ->
            ct:fail(no_stream_headers)
    end.

collect_chunks(Ref, Acc) ->
    receive
        {katipo_chunk, Ref, Chunk} -> collect_chunks(Ref, [Chunk | Acc]);
        {katipo_done, Ref, #{}} -> lists:reverse(Acc);
        {katipo_error, Ref, Error} -> ct:fail({stream_error, Error})
    after 10000 ->
            ct:fail(no_stream_done)
    end.

%% Content-Length most often; chunked with random chunk sizes (from one
%% byte to past curl's 16 KB buffer), hex case, chunk extensions and
%% sometimes trailers; or delimited by the connection closing.
framing() ->
    frequency([{3, exactly(content_length)},
               {2, {chunked, non_empty(list(chunk_size())), elements([upper, lower]),
                    elements([<<>>, <<";ext=1">>, <<"; name=\"q\"">>]),
                    trailers()}},
               {1, exactly(close)}]).

%% Trailer fields after a chunked body: none, or some with the same shapes
%% as response headers (but never folded).
trailers() ->
    frequency([{2, exactly([])},
               {1, non_empty(list({resp_header_name(), ows(), req_value(), ows()}))}]).

%% Large sizes are built from 4 KB steps: PropEr draws from a wide range
%% mostly near its low end, which would leave curl's 16 KB buffer untested.
chunk_size() ->
    frequency([{3, range(1, 16)}, {2, range(17, 4096)},
               {2, ?LET({Steps, Extra}, {range(1, 16), range(1, 4095)}, Steps * 4096 + Extra)}]).

resp_body() ->
    ?LET({Len, Seed, Lead}, {resp_body_len(), non_empty(binary()), lead()},
         fill(Len, Seed, Lead)).

resp_body_len() ->
    frequency([{1, exactly(0)},
               {3, range(1, 200)},
               {3, range(?HEAP_BIN_LIMIT - 2, ?HEAP_BIN_LIMIT + 2)},
               {3, range(200, 4000)},           %% the copy/share cutoff
               {2, range(16384 - 4, 16384 + 4)},
               {1, range(16384, 300000)}]).

%% 131 is the external term format's version byte: a body that starts
%% like a term must still be treated as opaque bytes.
lead() ->
    frequency([{4, exactly(<<>>)}, {1, exactly(<<131>>)},
               {1, exactly(<<131, 109>>)}]).

%% Len bytes: Lead, then Seed repeated. Shrinks with Seed, unlike random
%% bytes drawn outside PropEr.
fill(Len, Seed, Lead) ->
    Repeated = binary:copy(Seed, Len div byte_size(Seed) + 1),
    binary:part(<<Lead/binary, Repeated/binary>>, 0, Len).

%% Plain headers whose only job is to move the copy/share cutoff.
resp_body_headers() ->
    ?LET(N, range(0, 40),
         [{<<"x-prop-", (integer_to_binary(I))/binary>>, filler_value()}
          || I <- lists:seq(1, N)]).

filler_value() ->
    ?LET(Len, range(1, 120), list_to_binary(lists:duplicate(Len, $v))).

%% =====================================================================
%% Requests
%% =====================================================================

request_round_trips(Config) ->
    Port = ?config(port, Config),
    run(?FORALL({Method, Headers, ContentType, Body, Redirect},
                {method(), req_headers(), user_content_type(), req_body(),
                 redirect()},
                request_ok(Port, Method, Headers ++ ContentType, Body, Redirect))).

%% A HEAD request with a body is refused. Anything else must reach the
%% server -- through a redirect, if one is generated -- as the model says:
%% the method, every sent header in order, the body and its length, and
%% the Content-Type katipo is responsible for.
request_ok(Port, head, Headers, Body, Redirect) ->
    case sent_bytes(Body) of
        <<>> ->
            request_sent(Port, head, Headers, Body, Redirect);
        _ ->
            Result = katipo:head(?POOL, <<"http://127.0.0.1:1/">>,
                                 #{body => unwrap(Body)}),
            ?WHENFAIL(ct:pal("head with a body: ~P", [Result, 20]),
                      case Result of
                          {error, #{code := bad_opts}} -> true;
                          _ -> false
                      end)
    end;
request_ok(Port, Method, Headers, Body, Redirect) ->
    request_sent(Port, Method, Headers, Body, Redirect).

request_sent(Port, Method, Headers, Body, Redirect) ->
    Key = key(),
    EchoUrl = katipo_prop_server:script(Port, Key, echo),
    Url = case Redirect of
              none -> EchoUrl;
              Status -> katipo_prop_server:script(Port, key(), {redirect, Status, Key})
          end,
    {ok, #{status := 200}} =
        katipo:req(?POOL, #{url => Url, method => Method, headers => Headers,
                            body => unwrap(Body), followlocation => true,
                            timeout_ms => 60000}),
    Echo = {GotMethod, GotHeaders, GotBody} = katipo_prop_server:received(Key),
    {ExpMethod, ExpBody, ExpLength} = expected_request(Method, Body, Redirect),
    ?WHENFAIL(ct:pal("sent ~p ~p~n~P~n~P~ngot ~P",
                     [Method, Redirect, Headers, 30, Body, 30, Echo, 30]),
              GotMethod =:= ExpMethod
                  andalso in_order(Headers, GotHeaders)
                  andalso GotBody =:= ExpBody
                  andalso header(<<"content-length">>, GotHeaders) =:= ExpLength
                  andalso content_types(GotHeaders)
                          =:= expected_content_types(ExpMethod, ExpBody, Headers, Body)
                  andalso (ExpBody =:= <<>> orelse form_ok(Body, GotBody))).

%% Every method but HEAD sends its body. POST, PUT and PATCH always declare
%% one, if only Content-Length: 0; GET, DELETE and OPTIONS send an empty
%% body as none at all. A followed 301, 302 or 303 turns a POST into a GET
%% without its body, as browsers do; every other method keeps both.
expected_request(post, _Body, Status) when Status =:= 301; Status =:= 302;
                                           Status =:= 303 ->
    {<<"GET">>, <<>>, undefined};
expected_request(head, _Body, _Redirect) ->
    {<<"HEAD">>, <<>>, undefined};
expected_request(Method, Body, _Redirect) ->
    Sent = sent_bytes(Body),
    Length = case Sent =:= <<>> andalso not lists:member(Method, [post, put, patch]) of
                 true -> undefined;
                 false -> integer_to_binary(byte_size(Sent))
             end,
    {method_name(Method), Sent, Length}.

%% The caller's Content-Type always wins. Without one, a POST and a form
%% body are form-urlencoded, and any other body -- or no body, including a
%% POST's after a redirect turned it into a GET -- goes without one, rather
%% than with the form type curl would guess.
expected_content_types(Method, Sent, Headers, Body) ->
    Form = <<"application/x-www-form-urlencoded">>,
    case {content_types(Headers), Method, Sent, Body} of
        {[_ | _] = Own, _, _, _} -> Own;
        {[], <<"POST">>, _, _} -> [Form];
        {[], _, <<>>, _} -> [];
        {[], _, _, {form, _}} -> [Form];
        {[], _, _, _} -> []
    end.

content_types(Headers) ->
    [V || {K, V} <- Headers, string:lowercase(K) =:= <<"content-type">>].

unwrap({form, KVs}) -> KVs;
unwrap(IoData) -> IoData.

sent_bytes({form, KVs}) -> iolist_to_binary(uri_string:compose_query(KVs));
sent_bytes(IoData) -> iolist_to_binary(IoData).

%% The form body must decode back to the pairs it was built from, so a
%% double-encoded or truncated query fails even if the bytes look plausible.
%% Decoded here rather than with uri_string:dissect_query/1, which (OTP
%% 27.3) rejects a value containing an encoded '#', e.g. <<"k=%26%23a">>,
%% the very bytes compose_query/1 produced.
form_ok({form, KVs}, Got) -> decode_form(Got) =:= KVs;
form_ok(_, _) -> true.

decode_form(<<>>) ->
    [];
decode_form(Query) ->
    [case binary:split(Pair, <<"=">>) of
         [K] -> {form_decode(K), true};
         [K, V] -> {form_decode(K), form_decode(V)}
     end || Pair <- binary:split(Query, <<"&">>, [global])].

form_decode(B) ->
    pct_decode(B, <<>>).

pct_decode(<<"%", Hex:2/binary, Rest/binary>>, Acc) ->
    pct_decode(Rest, <<Acc/binary, (binary_to_integer(Hex, 16))>>);
pct_decode(<<"+", Rest/binary>>, Acc) ->
    pct_decode(Rest, <<Acc/binary, " ">>);
pct_decode(<<C, Rest/binary>>, Acc) ->
    pct_decode(Rest, <<Acc/binary, C>>);
pct_decode(<<>>, Acc) ->
    Acc.

method_name(M) -> string:uppercase(atom_to_binary(M)).

%% Each sent header arrives, unchanged and in order, among curl's own.
in_order([], _) -> true;
in_order(_, []) -> false;
in_order([H | Hs], [H | Gs]) -> in_order(Hs, Gs);
in_order(Hs, [_ | Gs]) -> in_order(Hs, Gs).

header(Name, Headers) ->
    katipo_prop_server:header(Name, Headers).

method() ->
    frequency([{3, post}, {2, put}, {2, patch},
               {1, get}, {1, delete}, {1, options}, {1, head}]).

%% Sometimes the caller sets its own Content-Type, in either case.
user_content_type() ->
    frequency([{3, exactly([])},
               {1, ?LET({Name, Value},
                        {elements([<<"Content-Type">>, <<"content-type">>]),
                         elements([<<"application/json">>,
                                   <<"text/plain; charset=utf-8">>,
                                   <<"application/x-www-form-urlencoded">>])},
                        [{Name, Value}])}]).

%% Most requests go straight to the server; some through one redirect.
redirect() ->
    frequency([{3, exactly(none)}, {1, elements([301, 302, 303, 307, 308])}]).

%% Sometimes a header is repeated under a name differing only in case;
%% both must be sent.
req_headers() ->
    ?LET({Headers, Dup},
         {?LET(N, frequency([{1, exactly(0)}, {4, range(1, 8)}, {1, range(9, 40)}]),
               vector(N, {header_name(), req_value()})),
          frequency([{4, false}, {1, true}])},
         case {Dup, Headers} of
             {true, [{Name, Value} | _]} -> Headers ++ [{flip_case(Name), Value}];
             _ -> Headers
         end).

flip_case(Name) ->
    << <<(if C >= $a, C =< $z -> C - 32; C >= $A, C =< $Z -> C + 32; true -> C end)>>
       || <<C>> <= Name >>.

%% Prefixed so a generated name never collides with a header curl manages
%% (Host, Content-Length, Expect...), which it would replace or drop.
header_name() ->
    ?LET({Prefix, Rest}, {oneof(["x-", "X-"]), non_empty(list(token_char()))},
         list_to_binary([Prefix | lists:sublist(Rest, 60)])).

%% RFC 9110 tchar.
token_char() ->
    frequency([{6, range($a, $z)}, {3, range($A, $Z)}, {2, range($0, $9)},
               {2, elements("!#$%&'*+-.^_`|~")}]).

%% A non-empty value with no surrounding whitespace (curl would send it as
%% is, but leading or trailing OWS is the receiver's to trim, so it would
%% not round-trip as bytes): visible ASCII, obs-text, and inner SP, HTAB
%% and colons.
req_value() ->
    ?LET({First, Mid, Last}, {field_vchar(), field_inner(), field_vchar()},
         case Mid of
             none -> <<First>>;
             _ -> list_to_binary([First, Mid, Last])
         end).

%% Long values repeat a short random run rather than drawing every byte,
%% which PropEr does one at a time.
field_inner() ->
    frequency([{1, exactly(none)},
               {5, vector_of(range(0, 10), inner_char())},
               {3, vector_of(range(10, 200), inner_char())},
               {1, ?LET({Len, Run}, {range(200, 4000), non_empty(list(inner_char()))},
                        lists:sublist(lists:append(
                                        lists:duplicate(Len div length(Run) + 1, Run)),
                                      Len))}]).

vector_of(LenGen, ElemGen) ->
    ?LET(N, LenGen, vector(N, ElemGen)).

field_vchar() ->
    frequency([{6, range($!, $~)}, {1, range(16#80, 16#FF)}]).

inner_char() ->
    frequency([{12, field_vchar()}, {1, $\s}, {1, $\t}, {1, $:}]).

req_body() ->
    frequency([{4, ?LET({Len, Seed}, {req_body_len(), non_empty(binary())},
                        fill(Len, Seed, <<>>))},
               {3, iodata_body()},
               {2, {form, form_pairs()}}]).

req_body_len() ->
    frequency([{1, exactly(0)},
               {3, range(1, 200)},
               {2, range(200, 70000)},
               {1, range(?EXPECT_THRESHOLD - 16, ?EXPECT_THRESHOLD + 16)},
               {1, range(?EXPECT_THRESHOLD, 3 * ?EXPECT_THRESHOLD)}]).

%% Nested iolists: bytes, binaries (empty ones too), nesting up to four
%% deep and binary tails, which ei_decode_iodata must flatten exactly as
%% iolist_to_binary does.
iodata_body() ->
    ?LET(Depth, frequency([{1, exactly(0)}, {4, range(1, 4)}]), iolist(Depth)).

iolist(Depth) ->
    oneof([vector_of(range(0, 6), io_elem(Depth)),
           ?LET({L, Tail}, {vector_of(range(1, 6), io_elem(Depth)), io_binary()},
                L ++ Tail)]).

io_elem(0) ->
    frequency([{3, range(0, 255)}, {3, io_binary()}]);
io_elem(Depth) ->
    frequency([{3, range(0, 255)}, {3, io_binary()},
               {3, ?LAZY(iolist(Depth - 1))}]).

io_binary() ->
    frequency([{1, exactly(<<>>)},
               {4, binary()},
               {1, ?LET({Len, Seed}, {range(1000, 20000), non_empty(binary())},
                        fill(Len, Seed, <<>>))}]).

%% uri_string:compose_query/1 pairs: Unicode keys and values, including
%% the characters form encoding has to escape, and bare keys (true).
form_pairs() ->
    non_empty(list({form_text(1), oneof([form_text(0), exactly(true)])})).

form_text(Min) ->
    ?LET(Cs, list(form_char()),
         unicode:characters_to_binary(lists:duplicate(max(0, Min - length(Cs)), $k) ++ Cs)).

form_char() ->
    frequency([{6, range($a, $z)},
               {3, elements(" &=+%?#/;:@!$'()*,[]")},
               {2, range(16#A0, 16#2FF)},
               {1, elements([16#4E2D, 16#6587, 16#1F600, 16#10FFFF])}]).

%% =====================================================================
%% Response headers
%% =====================================================================

response_headers_parsed(Config) ->
    Port = ?config(port, Config),
    run(?FORALL(Hops, response_chain(),
                response_chain_ok(Port, Hops))).

%% Hops: zero or more redirects, then the final response; any of them may
%% be preceded by a 103 Early Hints response with headers of its own. Only
%% the final response's headers may come back.
response_chain_ok(Port, Hops) ->
    Keys = [key() || _ <- Hops],
    Url = katipo_prop_server:url(Port, hd(Keys)),
    Next = tl(Keys) ++ [undefined],
    _ = [katipo_prop_server:script(Port, K, {raw, hop_bytes(Hop, N)})
         || {K, Hop, N} <- lists:zip3(Keys, Hops, Next)],
    {_Hints, {Status, _Reason}, Final, Trailers} = lists:last(Hops),
    Framing = case Trailers of
                  none -> {<<"content-length">>, <<"2">>};
                  _ -> {<<"transfer-encoding">>, <<"chunked">>}
              end,
    Expected = [{Name, value_of(Value)} || {Name, _Ows1, Value, _Ows2} <- Final]
        ++ [Framing],
    {ok, #{status := GotStatus, headers := Got, body := <<"ok">>}} =
        katipo:get(?POOL, Url, #{followlocation => true, maxredirs => 10}),
    ?WHENFAIL(ct:pal("expected ~p~ngot ~p", [Expected, Got]),
              GotStatus =:= Status andalso Got =:= Expected).

%% A hop with trailers sends its body (the final one's "ok", a redirect's
%% nothing) chunked, with the trailers after it.
hop_bytes({Hints, StatusLine, Headers, Trailers}, Next) ->
    Body = case Next of undefined -> <<"ok">>; _ -> <<>> end,
    iolist_to_binary(
      [case Hints of
           none -> [];
           _ -> [<<"HTTP/1.1 103 Early Hints\r\n">>, header_lines(Hints), <<"\r\n">>]
       end,
       status_line(StatusLine),
       header_lines(Headers),
       case Next of
           undefined -> [];
           _ -> [<<"location: /">>, Next, <<"\r\n">>]
       end,
       case Trailers of
           none ->
               [<<"content-length: ">>, integer_to_binary(byte_size(Body)),
                <<"\r\n\r\n">>, Body];
           _ ->
               [<<"transfer-encoding: chunked\r\n\r\n">>,
                chunks(Body, [1], upper, <<>>), <<"0\r\n">>,
                header_lines(Trailers), <<"\r\n">>]
       end]).

status_line({Status, Reason}) ->
    [<<"HTTP/1.1 ">>, integer_to_binary(Status), Reason, <<"\r\n">>].

header_lines(Headers) ->
    [[Name, <<":">>, Ows1, value_bytes(Value), Ows2, <<"\r\n">>]
     || {Name, Ows1, Value, Ows2} <- Headers].

%% A folded value goes over several lines: each part but the last ends in
%% optional whitespace and CRLF, and the next line starts with whitespace.
value_bytes({folded, [First | Parts], Gaps}) ->
    [First | [[Trail, <<"\r\n">>, Lead, Part]
              || {{Trail, Lead}, Part} <- lists:zip(Gaps, Parts)]];
value_bytes(Value) ->
    Value.

%% The value a folded header must parse to: its parts joined by one space
%% (RFC 9112 5.2 lets a recipient replace each obs-fold with SP).
value_of({folded, Parts, _Gaps}) ->
    iolist_to_binary(lists:join(<<" ">>, Parts));
value_of(Value) ->
    Value.

response_chain() ->
    ?LET({Redirects, Final},
         {vector_of(frequency([{3, exactly(0)}, {2, range(1, 4)}]), redirect_hop()),
          final_hop()},
         Redirects ++ [Final]).

redirect_hop() ->
    {hints(), {elements([301, 302, 303, 307, 308]), reason()}, resp_headers(),
     hop_trailers()}.

final_hop() ->
    {hints(), {elements([200, 203]), reason()}, resp_headers(), hop_trailers()}.

%% none: a Content-Length body; a list: a chunked body with these trailers.
hop_trailers() ->
    frequency([{2, exactly(none)}, {1, trailers()}]).

hints() ->
    frequency([{3, exactly(none)}, {1, non_empty(resp_headers())}]).

%% With and without a reason phrase; curl must not care.
reason() ->
    elements([<<" OK">>, <<" ">>, <<>>, <<" Some Reason">>]).

resp_headers() ->
    ?LET(N, frequency([{1, exactly(0)}, {4, range(1, 8)}, {1, range(9, 40)}]),
         vector(N, resp_header())).

%% {Name, OWS, Value, OWS}: the value as it should be parsed, between
%% optional whitespace that must be trimmed.
resp_header() ->
    {resp_header_name(), ows(), resp_value(), ows()}.

%% Names that start like a status line probe header_cb's check for a new
%% response, which must only fire on "HTTP/" or "HTTP " plus a digit.
resp_header_name() ->
    frequency([{8, header_name()},
               {1, elements([<<"HTTP">>, <<"HTTP2">>, <<"Http-Version">>,
                             <<"HTTP-1">>, <<"http">>])}]).

ows() ->
    frequency([{3, exactly(<<>>)},
               {2, ?LET(Cs, vector_of(range(1, 3), elements([$\s, $\t])),
                        list_to_binary(Cs))}]).

resp_value() ->
    frequency([{1, exactly(<<>>)}, {8, req_value()}, {1, folded_value()}]).

%% Two or three parts on successive lines (obs-fold), each continuation
%% line starting with at least one SP or HTAB.
folded_value() ->
    ?LET(Parts, vector_of(range(2, 3), req_value()),
         ?LET(Gaps, vector(length(Parts) - 1, {ows(), fold_lead()}),
              {folded, Parts, Gaps})).

fold_lead() ->
    ?LET(Cs, vector_of(range(1, 3), elements([$\s, $\t])), list_to_binary(Cs)).

%% =====================================================================
%% Span URL sanitising
%% =====================================================================

span_url_sanitised(_Config) ->
    run(?FORALL(Parts, url_parts(),
                begin
                    Url = compose(Parts),
                    {Sanitized, Host} = katipo_span:parse_url_for_span(Url),
                    Clean = compose(Parts#{userinfo := none, query := none,
                                           fragment := none}),
                    ?WHENFAIL(ct:pal("~p~n-> ~p", [Url, Sanitized]),
                              Sanitized =:= Clean
                                  andalso Host =:= expected_host(Parts)
                                  andalso nomatch =:= binary:match(Sanitized,
                                                                   <<?SECRET>>))
                end)).

%% Whatever the input, a pair of binaries comes back, and a non-empty URL
%% never carries a query or fragment.
span_url_never_crashes(_Config) ->
    run(?FORALL(Url, any_url(),
                case katipo_span:parse_url_for_span(Url) of
                    {<<>>, <<>>} ->
                        true;
                    {S, H} when is_binary(S), is_binary(H) ->
                        nomatch =:= binary:match(S, [<<"?">>, <<"#">>])
                end)).

any_url() ->
    frequency([{2, binary()},
               {2, ?LET(Cs, list(range(0, 255)), list_to_binary(Cs))},
               {4, ?LET({Parts, Edits}, {url_parts(), list({nat(), range(0, 255)})},
                        mutate(compose(Parts), Edits))}]).

%% Overwrite bytes of a well-formed URL, so the input stays close to
%% something uri_string parses.
mutate(Url, Edits) ->
    lists:foldl(fun({Pos, Byte}, U) when byte_size(U) > 0 ->
                        P = Pos rem byte_size(U),
                        <<A:P/binary, _, B/binary>> = U,
                        <<A/binary, Byte, B/binary>>;
                   (_, U) ->
                        U
                end, Url, Edits).

url_parts() ->
    ?LET({Scheme, Userinfo, Host, Port, Path, Query, Fragment},
         {elements([<<"http">>, <<"https">>]),
          frequency([{1, exactly(none)}, {3, userinfo()}]),
          host(),
          frequency([{2, exactly(none)}, {1, range(1, 65535)}]),
          path(),
          frequency([{1, exactly(none)}, {3, secret_text()}]),
          frequency([{2, exactly(none)}, {1, secret_text()}])},
         #{scheme => Scheme, userinfo => Userinfo, host => Host, port => Port,
           path => Path, query => Query, fragment => Fragment}).

compose(#{scheme := Scheme, userinfo := Userinfo, host := Host, port := Port,
          path := Path, query := Query, fragment := Fragment}) ->
    iolist_to_binary(
      [Scheme, <<"://">>,
       part(Userinfo, fun(U) -> [U, $@] end),
       Host,
       part(Port, fun(P) -> [$:, integer_to_binary(P)] end),
       Path,
       part(Query, fun(Q) -> [$?, Q] end),
       part(Fragment, fun(F) -> [$#, F] end)]).

part(none, _) -> [];
part(V, F) -> F(V).

expected_host(#{host := <<"[", Rest/binary>>}) ->
    binary:part(Rest, 0, byte_size(Rest) - 1);
expected_host(#{host := Host}) ->
    Host.

%% user, user:password or :password, with sub-delims and percent-encoding.
userinfo() ->
    ?LET({User, Password}, {secret_text(), oneof([none, secret_text()])},
         case Password of
             none -> User;
             _ -> <<User/binary, ":", Password/binary>>
         end).

secret_text() ->
    ?LET(Cs, list(oneof([unreserved(), sub_delim(), pct_encoded()])),
         iolist_to_binary([?SECRET | Cs])).

host() ->
    ensure_binary(oneof([?LET(Labels, non_empty(list(label())), lists:join($., Labels)),
           ?LET(Os, vector(4, range(0, 255)),
                lists:join($., [integer_to_binary(O) || O <- Os])),
           elements([<<"[::1]">>, <<"[2001:db8::7]">>, <<"[fe80::1:2:3:4]">>]),
           exactly(<<"localhost">>)])).

label() ->
    ?LET(Cs, non_empty(list(frequency([{6, range($a, $z)}, {2, range($0, $9)},
                                       {1, $-}]))),
         list_to_binary(Cs)).

%% Segments of lower-case unreserved characters, sub-delims, ':' and '@'
%% (all legal in a path) and percent-encodings.
path() ->
    frequency([{1, exactly(<<>>)},
               {4, ?LET(Segs, list(segment()),
                        iolist_to_binary([[$/, S] || S <- Segs]))}]).

segment() ->
    ?LET(Cs, list(frequency([{6, range($a, $z)}, {2, range($0, $9)},
                             {1, elements("-._~!$&'()*+,;=:@")},
                             {1, pct_encoded()}])),
         iolist_to_binary(Cs)).

unreserved() ->
    frequency([{4, range($a, $z)}, {4, range($A, $Z)}, {2, range($0, $9)},
               {1, elements("-._~")}]).

sub_delim() ->
    elements("!$&'()*+,;=").

pct_encoded() ->
    ?LET(B, range(0, 255), [$% | binary_to_list(binary:encode_hex(<<B>>))]).

%% =====================================================================
%% Generator coverage
%% =====================================================================

%% Sample each generator and require every edge it is weighted toward to
%% turn up often enough that ?NUMTESTS cases are all but certain to hit
%% it. A generator that drifts away from its edges fails here, not by
%% silently testing less.
generators_cover_edges(_Config) ->
    N = 2000,
    check_coverage(resp_body, N, resp_body(), fun(B) -> byte_size(B) end,
                   [{empty, fun(S) -> S =:= 0 end, 0.03},
                    {around_heap_limit,
                     fun(S) -> S >= ?HEAP_BIN_LIMIT - 2 andalso S =< ?HEAP_BIN_LIMIT + 2 end,
                     0.1},
                    {cutoff_range, fun(S) -> S >= 200 andalso S =< 4000 end, 0.15},
                    {around_16k, fun(S) -> abs(S - 16384) =< 4 end, 0.08},
                    {over_16k, fun(S) -> S > 16388 end, 0.03}]),
    check_coverage(framing, N, framing(), fun(F) -> F end,
                   [{content_length, fun(F) -> F =:= content_length end, 0.3},
                    {chunked, fun({chunked, _, _, _, _}) -> true; (_) -> false end, 0.2},
                    {one_byte_chunks, fun({chunked, Sizes, _, _, _}) -> lists:member(1, Sizes); (_) -> false end, 0.02},
                    {chunk_over_16k, fun({chunked, Sizes, _, _, _}) -> lists:any(fun(S) -> S > 16384 end, Sizes); (_) -> false end, 0.05},
                    {chunk_extension, fun({chunked, _, _, Ext, _}) -> Ext =/= <<>>; (_) -> false end, 0.1},
                    {trailers, fun({chunked, _, _, _, T}) -> T =/= []; (_) -> false end, 0.08},
                    {close, fun(F) -> F =:= close end, 0.1}]),
    check_coverage(resp_body_lead, N, resp_body(),
                   fun(<<Lead, _/binary>>) -> Lead; (_) -> none end,
                   [{starts_like_a_term, fun(Lead) -> Lead =:= 131 end,
                     0.15}]),
    check_coverage(req_body, N, req_body(), fun classify_req_body/1,
                   [{empty_binary, fun(C) -> C =:= {binary, 0} end, 0.02},
                    {binary, fun({binary, _}) -> true; (_) -> false end, 0.3},
                    {around_expect_threshold,
                     fun({binary, S}) -> abs(S - ?EXPECT_THRESHOLD) =< 16;
                        (_) -> false end, 0.03},
                    {over_expect_threshold,
                     fun({binary, S}) -> S > ?EXPECT_THRESHOLD; (_) -> false end, 0.05},
                    {nested_iolist, fun({iolist, _, Nested}) -> Nested; (_) -> false end, 0.1},
                    {improper_iolist, fun({iolist, Proper, _}) -> not Proper; (_) -> false end, 0.05},
                    {form, fun(C) -> C =:= form end, 0.15}]),
    check_coverage(form_pairs, N, form_pairs(), fun(KVs) -> KVs end,
                   [{bare_key, fun(KVs) -> lists:keymember(true, 2, KVs) end, 0.2},
                    {non_latin1,
                     fun(KVs) -> lists:any(fun({K, V}) -> beyond_latin1(K) orelse
                                                              beyond_latin1(V) end, KVs) end,
                     0.2},
                    {escapes,
                     fun(KVs) -> lists:any(fun({K, _}) -> nomatch =/= binary:match(K, [<<"&">>, <<"=">>, <<"+">>, <<"%">>]) end, KVs) end,
                     0.2}]),
    check_coverage(req_headers, N, req_headers(), fun(Hs) -> Hs end,
                   [{none, fun(Hs) -> Hs =:= [] end, 0.08},
                    {many, fun(Hs) -> length(Hs) > 8 end, 0.08},
                    {obs_text, fun(Hs) -> any_value(fun has_obs_text/1, Hs) end, 0.3},
                    {inner_whitespace, fun(Hs) -> any_value(fun has_inner_ws/1, Hs) end, 0.3},
                    {colon_in_value, fun(Hs) -> any_value(fun(V) -> nomatch =/= binary:match(V, <<":">>) end, Hs) end, 0.2},
                    {case_duplicate, fun(Hs) -> case_duplicate(Hs) end, 0.1},
                    {long_value, fun(Hs) -> any_value(fun(V) -> byte_size(V) > 200 end, Hs) end, 0.08}]),
    check_coverage(redirect, N, redirect(), fun(R) -> R end,
                   [{none, fun(R) -> R =:= none end, 0.5}]
                   ++ [{S, fun(R) -> R =:= S end, 0.03} || S <- [301, 302, 303, 307, 308]]),
    check_coverage(user_content_type, N, user_content_type(), fun(CT) -> CT end,
                   [{none, fun(CT) -> CT =:= [] end, 0.5},
                    {lower_case, fun(CT) -> [K || {K = <<"content-type">>, _} <- CT] =/= [] end, 0.08},
                    {form_type, fun(CT) -> [V || {_, V = <<"application/x-www-form-urlencoded">>} <- CT] =/= [] end, 0.05}]),
    check_coverage(method, N, method(), fun(M) -> M end,
                   [{M, fun(X) -> X =:= M end, 0.05}
                    || M <- [get, post, put, patch, delete, options, head]]),
    check_coverage(response_chain, N, response_chain(), fun(Hops) -> Hops end,
                   [{direct, fun(Hops) -> length(Hops) =:= 1 end, 0.4},
                    {redirected, fun(Hops) -> length(Hops) > 1 end, 0.25},
                    {early_hints, fun(Hops) -> lists:any(fun({H, _, _, _}) -> H =/= none end, Hops) end, 0.2},
                    {no_reason_phrase, fun(Hops) -> lists:any(fun({_, {_, R}, _, _}) -> R =:= <<>> end, Hops) end, 0.2},
                    {final_trailers, fun(Hops) -> element(4, lists:last(Hops)) =/= none andalso element(4, lists:last(Hops)) =/= [] end, 0.1},
                    {redirect_trailers, fun(Hops) -> lists:any(fun({_, _, _, T}) -> is_list(T) andalso T =/= [] end, lists:droplast(Hops)) end, 0.05}]),
    check_coverage(resp_headers, N, resp_headers(), fun(Hs) -> Hs end,
                   [{ows_around, fun(Hs) -> lists:any(fun({_, O1, _, O2}) -> O1 =/= <<>> andalso O2 =/= <<>> end, Hs) end, 0.3},
                    {tab_in_ows, fun(Hs) -> lists:any(fun({_, O1, _, O2}) -> nomatch =/= binary:match(<<O1/binary, O2/binary>>, <<"\t">>) end, Hs) end, 0.3},
                    {empty_value, fun(Hs) -> lists:any(fun({_, _, V, _}) -> V =:= <<>> end, Hs) end, 0.2},
                    {folded, fun(Hs) -> lists:any(fun({_, _, V, _}) -> is_tuple(V) end, Hs) end, 0.2},
                    {status_like_name, fun(Hs) -> lists:any(fun({<<H, T, T2, P, _/binary>>, _, _, _}) -> string:uppercase([H, T, T2, P]) =:= "HTTP"; (_) -> false end, Hs) end, 0.2},
                    {obs_text, fun(Hs) -> lists:any(fun({_, _, V, _}) -> has_obs_text(value_of(V)) end, Hs) end, 0.3}]),
    check_coverage(url_parts, N, url_parts(), fun(P) -> P end,
                   [{userinfo, fun(#{userinfo := U}) -> U =/= none end, 0.5},
                    {password, fun(#{userinfo := U}) -> is_binary(U) andalso nomatch =/= binary:match(U, <<":">>) end, 0.2},
                    {query, fun(#{query := Q}) -> Q =/= none end, 0.5},
                    {fragment, fun(#{fragment := F}) -> F =/= none end, 0.2},
                    {bare, fun(#{userinfo := U, query := Q, fragment := F}) -> {U, Q, F} =:= {none, none, none} end, 0.02},
                    {ipv6, fun(#{host := <<"[", _/binary>>}) -> true; (_) -> false end, 0.1},
                    {port, fun(#{port := P}) -> P =/= none end, 0.2},
                    {pct_in_path, fun(#{path := P}) -> nomatch =/= binary:match(P, <<"%">>) end, 0.15}]),
    ok.

check_coverage(Name, N, Gen, Classify, Classes) ->
    Samples = [Classify(sample(Gen)) || _ <- lists:seq(1, N)],
    Shares = [{Class, length([S || S <- Samples, Pred(S)]) / N, Min}
              || {Class, Pred, Min} <- Classes],
    ct:pal("~p coverage over ~B samples:~n~s",
           [Name, N, [io_lib:format("  ~-26w ~5.1f%  (min ~4.1f%)~n",
                                    [C, 100 * S, 100 * M])
                      || {C, S, M} <- Shares]]),
    case [C || {C, S, Min} <- Shares, S < Min] of
        [] -> ok;
        Short -> ct:fail({under_covered, Name, Short})
    end.

%% A value as quickcheck would draw it across a run: sizes 1..42.
sample(Gen) ->
    {ok, V} = proper_gen:pick(Gen, rand:uniform(42)),
    V.

classify_req_body({form, _}) -> form;
classify_req_body(B) when is_binary(B) -> {binary, byte_size(B)};
classify_req_body(L) ->
    {iolist, is_proper_list(L), has_sublist(L)}.

is_proper_list([]) -> true;
is_proper_list([_ | T]) -> is_proper_list(T);
is_proper_list(_) -> false.

has_sublist([H | _]) when is_list(H) -> true;
has_sublist([_ | T]) -> has_sublist(T);
has_sublist(_) -> false.

case_duplicate(Hs) ->
    Lower = [string:lowercase(K) || {K, _} <- Hs],
    length(lists:usort(Lower)) < length(Lower)
        andalso length(lists:usort([K || {K, _} <- Hs])) =:= length(Hs).

any_value(Pred, Hs) ->
    lists:any(fun({_, V}) -> Pred(V) end, Hs).

has_obs_text(V) ->
    lists:any(fun(B) -> B >= 16#80 end, binary_to_list(V)).

has_inner_ws(V) ->
    nomatch =/= binary:match(V, [<<" ">>, <<"\t">>]).

beyond_latin1(true) -> false;
beyond_latin1(B) -> lists:any(fun(C) -> C > 16#FF end, unicode:characters_to_list(B)).

ensure_binary(Gen) ->
    ?LET(V, Gen, iolist_to_binary(V)).

key() ->
    integer_to_binary(erlang:unique_integer([positive])).
