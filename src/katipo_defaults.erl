-module(katipo_defaults).
-moduledoc false.

%% Each pool's default request options (katipo_pool's `defaults') and its
%% generation, a reference made by each katipo_pool:start/3, kept among the
%% pool's wpool options and in its workers' arguments. wpool stores the
%% options when the pool starts, and again from the same arguments when it
%% restarts, and wpool_pool:find_wpool/1 gives them only while the pool's
%% name is registered, so they are used only while the pool runs; wpool
%% keeps the record after a stop, until a pool takes the name again. They
%% are wrapped in a fun, as the options show in worker crash reports and in
%% wpool:stats/1 and the defaults may hold credentials; a hot upgrade of
%% this module would leave running pools with a fun it cannot call.
%% Requests read them in the caller and merge them into their options
%% (merge_into/2). Modelled in formal/KatipoPoolDefaults.tla.

-export([wpool_opt/2]).
-export([merge_into/2]).
-export([none/0]).

%% The defaults that apply only to requests for base_url's origin, as they
%% may carry credentials meant for it alone, or a client's TLS identity.
-define(ORIGIN_ONLY, [headers, username, password, userpwd,
                      sslcert, sslkey, sslkey_blob, keypasswd]).

-type get() :: fun(() -> {reference() | undefined, map(), base()}).
%% base_url split into its scheme and authority, and its path, with its
%% origin; worked out once, when the pool starts.
-type base() :: undefined | {binary(), binary(), {ok, map()} | error}.
-export_type([get/0]).

-spec wpool_opt(reference(), map()) -> {katipo_defaults, get()}.
wpool_opt(Gen, Defaults) ->
    Base = base(maps:get(base_url, Defaults, undefined)),
    Rest = maps:remove(base_url, Defaults),
    {katipo_defaults, fun() -> {Gen, Rest, Base} end}.

%% The defaults of a pool from before there were any: none, and no
%% generation (katipo_worker:code_change/3).
-spec none() -> {undefined, map(), undefined}.
none() ->
    {undefined, #{}, undefined}.

%% Opts with Pool's defaults under them, and the pool generation they
%% belong to, which only that pool's workers admit (katipo_worker): an
%% option given wins, a header replaces a default one of the same name
%% (compared ignoring ASCII case), and a relative url, or with none a
%% default one, is resolved against the default base_url, while an
%% absolute one stands. A pool not running exits no_workers, as wpool's
%% own calls do. Options wpool rebuilt, which it does if it finds the name
%% but not the record, as a caller racing the pool's first start can, and
%% keeps, are empty: the defaults are then asked of a worker, which has
%% them in its arguments. Options with no defaults at all are a pool's from
%% before there were any.
-spec merge_into(katipo_pool:name(), map()) ->
          {ok, map(), reference() | undefined} | {error, katipo:error()}.
merge_into(Pool, Opts) ->
    case wpool_pool:find_wpool(Pool) of
        undefined ->
            exit(no_workers);
        Wpool ->
            case wpool_pool:wpool_get(opts, Wpool) of
                #{katipo_defaults := Get} ->
                    merge(Get(), Opts);
                Rebuilt when map_size(Rebuilt) =:= 0 ->
                    Size = wpool_pool:wpool_get(size, Wpool),
                    ask([wpool_pool:worker_name(Pool, I) || I <- lists:seq(1, Size)], Opts);
                #{} ->
                    {ok, Opts, undefined}
            end
    end.

%% The first worker that answers; one dead or restarting is passed over.
ask([], _Opts) ->
    {error, katipo_req:error_map(worker_died, <<>>)};
ask([Worker | Workers], Opts) ->
    try katipo_worker:defaults(Worker) of
        Get -> merge(Get(), Opts)
    catch
        exit:_ -> ask(Workers, Opts)
    end.

merge({Gen, Defaults, Base}, Opts) ->
    {ok, merge(Defaults, Base, Opts), Gen}.

merge(Defaults, undefined, Opts) when map_size(Defaults) =:= 0 ->
    Opts;
merge(Defaults, Base, Opts) ->
    Opts1 = url(Base, default_url(Defaults, Opts)),
    Rest = retry(Opts1, origin_only(Base, Opts1, maps:remove(url, Defaults))),
    headers(Rest, Opts1, maps:merge(Rest, Opts1)).

default_url(#{url := Url}, Opts) when not is_map_key(url, Opts) -> Opts#{url => Url};
default_url(_Defaults, Opts) -> Opts.

%% base_url, checked at start: http or https, with a host and no query or
%% fragment.
base(undefined) ->
    undefined;
base(Url) ->
    {match, [Prefix]} = re:run(Url, "^[A-Za-z][A-Za-z0-9+.-]*://[^/?#]*",
                               [{capture, first, binary}]),
    <<_:(byte_size(Prefix))/binary, Path/binary>> = Url,
    {Prefix, Path, origin(Url)}.

%% An absolute url, one with a scheme, is sent as given. A relative one's
%% path is resolved against base_url as RFC 3986 has it, and its query and
%% fragment kept as given. The bytes are not checked, as they are not in
%% an absolute url: curl sends both alike.
url(undefined, Opts) ->
    Opts;
url(Base, Opts = #{url := Url}) when is_binary(Url) ->
    case re:run(Url, "^[A-Za-z][A-Za-z0-9+.-]*:", [{capture, none}]) of
        match ->
            Opts;
        nomatch ->
            {Path, Rest} = case binary:match(Url, [<<"?">>, <<"#">>]) of
                               nomatch -> {Url, <<>>};
                               {At, _} -> split_binary(Url, At)
                           end,
            Opts#{url := <<(resolve(Path, Base))/binary, Rest/binary>>}
    end;
url({Prefix, Path, _Origin}, Opts) when not is_map_key(url, Opts) ->
    Opts#{url => <<Prefix/binary, Path/binary>>};
url(_Base, Opts) ->
    Opts.

%% RFC 3986 5.2.2, for a reference with no scheme, query or fragment.
resolve(<<"//", _/binary>> = Ref, {Prefix, _Path, _Origin}) ->
    [Scheme | _] = binary:split(Prefix, <<":">>),
    {Authority, Path} = case binary:match(Ref, <<"/">>, [{scope, {2, byte_size(Ref) - 2}}]) of
                            nomatch -> {Ref, <<>>};
                            {At, _} -> split_binary(Ref, At)
                        end,
    <<Scheme/binary, ":", Authority/binary, (remove_dots(Path))/binary>>;
resolve(<<>>, {Prefix, Path, _Origin}) ->
    <<Prefix/binary, Path/binary>>;
resolve(<<"/", _/binary>> = Ref, {Prefix, _Path, _Origin}) ->
    <<Prefix/binary, (remove_dots(Ref))/binary>>;
resolve(Ref, {Prefix, Path, _Origin}) ->
    Dir = case binary:matches(Path, <<"/">>) of
              [] -> <<"/">>;
              Slashes -> {At, 1} = lists:last(Slashes), binary:part(Path, 0, At + 1)
          end,
    <<Prefix/binary, (remove_dots(<<Dir/binary, Ref/binary>>))/binary>>.

%% RFC 3986 5.2.4, on a path; Out holds its segments in reverse, each with
%% the slash before it.
remove_dots(Path) ->
    remove_dots(Path, []).

remove_dots(<<"../", In/binary>>, Out) -> remove_dots(In, Out);
remove_dots(<<"./", In/binary>>, Out) -> remove_dots(In, Out);
remove_dots(<<"/./", In/binary>>, Out) -> remove_dots(<<"/", In/binary>>, Out);
remove_dots(<<"/.">>, Out) -> remove_dots(<<"/">>, Out);
remove_dots(<<"/../", In/binary>>, Out) -> remove_dots(<<"/", In/binary>>, drop(Out));
remove_dots(<<"/..">>, Out) -> remove_dots(<<"/">>, drop(Out));
remove_dots(Dots, Out) when Dots =:= <<".">>; Dots =:= <<"..">>; Dots =:= <<>> ->
    iolist_to_binary(lists:reverse(Out));
remove_dots(<<"/", In/binary>>, Out) ->
    {Seg, Rest} = segment(In),
    remove_dots(Rest, [<<"/", Seg/binary>> | Out]);
remove_dots(In, Out) ->
    {Seg, Rest} = segment(In),
    remove_dots(Rest, [Seg | Out]).

segment(In) ->
    case binary:match(In, <<"/">>) of
        nomatch -> {In, <<>>};
        {At, _} -> split_binary(In, At)
    end.

drop([_ | Out]) -> Out;
drop([]) -> [].

origin_only(undefined, _Opts, Defaults) ->
    Defaults;
origin_only({_Prefix, _Path, BaseOrigin}, #{url := Url}, Defaults) ->
    case {origin(Url), BaseOrigin} of
        {{ok, Same}, {ok, Same}} -> Defaults;
        _ -> maps:without(?ORIGIN_ONLY, Defaults)
    end.

%% The scheme, host and port, normalised. A url without an origin that can
%% be told never shares base_url's.
origin(Url) when is_binary(Url) ->
    case re:run(Url, "^[A-Za-z][A-Za-z0-9+.-]*://[^/?#]*", [{capture, first, binary}]) of
        {match, [Authority]} ->
            case uri_string:normalize(Authority, [return_map]) of
                #{scheme := _, host := _} = Uri -> {ok, maps:with([scheme, host, port], Uri)};
                _ -> error
            end;
        nomatch ->
            error
    end;
origin(_) ->
    error.

%% A default retry policy is for the requests it can apply to: one that
%% streams cannot be sent again (katipo_req's retry_error/1).
retry(#{stream := true}, Defaults) -> maps:remove(retry, Defaults);
retry(#{body := {stream, _}}, Defaults) -> maps:remove(retry, Defaults);
retry(_Opts, Defaults) -> Defaults.

%% The request's own headers come first, so an error in one names its
%% place in the request's list. Anything but a proper list is left for the
%% request's checks to name.
headers(#{headers := Default}, #{headers := Given}, Merged) ->
    case proper(Given) of
        true ->
            Names = [header_name(K) || {K, _} <- Given],
            Merged#{headers := Given ++ [H || {K, _} = H <- Default,
                                              not lists:member(header_name(K), Names)]};
        false ->
            Merged
    end;
headers(_Defaults, _Opts, Merged) ->
    Merged.

proper([]) -> true;
proper([_ | T]) -> proper(T);
proper(_) -> false.

%% The request's headers are not checked yet.
header_name(K) ->
    try katipo_req:header_name(K)
    catch error:badarg -> K
    end.
