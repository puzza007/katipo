%% Event log for trace validation (formal/README.md, "Trace validation").
%%
%% The test profile compiles src/ with KATIPO_TRACE, which turns the ?TRACE
%% hooks in katipo and katipo_worker into calls to emit/1 and attempt/2.
%% Nothing is recorded unless KATIPO_TRACE_DIR is set when a suite calls
%% start/0; dump/1 then writes the run, one event per line, for the Lean
%% checker (formal/lean/scripts/TraceCheck.lean) to replay against the
%% admission model.
%%
%% Identities. An admission attempt is named by a seq_trace label the caller
%% sets for the duration of the call: the label rides on the call message, so
%% the worker reads it back without any change to the wire format. Once the
%% worker creates the request's alias, later events name the alias instead;
%% dump/1 maps both to one small integer per attempt. Events are ordered by
%% erlang:unique_integer([monotonic]), which is strictly increasing across
%% the node, so a send is always ordered before the worker's receipt of it.
-module(katipo_trace).

-export([start/0, dump/1, emit/1, attempt/2]).

-define(TAB, katipo_trace).

start() ->
    case os:getenv("KATIPO_TRACE_DIR") of
        false ->
            ok;
        _ ->
            Self = self(),
            Owner = spawn(fun() ->
                                  _ = ets:new(?TAB, [ordered_set, public, named_table]),
                                  Self ! {?TAB, ready},
                                  receive stop -> ok end
                          end),
            receive {?TAB, ready} -> ok end,
            persistent_term:put(?TAB, Owner),
            ok
    end.

%% Called by the ?TRACE hooks. Worker events are tagged with the worker's
%% registered name (one model worker per pool slot, across restarts); only
%% async requests -- whose From is {WorkerPid, Alias} -- are recorded.
emit(Event) ->
    case ets:whereis(?TAB) of
        undefined -> ok;
        _ -> record(Event)
    end.

record(start) ->
    put_event(slot(), start);
%% A refusal for another pool generation, like an overload one, touches no
%% state, so it is dropped as one is.
record({Refused, {async_req, _, _, _, _}}) when Refused =:= overload; Refused =:= stale ->
    put_event(slot(), {overload, label()});
record({Refused, _SyncReq}) when Refused =:= overload; Refused =:= stale ->
    ok;
record({clock, Deadline}) ->
    %% Read just before the worker's own past/1 check, so a late bit here
    %% means that check must have seen the deadline passed too.
    put_event(slot(), {clock, erlang:monotonic_time(millisecond) >= Deadline});
record(pre_refused) ->
    put_event(slot(), {pre, label()});
record(sending) ->
    put_event(slot(), {recv, label()});
record({post_refused, Alias}) ->
    put_event(slot(), {post, label(), Alias});
record({admitted, Alias}) ->
    put_event(slot(), {admit, label(), Alias});
record({Kind, {Pid, Alias}, Outcome}) when Pid =:= self(),
                                           (Kind =:= progress orelse
                                            Kind =:= terminal orelse
                                            Kind =:= cancel) ->
    put_event(slot(), {Kind, Alias, Outcome});
record({_Kind, {_SyncCaller, _Tag}, _Outcome}) ->
    ok;
record({delivered, {Pid, Alias}}) when Pid =:= self() ->
    put_event(slot(), {terminal, Alias, delivered});
record({delivered, _SyncFrom}) ->
    ok;
record(terminate) ->
    put_event(slot(), terminate);
record({cancel, Ref}) ->
    put_event(caller, {ccancel, Ref}).

%% Wraps one admission call (katipo:attempt/3). Records the send before the
%% call and the raw outcome after it, before attempt/3 folds `expired` and a
%% call timeout into one admission_timeout.
attempt({async_req, _, _, _}, Fun) ->
    case ets:whereis(?TAB) of
        undefined ->
            Fun();
        _ ->
            Label = erlang:unique_integer([positive]),
            Old = seq_trace:get_token(),
            _ = seq_trace:set_token(label, Label),
            put_event(caller, {send, Label}),
            try Fun() of
                Reply ->
                    put_event(caller, {result, Label, reply_outcome(Reply)}),
                    Reply
            catch
                exit:Reason:Stack ->
                    put_event(caller, {result, Label, exit_outcome(Reason)}),
                    erlang:raise(exit, Reason, Stack)
            after
                _ = seq_trace:set_token(Old)
            end
    end;
attempt(_SyncReq, Fun) ->
    Fun().

reply_outcome({overload, _}) -> overload;
reply_outcome(stale) -> overload;
reply_outcome(expired) -> expired;
reply_outcome(_Alias) -> ok.

exit_outcome({timeout, {gen_server, call, _}}) -> timeout;
exit_outcome(_) -> died.

put_event(Slot, Event) ->
    true = ets:insert(?TAB, {erlang:unique_integer([monotonic]), Slot, Event}),
    ok.

slot() ->
    case process_info(self(), registered_name) of
        {registered_name, Name} -> Name;
        _ -> self()
    end.

label() ->
    case seq_trace:get_token(label) of
        {label, L} -> L;
        [] -> undefined
    end.

%% Write the run as `<slot> <event> <args>` lines in event order and stop
%% recording. Attempts the worker rejected as overloaded are dropped: the
%% rejection touches no state, and spillover retries as a new attempt.
%% Attempts no worker ever saw get a slot of their own.
dump(Name) ->
    case persistent_term:get(?TAB, undefined) of
        undefined ->
            ok;
        Owner ->
            Events = [{S, E} || {_, S, E} <- ets:tab2list(?TAB)],
            Owner ! stop,
            _ = persistent_term:erase(?TAB),
            Dir = os:getenv("KATIPO_TRACE_DIR"),
            ok = filelib:ensure_dir(filename:join(Dir, "x")),
            File = filename:join(Dir, atom_to_list(Name) ++ ".trace"),
            ok = file:write_file(File, lines(Events))
    end.

lines(Raw) ->
    Folded = fold_crashes(attach_clocks(Raw, #{})),
    Overloaded = #{L => true || {_, {overload, L}} <- Folded},
    Events = [SE || SE = {_, E} <- Folded, not maps:is_key(label_of(E), Overloaded)],
    LabelSlot = maps:from_list([{L, S} || {S, {K, L, _}} <- Events, K =:= pre orelse K =:= recv]),
    AliasLabel = maps:from_list([{A, L} || {_, {K, L, A, _}} <- Events, K =:= post orelse K =:= admit]),
    {Lines, _} = lists:mapfoldl(
                   fun({S, E}, Ids) -> line(S, E, LabelSlot, AliasLabel, Ids) end,
                   #{}, Events),
    [L || L <- Lines, L =/= []].

%% Each deadline check's clock reading goes on the admission event that
%% reports that check's outcome, the slot's next event.
attach_clocks([], _) ->
    [];
attach_clocks([{S, {clock, Late}} | Rest], Clocks) ->
    attach_clocks(Rest, Clocks#{S => Late});
attach_clocks([{S, E} | Rest], Clocks) when element(1, E) =:= pre; element(1, E) =:= recv;
                                            element(1, E) =:= post; element(1, E) =:= admit ->
    {Late, Clocks2} = maps:take(S, Clocks),
    [{S, erlang:append_element(E, Late)} | attach_clocks(Rest, Clocks2)];
attach_clocks([SE | Rest], Clocks) ->
    [SE | attach_clocks(Rest, Clocks)].

%% terminate/2's worker_died notifications are the deliveries a worker makes
%% right after its terminate event, before it does anything else.
fold_crashes([]) ->
    [];
fold_crashes([{S, terminate} | Rest]) ->
    {Told, Rest2} = take_told(S, Rest, [], []),
    [{S, {crash, Told}} | fold_crashes(Rest2)];
fold_crashes([E | Rest]) ->
    [E | fold_crashes(Rest)].

take_told(S, [{S, {terminal, A, delivered}} | Rest], Told, Skipped) ->
    take_told(S, Rest, [A | Told], Skipped);
take_told(S, [E = {S2, _} | Rest], Told, Skipped) when S2 =/= S ->
    take_told(S, Rest, Told, [E | Skipped]);
take_told(_S, Rest, Told, Skipped) ->
    {lists:reverse(Told), lists:reverse(Skipped, Rest)}.

label_of({send, L}) -> L;
label_of({result, L, _}) -> L;
label_of({overload, L}) -> L;
label_of(_) -> none.

line(S, start, _, _, Ids) ->
    {fmt(S, "start", []), Ids};
line(_, {send, L}, LS, _, Ids) ->
    {Id, Ids2} = id({label, L}, Ids),
    {fmt(attempt_slot(L, Id, LS), "send", [Id]), Ids2};
line(_, {result, L, R}, LS, _, Ids) ->
    {Id, Ids2} = id({label, L}, Ids),
    {fmt(attempt_slot(L, Id, LS), "result " ++ atom_to_list(R), [Id]), Ids2};
line(_, {ccancel, Ref}, LS, AL, Ids) ->
    case AL of
        #{Ref := L} ->
            {Id, Ids2} = id({label, L}, Ids),
            {fmt(attempt_slot(L, Id, LS), "cancel", [Id]), Ids2};
        _ ->
            %% Not an alias katipo created: the runtime drops the send.
            {[], Ids}
    end;
line(S, {K, L, Late}, _, _, Ids) when K =:= pre; K =:= recv ->
    {Id, Ids2} = id({label, L}, Ids),
    {fmt(S, atom_to_list(K), [Id, bit(Late)]), Ids2};
line(S, {K, L, _Alias, Late}, _, _, Ids) when K =:= post; K =:= admit ->
    {Id, Ids2} = id({label, L}, Ids),
    {fmt(S, atom_to_list(K), [Id, bit(Late)]), Ids2};
line(S, {K, Alias, Outcome}, _, AL, Ids) ->
    {Id, Ids2} = alias_id(Alias, AL, Ids),
    Hit = lists:member(Outcome, [forwarded, delivered, effective]),
    {fmt(S, kind_name(K), [Id, bit(Hit)]), Ids2};
line(S, {crash, Aliases}, _, AL, Ids) ->
    {AIds, Ids2} = lists:mapfoldl(fun(A, I) -> alias_id(A, AL, I) end, Ids, Aliases),
    {fmt(S, "crash", AIds), Ids2}.

kind_name(progress) -> "chunk";
kind_name(terminal) -> "resp";
kind_name(cancel) -> "wcancel".

bit(true) -> 1;
bit(false) -> 0.

alias_id(Alias, AL, Ids) ->
    case AL of
        #{Alias := L} -> id({label, L}, Ids);
        _ -> id({alias, Alias}, Ids)
    end.

id(Key, Ids) ->
    case Ids of
        #{Key := Id} -> {Id, Ids};
        _ -> Id = map_size(Ids), {Id, Ids#{Key => Id}}
    end.

attempt_slot(L, Id, LS) ->
    case LS of
        #{L := S} -> S;
        _ -> {unseen, Id}
    end.

fmt(Slot, Kind, Args) ->
    SlotStr = re:replace(io_lib:format("~0p", [Slot]), "[^A-Za-z0-9_.-]", "_",
                         [global, {return, list}]),
    [SlotStr, " ", Kind, [[" ", integer_to_list(A)] || A <- Args], "\n"].
