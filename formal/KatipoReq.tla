-------------------------------- MODULE KatipoReq --------------------------------
(***************************************************************************)
(* WHAT THIS MODELS. The katipo async request lifecycle: admission of a    *)
(* request into a pool worker, the transfer running in the C port,         *)
(* streaming chunk delivery under a credit window, and the four ways a     *)
(* request can resolve (completion, curl error, request timeout, worker    *)
(* death) racing each other and racing caller-issued cancel/flow commands. *)
(* The subtle part: FIVE independent senders of events (port data, the     *)
(* request timer, caller alias sends, the network, port death) interleave  *)
(* at the worker, and the design claims an admitted request resolves       *)
(* EXACTLY ONCE no matter how they land.                                   *)
(*                                                                         *)
(* Real code this abstracts (file:line as of commit 06f0138):              *)
(*   - src/katipo_worker.erl  admission/admit (~57..92), port msg          *)
(*     handling handle_port_msg/finish_req (~100..160), timeout handler    *)
(*     (~186..205), cancel handler (~206..224), flow handler (~225..233),  *)
(*     EXIT + terminate/2 worker_died notification (~234..258)             *)
(*   - src/katipo.erl  async_req/dispatch_async (~370..410), cancel/2 and  *)
(*     update_flow/3 as plain sends to the alias (~412..460), pool_call    *)
(*     worker_died conversion (~480..520)                                  *)
(*   - c_src/katipo.c  ConnInfo/active_conns (~73..115), cancel_conn       *)
(*     (~713), flow_conn credits+resume (~723..742), check_multi_info      *)
(*     completion (~744..790), write_cb streaming window/pause (~880..910) *)
(*                                                                         *)
(* THE ACTORS, and why each is or is not fair:                             *)
(*   - worker  - a gen_server; each handler is one atomic step. FAIR.      *)
(*   - port    - single-threaded libevent loop; each callback / command    *)
(*               is one atomic step. FAIR (the process runs; individual    *)
(*               network outcomes remain nondeterministic "may" choices).  *)
(*   - timer   - erlang:start_timer; WF models "an armed timer eventually  *)
(*               fires unless cancelled". FAIR. This is the actor that     *)
(*               makes liveness hold even when the network stalls or the   *)
(*               consumer stops granting credits.                          *)
(*   - caller  - the user. May stop consuming, granting, or cancelling at  *)
(*               any time. NOT fair.                                       *)
(*   - network completion / curl error / port death - "may" actions with   *)
(*               no fairness: a transfer that never finishes is legal.     *)
(*                                                                         *)
(* ABSTRACTION CHOICES:                                                    *)
(*   - Request identity is an allocation token (1..NumReqs), one-shot,     *)
(*     never reused - faithful to the worker minting a fresh alias ref     *)
(*     per request. Stale-message bugs across requests are expressible.    *)
(*   - Erlang guarantees FIFO only per sender/receiver pair, so each pair  *)
(*     is its own channel: dataChan (port->worker, EXIT ordered last,     *)
(*     as a port's exit signal is), aliasChan (caller->worker), cmdChan    *)
(*     (worker->port), mbox (worker->caller). Timer messages are their     *)
(*     own pseudo-channel (the "fired" state). The worker picks among      *)
(*     channel heads nondeterministically.                                 *)
(*   - Sends to a deactivated alias are dropped at SEND time; messages     *)
(*     already queued survive unalias and are no-op'd by the Reqs lookup - *)
(*     both faithful to the runtime.                                       *)
(*   - erlang:cancel_timer can lose the race: a timer in "fired" state     *)
(*     stays fired (its message is already queued) and the worker later    *)
(*     drops it as stale - the real maps:take/Tref-match discipline.       *)
(*   - Curl re-delivers the write_cb buffer held across a pause, so the    *)
(*     model simply does not consume the chunk when pausing.               *)
(*   - The port reads reqStream[t] directly instead of carrying the flag   *)
(*     through the req command; it is immutable from admission onward,     *)
(*     so this loses nothing.                                              *)
(*   - curl "error at any time" (including while paused: the overall      *)
(*     CURLOPT_TIMEOUT_MS still runs) over-approximates the network.       *)
(*                                                                         *)
(* OUT OF SCOPE, deliberately:                                             *)
(*   - Sync requests: the caller is blocked inside one gen_server call;    *)
(*     exactly-once is carried by gen_server:reply + the call monitor and  *)
(*     shares finish_req with the async path modelled here. No extra       *)
(*     interleaving exists that the async path does not already cover.     *)
(*   - Pool selection / spillover / max_in_flight admission: pure          *)
(*     request-routing before a worker accepts; a rejected request mints   *)
(*     no ref and creates no delivery obligation.                          *)
(*   - Option validation, header parsing, TLS/proxy plumbing: single-      *)
(*     actor data transformation; a model would prove nothing.             *)
(*   - Worker restart by wpool: a restarted worker is a fresh instance     *)
(*     with an empty Reqs map; it cannot touch old tokens (aliases died    *)
(*     with the old process), so one worker generation suffices.           *)
(*   - Crashes inside terminate/2 itself (notifications assumed to run).   *)
(***************************************************************************)
EXTENDS Integers, Sequences, FiniteSets, TLC

CONSTANTS
    NumReqs,        \* how many requests the caller may start (tokens 1..NumReqs)
    MaxChunks,      \* max body chunks per transfer
    MaxGrants,      \* max update_flow grants per request
    PortCanDie,     \* TRUE enables the port-death action (EXIT -> terminate/2)
    CallerCancels,  \* TRUE enables katipo:cancel/2
    StreamChoices,  \* subset of BOOLEAN: stream => true / false per request
    WindowChoices,  \* stream_window values: -1 = unbounded, n > 0 = bounded
    \* --- deliberately-wrong variants, to prove the model has teeth ---
    \* TRUE removes the worker's "is this request still in Reqs" check
    \* before forwarding/delivering port messages (katipo_worker.erl
    \* forward_progress/finish_req). MUST violate AtMostOneTerminal and the
    \* nothing-after-terminal assertion, or the model is not testing them.
    SkipStaleCheck,
    \* TRUE removes terminate/2's worker_died notification
    \* (katipo_worker.erl notify_worker_died). MUST violate liveness.
    NoTerminateNotify,
    \* TRUE tracks the witness-only ghosts (termType, everPaused,
    \* everStaleDrop) read by no invariant or property outside the
    \* _witness_* configs. FALSE freezes them so the large safety and
    \* liveness configs do not pay their state-space multiplication.
    TrackWitnesses

Tokens == 1..NumReqs

\* Named sets for the .cfg files (TLC's cfg parser cannot express booleans
\* or negative numbers inside set literals; configs substitute these).
BothStream   == {TRUE, FALSE}
StreamOnly   == {TRUE}
WinAll       == {-1, 1}
WinBounded   == {1}

\* port -> worker data messages (and the port's EXIT signal, FIFO-last)
HdrsM(t)  == [typ |-> "headers", r |-> t]
ChunkM(t) == [typ |-> "chunk",   r |-> t]
DoneM(t)  == [typ |-> "done",    r |-> t]
OkM(t)    == [typ |-> "ok",      r |-> t]
ErrM(t)   == [typ |-> "err",     r |-> t]
ExitM     == [typ |-> "exit",    r |-> 0]

\* worker -> port commands
ReqC(t, w)   == [typ |-> "req",    r |-> t, n |-> w]
CancelC(t)   == [typ |-> "cancel", r |-> t, n |-> 0]
FlowC(t, nn) == [typ |-> "flow",   r |-> t, n |-> nn]

\* (the caller's alias sends reuse CancelC/FlowC: same shape, and the
\* channel already encodes the direction)

\* worker -> caller (reply_to) messages
MHdrs(t)     == [typ |-> "headers", r |-> t, why |-> "-"]
MChunk(t)    == [typ |-> "chunk",   r |-> t, why |-> "-"]
MDone(t)     == [typ |-> "done",    r |-> t, why |-> "-"]
MResp(t)     == [typ |-> "resp",    r |-> t, why |-> "-"]
MErr(t, w)   == [typ |-> "err",     r |-> t, why |-> w]

\* the terminal reply_to message for a port terminal (ok/done/err)
TermM(m) == CASE m.typ = "ok"   -> MResp(m.r)
              [] m.typ = "done" -> MDone(m.r)
              [] OTHER          -> MErr(m.r, "curl")

(* --algorithm KatipoReq

variables
    \* channels (one per sender/receiver pair; Erlang FIFO per pair)
    cmdChan   = <<>>,   \* worker -> port
    dataChan  = <<>>,   \* port -> worker (EXIT rides this, ordered last)
    aliasChan = <<>>,   \* caller -> worker (cancel/flow via the alias)
    mbox      = <<>>,   \* worker -> caller (katipo_* messages)
    \* worker state
    wAlive      = TRUE,
    terminating = FALSE,                     \* EXIT seen / crashed; heading to terminate/2
    inflight    = {},                        \* the Reqs map's key set
    timer       = [t \in Tokens |-> "off"],  \* "off" | "armed" | "fired"
    aliasActive = [t \in Tokens |-> FALSE],
    \* port state
    pAlive   = TRUE,
    connSt   = [t \in Tokens |-> "none"],    \* "none" | "run" | "paused"
    connHdrs = [t \in Tokens |-> FALSE],     \* headers_sent
    connWin  = [t \in Tokens |-> -1],        \* remaining chunk credits (-1 unbounded)
    connLeft = [t \in Tokens |-> 0],         \* body chunks the network still holds
    \* caller state + ghosts
    nextTok     = 1,
    started     = {},                        \* admission returned {ok, Ref}
    admitFailed = {},                        \* admission returned {error, worker_died}
    cancelled   = {},                        \* caller invoked cancel/2
    reqStream   = [t \in Tokens |-> FALSE],
    reqWin      = [t \in Tokens |-> -1],
    grantsSent  = [t \in Tokens |-> 0],     \* update_flow credits issued (cap MaxGrants)
    portChunksSent = [t \in Tokens |-> 0],   \* chunk messages the port emitted
    gotHdrs     = [t \in Tokens |-> FALSE],  \* caller receive-side trackers
    gotChunk    = [t \in Tokens |-> FALSE],
    termRecv    = [t \in Tokens |-> 0],
    termSent    = [t \in Tokens |-> 0],      \* ghost: terminals APPENDED to mbox
    \* witness-only ghosts, live only under TrackWitnesses:
    termType    = [t \in Tokens |-> "none"], \* "ok"|"done"|"curl"|"timeout"|"worker_died"
    everPaused  = [t \in Tokens |-> FALSE],  \* transfer hit window = 0
    everStaleDrop = FALSE;                   \* a late msg was dropped by the Reqs lookup

\* ------------------------------------------------------------------------
\* The pool worker gen_server. Every either-branch is ONE handler = one
\* atomic step, matching gen_server semantics.
\* ------------------------------------------------------------------------
fair process worker = "worker"
begin
WLoop:
  while ~terminating do
    either
      \* --- handle_info {Port, {data, ...}}: one decoded port message ---
      await dataChan # <<>> /\ Head(dataChan).typ # "exit";
      with dm = Head(dataChan) do
        dataChan := Tail(dataChan);
        if dm.typ \in {"ok", "err", "done"} then
          \* finish_req: resolve iff still in Reqs; else drop silently
          if dm.r \in inflight then
            inflight := inflight \ {dm.r};
            timer[dm.r] := IF timer[dm.r] = "armed" THEN "off" ELSE timer[dm.r];
            aliasActive[dm.r] := FALSE;   \* deactivate (unalias)
            mbox := Append(mbox, TermM(dm));
            termSent[dm.r] := termSent[dm.r] + 1;
            termType[dm.r] := IF TrackWitnesses
                              THEN IF dm.typ = "err" THEN "curl" ELSE dm.typ
                              ELSE termType[dm.r];
          elsif SkipStaleCheck then
            \* SABOTAGE: deliver a terminal for an already-resolved request
            mbox := Append(mbox, TermM(dm));
            termSent[dm.r] := termSent[dm.r] + 1;
          else
            everStaleDrop := everStaleDrop \/ TrackWitnesses;
          end if;
        else
          \* forward_progress: headers/chunk to reply_to iff still in Reqs
          if dm.r \in inflight \/ SkipStaleCheck then
            mbox := Append(mbox, IF dm.typ = "headers" THEN MHdrs(dm.r)
                                                       ELSE MChunk(dm.r));
          else
            everStaleDrop := everStaleDrop \/ TrackWitnesses;
          end if;
        end if;
      end with;
    or
      \* --- handle_info {timeout, Tref, {req_timeout, From}} ---
      with t \in {x \in Tokens : timer[x] = "fired"} do
        timer[t] := "off";               \* the message is consumed either way
        if t \in inflight then
          inflight := inflight \ {t};
          aliasActive[t] := FALSE;
          mbox := Append(mbox, MErr(t, "timeout"));
          termSent[t] := termSent[t] + 1;
          termType[t] := IF TrackWitnesses THEN "timeout" ELSE termType[t];
          cmdChan := Append(cmdChan, CancelC(t));   \* abort_transfer
        else
          \* cancel_timer lost the race; stale drop
          everStaleDrop := everStaleDrop \/ TrackWitnesses;
        end if;
      end with;
    or
      \* --- handle_info {cancel, Ref} / {flow, Ref, N} (alias sends) ---
      await aliasChan # <<>>;
      with am = Head(aliasChan) do
        aliasChan := Tail(aliasChan);
        if am.typ = "cancel" then
          if am.r \in inflight then
            inflight := inflight \ {am.r};
            timer[am.r] := IF timer[am.r] = "armed" THEN "off" ELSE timer[am.r];
            aliasActive[am.r] := FALSE;
            cmdChan := Append(cmdChan, CancelC(am.r));
            \* no message to the caller: cancellation is silent by contract
          end if;
        else \* flow
          if am.r \in inflight then
            cmdChan := Append(cmdChan, FlowC(am.r, am.n));
          end if;
        end if;
      end with;
    or
      \* --- handle_info {'EXIT', Port, Reason} -> {stop, port_died} ---
      await dataChan # <<>> /\ Head(dataChan).typ = "exit";
      dataChan := Tail(dataChan);
      terminating := TRUE;
    end either;
  end while;
WTerm:
  \* terminate/2: notify each still-in-flight async request's reply_to,
  \* one send per step (maps:foreach sends are individually observable)
  while inflight # {} do
    with t \in inflight do
      inflight := inflight \ {t};
      if ~NoTerminateNotify then
        mbox := Append(mbox, MErr(t, "worker_died"));
        termSent[t] := termSent[t] + 1;
        termType[t] := IF TrackWitnesses THEN "worker_died" ELSE termType[t];
      end if;
    end with;
  end while;
WDead:
  wAlive := FALSE;
  aliasActive := [x \in Tokens |-> FALSE];  \* aliases die with the process
end process;

\* ------------------------------------------------------------------------
\* The C port: single-threaded libevent loop. Commands and callbacks are
\* atomic; network outcomes are nondeterministic.
\* ------------------------------------------------------------------------
fair process port = "port"
begin
PLoop:
  while pAlive do
    either
      \* --- one command from the Erlang side ---
      await cmdChan # <<>>;
      with cm = Head(cmdChan) do
        cmdChan := Tail(cmdChan);
        if cm.typ = "req" then
          \* new_conn: register the transfer; the network picks a body length
          connSt[cm.r] := "run";
          connHdrs[cm.r] := FALSE;
          connWin[cm.r] := cm.n;
          with bl \in 0..MaxChunks do
            connLeft[cm.r] := bl;
          end with;
        elsif cm.typ = "cancel" then
          \* cancel_conn: free if still active, else no-op
          connSt[cm.r] := "none";
        else
          \* flow_conn: credits, resume if paused; no-op if gone or unbounded
          if connSt[cm.r] # "none" /\ connWin[cm.r] >= 0 /\ cm.n > 0 then
            connWin[cm.r] := connWin[cm.r] + cm.n;
            connSt[cm.r] := "run";
          end if;
        end if;
      end with;
    or
      \* --- write_cb: a body chunk arrives for a running transfer ---
      with t \in {x \in Tokens : connSt[x] = "run" /\ connLeft[x] > 0} do
        if reqStream[t] then
          if connWin[t] = 0 then
            \* out of credits: CURL_WRITEFUNC_PAUSE; curl holds the buffer
            connSt[t] := "paused";
            everPaused[t] := everPaused[t] \/ TrackWitnesses;
          else
            dataChan := dataChan \o (IF connHdrs[t] THEN <<ChunkM(t)>>
                                     ELSE <<HdrsM(t), ChunkM(t)>>);
            connHdrs[t] := TRUE;
            connLeft[t] := connLeft[t] - 1;
            portChunksSent[t] := portChunksSent[t] + 1;
            connWin[t] := IF connWin[t] > 0 THEN connWin[t] - 1 ELSE connWin[t];
          end if;
        else
          connLeft[t] := connLeft[t] - 1;   \* buffered into conn->memory
        end if;
      end with;
    or
      \* --- check_multi_info: transfer completed CURLE_OK ---
      with t \in {x \in Tokens : connSt[x] = "run" /\ connLeft[x] = 0} do
        if reqStream[t] then
          \* bodyless responses still owe the one-time headers message
          dataChan := dataChan \o (IF connHdrs[t] THEN <<DoneM(t)>>
                                   ELSE <<HdrsM(t), DoneM(t)>>);
        else
          dataChan := Append(dataChan, OkM(t));
        end if;
        connSt[t] := "none";   \* free_conn
      end with;
    or
      \* --- transfer failed (curl error; possible even while paused) ---
      with t \in {x \in Tokens : connSt[x] \in {"run", "paused"}} do
        dataChan := Append(dataChan, ErrM(t));
        connSt[t] := "none";
      end with;
    or
      \* --- the port dies; its EXIT signal is FIFO-last on dataChan ---
      await PortCanDie;
      pAlive := FALSE;
      connSt := [x \in Tokens |-> "none"];
      dataChan := Append(dataChan, ExitM);
    end either;
  end while;
end process;

\* ------------------------------------------------------------------------
\* The timer service (erlang:start_timer). WF: an armed timer that is never
\* cancelled eventually fires; each token's timer is one-shot.
\* ------------------------------------------------------------------------
fair process timers = "timers"
begin
TFire:
  while TRUE do
    with t \in {x \in Tokens : timer[x] = "armed"} do
      timer[t] := "fired";
    end with;
  end while;
end process;

\* ------------------------------------------------------------------------
\* The user. NOT fair: may stop consuming, granting, or cancelling.
\* ------------------------------------------------------------------------
process caller = "caller"
begin
CLoop:
  while TRUE do
    either
      \* --- async_req: admission is one atomic gen_server call ---
      await nextTok <= NumReqs /\ wAlive /\ ~terminating;
      if pAlive then
        with s \in StreamChoices,
             w \in IF s THEN WindowChoices ELSE {-1} do
          started := started \cup {nextTok};
          reqStream[nextTok] := s;
          reqWin[nextTok] := w;
          inflight := inflight \cup {nextTok};
          timer[nextTok] := "armed";
          aliasActive[nextTok] := TRUE;
          cmdChan := Append(cmdChan, ReqC(nextTok, w));
        end with;
      else
        \* send_to_port hits a closed port: badarg crashes the worker inside
        \* handle_call BEFORE the Reqs insert; the caller's call monitor
        \* converts it to {error, worker_died}; terminate/2 then runs.
        admitFailed := admitFailed \cup {nextTok};
        terminating := TRUE;
      end if;
      nextTok := nextTok + 1;
    or
      \* --- receive one katipo_* message; assert the delivery contract ---
      await mbox # <<>>;
      with rm = Head(mbox) do
        mbox := Tail(mbox);
        assert termRecv[rm.r] = 0;   \* nothing arrives after a terminal
        if rm.typ = "headers" then
          assert reqStream[rm.r] /\ ~gotHdrs[rm.r];
          gotHdrs[rm.r] := TRUE;
        elsif rm.typ = "chunk" then
          assert reqStream[rm.r] /\ gotHdrs[rm.r];
          gotChunk[rm.r] := TRUE;
        elsif rm.typ = "done" then
          assert reqStream[rm.r] /\ gotHdrs[rm.r];
          termRecv[rm.r] := termRecv[rm.r] + 1;
        elsif rm.typ = "resp" then
          assert ~reqStream[rm.r] /\ ~gotHdrs[rm.r] /\ ~gotChunk[rm.r];
          termRecv[rm.r] := termRecv[rm.r] + 1;
        else \* err (curl / timeout / worker_died): legal at any point
          termRecv[rm.r] := termRecv[rm.r] + 1;
        end if;
      end with;
    or
      \* --- cancel/2: a plain send to the alias; dropped if deactivated ---
      await CallerCancels;
      with t \in started \ cancelled do
        cancelled := cancelled \cup {t};
        if aliasActive[t] then
          aliasChan := Append(aliasChan, CancelC(t));
        end if;
      end with;
    or
      \* --- update_flow/3: grant one credit ---
      with t \in {x \in started : reqStream[x] /\ reqWin[x] >= 0
                                  /\ grantsSent[x] < MaxGrants} do
        grantsSent[t] := grantsSent[t] + 1;
        if aliasActive[t] then
          aliasChan := Append(aliasChan, FlowC(t, 1));
        end if;
      end with;
    end either;
  end while;
end process;

end algorithm; *)

\* Translate with:  java -cp tla2tools.jar pcal.trans formal/KatipoReq.tla

\* BEGIN TRANSLATION
VARIABLES cmdChan, dataChan, aliasChan, mbox, wAlive, terminating, inflight, 
          timer, aliasActive, pAlive, connSt, connHdrs, connWin, connLeft, 
          nextTok, started, admitFailed, cancelled, reqStream, reqWin, 
          grantsSent, portChunksSent, gotHdrs, gotChunk, termRecv, termSent, 
          termType, everPaused, everStaleDrop, pc

vars == << cmdChan, dataChan, aliasChan, mbox, wAlive, terminating, inflight, 
           timer, aliasActive, pAlive, connSt, connHdrs, connWin, connLeft, 
           nextTok, started, admitFailed, cancelled, reqStream, reqWin, 
           grantsSent, portChunksSent, gotHdrs, gotChunk, termRecv, termSent, 
           termType, everPaused, everStaleDrop, pc >>

ProcSet == {"worker"} \cup {"port"} \cup {"timers"} \cup {"caller"}

Init == (* Global variables *)
        /\ cmdChan = <<>>
        /\ dataChan = <<>>
        /\ aliasChan = <<>>
        /\ mbox = <<>>
        /\ wAlive = TRUE
        /\ terminating = FALSE
        /\ inflight = {}
        /\ timer = [t \in Tokens |-> "off"]
        /\ aliasActive = [t \in Tokens |-> FALSE]
        /\ pAlive = TRUE
        /\ connSt = [t \in Tokens |-> "none"]
        /\ connHdrs = [t \in Tokens |-> FALSE]
        /\ connWin = [t \in Tokens |-> -1]
        /\ connLeft = [t \in Tokens |-> 0]
        /\ nextTok = 1
        /\ started = {}
        /\ admitFailed = {}
        /\ cancelled = {}
        /\ reqStream = [t \in Tokens |-> FALSE]
        /\ reqWin = [t \in Tokens |-> -1]
        /\ grantsSent = [t \in Tokens |-> 0]
        /\ portChunksSent = [t \in Tokens |-> 0]
        /\ gotHdrs = [t \in Tokens |-> FALSE]
        /\ gotChunk = [t \in Tokens |-> FALSE]
        /\ termRecv = [t \in Tokens |-> 0]
        /\ termSent = [t \in Tokens |-> 0]
        /\ termType = [t \in Tokens |-> "none"]
        /\ everPaused = [t \in Tokens |-> FALSE]
        /\ everStaleDrop = FALSE
        /\ pc = [self \in ProcSet |-> CASE self = "worker" -> "WLoop"
                                        [] self = "port" -> "PLoop"
                                        [] self = "timers" -> "TFire"
                                        [] self = "caller" -> "CLoop"]

WLoop == /\ pc["worker"] = "WLoop"
         /\ IF ~terminating
               THEN /\ \/ /\ dataChan # <<>> /\ Head(dataChan).typ # "exit"
                          /\ LET dm == Head(dataChan) IN
                               /\ dataChan' = Tail(dataChan)
                               /\ IF dm.typ \in {"ok", "err", "done"}
                                     THEN /\ IF dm.r \in inflight
                                                THEN /\ inflight' = inflight \ {dm.r}
                                                     /\ timer' = [timer EXCEPT ![dm.r] = IF timer[dm.r] = "armed" THEN "off" ELSE timer[dm.r]]
                                                     /\ aliasActive' = [aliasActive EXCEPT ![dm.r] = FALSE]
                                                     /\ mbox' = Append(mbox, TermM(dm))
                                                     /\ termSent' = [termSent EXCEPT ![dm.r] = termSent[dm.r] + 1]
                                                     /\ termType' = [termType EXCEPT ![dm.r] = IF TrackWitnesses
                                                                                               THEN IF dm.typ = "err" THEN "curl" ELSE dm.typ
                                                                                               ELSE termType[dm.r]]
                                                     /\ UNCHANGED everStaleDrop
                                                ELSE /\ IF SkipStaleCheck
                                                           THEN /\ mbox' = Append(mbox, TermM(dm))
                                                                /\ termSent' = [termSent EXCEPT ![dm.r] = termSent[dm.r] + 1]
                                                                /\ UNCHANGED everStaleDrop
                                                           ELSE /\ everStaleDrop' = (everStaleDrop \/ TrackWitnesses)
                                                                /\ UNCHANGED << mbox, 
                                                                                termSent >>
                                                     /\ UNCHANGED << inflight, 
                                                                     timer, 
                                                                     aliasActive, 
                                                                     termType >>
                                     ELSE /\ IF dm.r \in inflight \/ SkipStaleCheck
                                                THEN /\ mbox' = Append(mbox, IF dm.typ = "headers" THEN MHdrs(dm.r)
                                                                                                   ELSE MChunk(dm.r))
                                                     /\ UNCHANGED everStaleDrop
                                                ELSE /\ everStaleDrop' = (everStaleDrop \/ TrackWitnesses)
                                                     /\ mbox' = mbox
                                          /\ UNCHANGED << inflight, timer, 
                                                          aliasActive, 
                                                          termSent, termType >>
                          /\ UNCHANGED <<cmdChan, aliasChan, terminating>>
                       \/ /\ \E t \in {x \in Tokens : timer[x] = "fired"}:
                               /\ timer' = [timer EXCEPT ![t] = "off"]
                               /\ IF t \in inflight
                                     THEN /\ inflight' = inflight \ {t}
                                          /\ aliasActive' = [aliasActive EXCEPT ![t] = FALSE]
                                          /\ mbox' = Append(mbox, MErr(t, "timeout"))
                                          /\ termSent' = [termSent EXCEPT ![t] = termSent[t] + 1]
                                          /\ termType' = [termType EXCEPT ![t] = IF TrackWitnesses THEN "timeout" ELSE termType[t]]
                                          /\ cmdChan' = Append(cmdChan, CancelC(t))
                                          /\ UNCHANGED everStaleDrop
                                     ELSE /\ everStaleDrop' = (everStaleDrop \/ TrackWitnesses)
                                          /\ UNCHANGED << cmdChan, mbox, 
                                                          inflight, 
                                                          aliasActive, 
                                                          termSent, termType >>
                          /\ UNCHANGED <<dataChan, aliasChan, terminating>>
                       \/ /\ aliasChan # <<>>
                          /\ LET am == Head(aliasChan) IN
                               /\ aliasChan' = Tail(aliasChan)
                               /\ IF am.typ = "cancel"
                                     THEN /\ IF am.r \in inflight
                                                THEN /\ inflight' = inflight \ {am.r}
                                                     /\ timer' = [timer EXCEPT ![am.r] = IF timer[am.r] = "armed" THEN "off" ELSE timer[am.r]]
                                                     /\ aliasActive' = [aliasActive EXCEPT ![am.r] = FALSE]
                                                     /\ cmdChan' = Append(cmdChan, CancelC(am.r))
                                                ELSE /\ TRUE
                                                     /\ UNCHANGED << cmdChan, 
                                                                     inflight, 
                                                                     timer, 
                                                                     aliasActive >>
                                     ELSE /\ IF am.r \in inflight
                                                THEN /\ cmdChan' = Append(cmdChan, FlowC(am.r, am.n))
                                                ELSE /\ TRUE
                                                     /\ UNCHANGED cmdChan
                                          /\ UNCHANGED << inflight, timer, 
                                                          aliasActive >>
                          /\ UNCHANGED <<dataChan, mbox, terminating, termSent, termType, everStaleDrop>>
                       \/ /\ dataChan # <<>> /\ Head(dataChan).typ = "exit"
                          /\ dataChan' = Tail(dataChan)
                          /\ terminating' = TRUE
                          /\ UNCHANGED <<cmdChan, aliasChan, mbox, inflight, timer, aliasActive, termSent, termType, everStaleDrop>>
                    /\ pc' = [pc EXCEPT !["worker"] = "WLoop"]
               ELSE /\ pc' = [pc EXCEPT !["worker"] = "WTerm"]
                    /\ UNCHANGED << cmdChan, dataChan, aliasChan, mbox, 
                                    terminating, inflight, timer, aliasActive, 
                                    termSent, termType, everStaleDrop >>
         /\ UNCHANGED << wAlive, pAlive, connSt, connHdrs, connWin, connLeft, 
                         nextTok, started, admitFailed, cancelled, reqStream, 
                         reqWin, grantsSent, portChunksSent, gotHdrs, gotChunk, 
                         termRecv, everPaused >>

WTerm == /\ pc["worker"] = "WTerm"
         /\ IF inflight # {}
               THEN /\ \E t \in inflight:
                         /\ inflight' = inflight \ {t}
                         /\ IF ~NoTerminateNotify
                               THEN /\ mbox' = Append(mbox, MErr(t, "worker_died"))
                                    /\ termSent' = [termSent EXCEPT ![t] = termSent[t] + 1]
                                    /\ termType' = [termType EXCEPT ![t] = IF TrackWitnesses THEN "worker_died" ELSE termType[t]]
                               ELSE /\ TRUE
                                    /\ UNCHANGED << mbox, termSent, termType >>
                    /\ pc' = [pc EXCEPT !["worker"] = "WTerm"]
               ELSE /\ pc' = [pc EXCEPT !["worker"] = "WDead"]
                    /\ UNCHANGED << mbox, inflight, termSent, termType >>
         /\ UNCHANGED << cmdChan, dataChan, aliasChan, wAlive, terminating, 
                         timer, aliasActive, pAlive, connSt, connHdrs, connWin, 
                         connLeft, nextTok, started, admitFailed, cancelled, 
                         reqStream, reqWin, grantsSent, portChunksSent, 
                         gotHdrs, gotChunk, termRecv, everPaused, 
                         everStaleDrop >>

WDead == /\ pc["worker"] = "WDead"
         /\ wAlive' = FALSE
         /\ aliasActive' = [x \in Tokens |-> FALSE]
         /\ pc' = [pc EXCEPT !["worker"] = "Done"]
         /\ UNCHANGED << cmdChan, dataChan, aliasChan, mbox, terminating, 
                         inflight, timer, pAlive, connSt, connHdrs, connWin, 
                         connLeft, nextTok, started, admitFailed, cancelled, 
                         reqStream, reqWin, grantsSent, portChunksSent, 
                         gotHdrs, gotChunk, termRecv, termSent, termType, 
                         everPaused, everStaleDrop >>

worker == WLoop \/ WTerm \/ WDead

PLoop == /\ pc["port"] = "PLoop"
         /\ IF pAlive
               THEN /\ \/ /\ cmdChan # <<>>
                          /\ LET cm == Head(cmdChan) IN
                               /\ cmdChan' = Tail(cmdChan)
                               /\ IF cm.typ = "req"
                                     THEN /\ connSt' = [connSt EXCEPT ![cm.r] = "run"]
                                          /\ connHdrs' = [connHdrs EXCEPT ![cm.r] = FALSE]
                                          /\ connWin' = [connWin EXCEPT ![cm.r] = cm.n]
                                          /\ \E bl \in 0..MaxChunks:
                                               connLeft' = [connLeft EXCEPT ![cm.r] = bl]
                                     ELSE /\ IF cm.typ = "cancel"
                                                THEN /\ connSt' = [connSt EXCEPT ![cm.r] = "none"]
                                                     /\ UNCHANGED connWin
                                                ELSE /\ IF connSt[cm.r] # "none" /\ connWin[cm.r] >= 0 /\ cm.n > 0
                                                           THEN /\ connWin' = [connWin EXCEPT ![cm.r] = connWin[cm.r] + cm.n]
                                                                /\ connSt' = [connSt EXCEPT ![cm.r] = "run"]
                                                           ELSE /\ TRUE
                                                                /\ UNCHANGED << connSt, 
                                                                                connWin >>
                                          /\ UNCHANGED << connHdrs, connLeft >>
                          /\ UNCHANGED <<dataChan, pAlive, portChunksSent, everPaused>>
                       \/ /\ \E t \in {x \in Tokens : connSt[x] = "run" /\ connLeft[x] > 0}:
                               IF reqStream[t]
                                  THEN /\ IF connWin[t] = 0
                                             THEN /\ connSt' = [connSt EXCEPT ![t] = "paused"]
                                                  /\ everPaused' = [everPaused EXCEPT ![t] = everPaused[t] \/ TrackWitnesses]
                                                  /\ UNCHANGED << dataChan, 
                                                                  connHdrs, 
                                                                  connWin, 
                                                                  connLeft, 
                                                                  portChunksSent >>
                                             ELSE /\ dataChan' = dataChan \o (IF connHdrs[t] THEN <<ChunkM(t)>>
                                                                              ELSE <<HdrsM(t), ChunkM(t)>>)
                                                  /\ connHdrs' = [connHdrs EXCEPT ![t] = TRUE]
                                                  /\ connLeft' = [connLeft EXCEPT ![t] = connLeft[t] - 1]
                                                  /\ portChunksSent' = [portChunksSent EXCEPT ![t] = portChunksSent[t] + 1]
                                                  /\ connWin' = [connWin EXCEPT ![t] = IF connWin[t] > 0 THEN connWin[t] - 1 ELSE connWin[t]]
                                                  /\ UNCHANGED << connSt, 
                                                                  everPaused >>
                                  ELSE /\ connLeft' = [connLeft EXCEPT ![t] = connLeft[t] - 1]
                                       /\ UNCHANGED << dataChan, connSt, 
                                                       connHdrs, connWin, 
                                                       portChunksSent, 
                                                       everPaused >>
                          /\ UNCHANGED <<cmdChan, pAlive>>
                       \/ /\ \E t \in {x \in Tokens : connSt[x] = "run" /\ connLeft[x] = 0}:
                               /\ IF reqStream[t]
                                     THEN /\ dataChan' = dataChan \o (IF connHdrs[t] THEN <<DoneM(t)>>
                                                                      ELSE <<HdrsM(t), DoneM(t)>>)
                                     ELSE /\ dataChan' = Append(dataChan, OkM(t))
                               /\ connSt' = [connSt EXCEPT ![t] = "none"]
                          /\ UNCHANGED <<cmdChan, pAlive, connHdrs, connWin, connLeft, portChunksSent, everPaused>>
                       \/ /\ \E t \in {x \in Tokens : connSt[x] \in {"run", "paused"}}:
                               /\ dataChan' = Append(dataChan, ErrM(t))
                               /\ connSt' = [connSt EXCEPT ![t] = "none"]
                          /\ UNCHANGED <<cmdChan, pAlive, connHdrs, connWin, connLeft, portChunksSent, everPaused>>
                       \/ /\ PortCanDie
                          /\ pAlive' = FALSE
                          /\ connSt' = [x \in Tokens |-> "none"]
                          /\ dataChan' = Append(dataChan, ExitM)
                          /\ UNCHANGED <<cmdChan, connHdrs, connWin, connLeft, portChunksSent, everPaused>>
                    /\ pc' = [pc EXCEPT !["port"] = "PLoop"]
               ELSE /\ pc' = [pc EXCEPT !["port"] = "Done"]
                    /\ UNCHANGED << cmdChan, dataChan, pAlive, connSt, 
                                    connHdrs, connWin, connLeft, 
                                    portChunksSent, everPaused >>
         /\ UNCHANGED << aliasChan, mbox, wAlive, terminating, inflight, timer, 
                         aliasActive, nextTok, started, admitFailed, cancelled, 
                         reqStream, reqWin, grantsSent, gotHdrs, gotChunk, 
                         termRecv, termSent, termType, everStaleDrop >>

port == PLoop

TFire == /\ pc["timers"] = "TFire"
         /\ \E t \in {x \in Tokens : timer[x] = "armed"}:
              timer' = [timer EXCEPT ![t] = "fired"]
         /\ pc' = [pc EXCEPT !["timers"] = "TFire"]
         /\ UNCHANGED << cmdChan, dataChan, aliasChan, mbox, wAlive, 
                         terminating, inflight, aliasActive, pAlive, connSt, 
                         connHdrs, connWin, connLeft, nextTok, started, 
                         admitFailed, cancelled, reqStream, reqWin, grantsSent, 
                         portChunksSent, gotHdrs, gotChunk, termRecv, termSent, 
                         termType, everPaused, everStaleDrop >>

timers == TFire

CLoop == /\ pc["caller"] = "CLoop"
         /\ \/ /\ nextTok <= NumReqs /\ wAlive /\ ~terminating
               /\ IF pAlive
                     THEN /\ \E s \in StreamChoices:
                               \E w \in IF s THEN WindowChoices ELSE {-1}:
                                 /\ started' = (started \cup {nextTok})
                                 /\ reqStream' = [reqStream EXCEPT ![nextTok] = s]
                                 /\ reqWin' = [reqWin EXCEPT ![nextTok] = w]
                                 /\ inflight' = (inflight \cup {nextTok})
                                 /\ timer' = [timer EXCEPT ![nextTok] = "armed"]
                                 /\ aliasActive' = [aliasActive EXCEPT ![nextTok] = TRUE]
                                 /\ cmdChan' = Append(cmdChan, ReqC(nextTok, w))
                          /\ UNCHANGED << terminating, admitFailed >>
                     ELSE /\ admitFailed' = (admitFailed \cup {nextTok})
                          /\ terminating' = TRUE
                          /\ UNCHANGED << cmdChan, inflight, timer, 
                                          aliasActive, started, reqStream, 
                                          reqWin >>
               /\ nextTok' = nextTok + 1
               /\ UNCHANGED <<aliasChan, mbox, cancelled, grantsSent, gotHdrs, gotChunk, termRecv>>
            \/ /\ mbox # <<>>
               /\ LET rm == Head(mbox) IN
                    /\ mbox' = Tail(mbox)
                    /\ Assert(termRecv[rm.r] = 0, 
                              "Failure of assertion at line 407, column 9.")
                    /\ IF rm.typ = "headers"
                          THEN /\ Assert(reqStream[rm.r] /\ ~gotHdrs[rm.r], 
                                         "Failure of assertion at line 409, column 11.")
                               /\ gotHdrs' = [gotHdrs EXCEPT ![rm.r] = TRUE]
                               /\ UNCHANGED << gotChunk, termRecv >>
                          ELSE /\ IF rm.typ = "chunk"
                                     THEN /\ Assert(reqStream[rm.r] /\ gotHdrs[rm.r], 
                                                    "Failure of assertion at line 412, column 11.")
                                          /\ gotChunk' = [gotChunk EXCEPT ![rm.r] = TRUE]
                                          /\ UNCHANGED termRecv
                                     ELSE /\ IF rm.typ = "done"
                                                THEN /\ Assert(reqStream[rm.r] /\ gotHdrs[rm.r], 
                                                               "Failure of assertion at line 415, column 11.")
                                                     /\ termRecv' = [termRecv EXCEPT ![rm.r] = termRecv[rm.r] + 1]
                                                ELSE /\ IF rm.typ = "resp"
                                                           THEN /\ Assert(~reqStream[rm.r] /\ ~gotHdrs[rm.r] /\ ~gotChunk[rm.r], 
                                                                          "Failure of assertion at line 418, column 11.")
                                                                /\ termRecv' = [termRecv EXCEPT ![rm.r] = termRecv[rm.r] + 1]
                                                           ELSE /\ termRecv' = [termRecv EXCEPT ![rm.r] = termRecv[rm.r] + 1]
                                          /\ UNCHANGED gotChunk
                               /\ UNCHANGED gotHdrs
               /\ UNCHANGED <<cmdChan, aliasChan, terminating, inflight, timer, aliasActive, nextTok, started, admitFailed, cancelled, reqStream, reqWin, grantsSent>>
            \/ /\ CallerCancels
               /\ \E t \in started \ cancelled:
                    /\ cancelled' = (cancelled \cup {t})
                    /\ IF aliasActive[t]
                          THEN /\ aliasChan' = Append(aliasChan, CancelC(t))
                          ELSE /\ TRUE
                               /\ UNCHANGED aliasChan
               /\ UNCHANGED <<cmdChan, mbox, terminating, inflight, timer, aliasActive, nextTok, started, admitFailed, reqStream, reqWin, grantsSent, gotHdrs, gotChunk, termRecv>>
            \/ /\ \E t \in {x \in started : reqStream[x] /\ reqWin[x] >= 0
                                            /\ grantsSent[x] < MaxGrants}:
                    /\ grantsSent' = [grantsSent EXCEPT ![t] = grantsSent[t] + 1]
                    /\ IF aliasActive[t]
                          THEN /\ aliasChan' = Append(aliasChan, FlowC(t, 1))
                          ELSE /\ TRUE
                               /\ UNCHANGED aliasChan
               /\ UNCHANGED <<cmdChan, mbox, terminating, inflight, timer, aliasActive, nextTok, started, admitFailed, cancelled, reqStream, reqWin, gotHdrs, gotChunk, termRecv>>
         /\ pc' = [pc EXCEPT !["caller"] = "CLoop"]
         /\ UNCHANGED << dataChan, wAlive, pAlive, connSt, connHdrs, connWin, 
                         connLeft, portChunksSent, termSent, termType, 
                         everPaused, everStaleDrop >>

caller == CLoop

Next == worker \/ port \/ timers \/ caller

Spec == /\ Init /\ [][Next]_vars
        /\ WF_vars(worker)
        /\ WF_vars(port)
        /\ WF_vars(timers)

\* END TRANSLATION

(***************************************************************************)
(* Safety.                                                                 *)
(***************************************************************************)

TypeOK ==
    /\ inflight \subseteq Tokens
    /\ started \subseteq Tokens
    /\ admitFailed \subseteq Tokens
    /\ cancelled \subseteq Tokens
    /\ started \cap admitFailed = {}
    /\ timer \in [Tokens -> {"off", "armed", "fired"}]
    /\ connSt \in [Tokens -> {"none", "run", "paused"}]
    /\ \A t \in Tokens : termSent[t] \in 0..2
    /\ \A t \in Tokens : connLeft[t] \in 0..MaxChunks

\* The headline claim (katipo_worker.erl admit/finish_req docs): an admitted
\* request resolves at most once, across completion, error, timeout, cancel
\* and worker death racing each other.
AtMostOneTerminal == \A t \in Tokens : termSent[t] <= 1

\* Why it holds: presence in Reqs <=> not yet resolved. Every delivery path
\* first takes the request out of Reqs, and every path checks membership.
InflightMeansUnresolved == \A t \in Tokens : t \in inflight => termSent[t] = 0

\* A request that failed admission created no delivery obligation.
AdmitFailedSilent == \A t \in Tokens : t \in admitFailed => termSent[t] = 0

\* The alias discipline that makes late cancel/flow sends safe: while the
\* worker is serving its loop, an active alias always denotes an in-flight
\* request. (Suspended during terminate/2, where aliases die with the
\* process rather than one at a time.)
AliasDiscipline ==
    pc["worker"] = "WLoop" =>
        \A t \in Tokens : aliasActive[t] => t \in inflight

\* Backpressure accounting: a bounded-window stream never emits more chunk
\* messages than its initial window plus the credits the caller granted.
WindowBound ==
    \A t \in Tokens :
        reqWin[t] >= 0 => portChunksSent[t] <= reqWin[t] + grantsSent[t]

(***************************************************************************)
(* Liveness. The claim in the async_req docs: every accepted request        *)
(* produces exactly one terminal message - even if the network stalls        *)
(* (request timer), the consumer stops granting credits (request timer       *)
(* keeps running while paused), or the port dies (terminate/2 notifies).     *)
(* A cancelled request is exempt: cancellation is silent by contract.        *)
(***************************************************************************)
EventuallyResolved ==
    \A t \in Tokens : (t \in started) ~> (termSent[t] = 1 \/ t \in cancelled)

(***************************************************************************)
(* Witnesses: negations of states the model must be able to reach. Each     *)
(* witness config EXPECTS a violation; a pass means the model lost teeth.   *)
(***************************************************************************)

\* the timeout path delivers operation_timedout
NoTimeoutEver == ~\E t \in Tokens : termType[t] = "timeout"

\* a window-paused stream can resume on credits and still complete
NoPausedDone == ~\E t \in Tokens : everPaused[t] /\ termType[t] = "done"

\* port death reaches the caller as worker_died
NoWorkerDied == ~\E t \in Tokens : termType[t] = "worker_died"

\* the stale-message discipline actually exercises its drop path
NoStaleDrops == ~everStaleDrop

\* a cancel actually lands: the request leaves Reqs with no terminal ever sent
NoSilentCancel ==
    ~\E t \in Tokens :
        t \in (started \cap cancelled) /\ t \notin inflight /\ termSent[t] = 0

(***************************************************************************)
(* Readable traces for debugging: add `ALIAS Alias` to a config and rerun.  *)
(* Needs a tla2tools.jar with config ALIAS support (1.7.0+ mainline); the   *)
(* jar this repo has been checked with does not accept it, so the operator  *)
(* is kept here for ad-hoc use rather than wired into the configs.          *)
(***************************************************************************)
Alias ==
    [ worker    |-> pc["worker"],
      port      |-> pc["port"],
      inflight  |-> inflight,
      conn      |-> [t \in Tokens |->
                       <<connSt[t], "win", connWin[t], "left", connLeft[t]>>],
      timer     |-> timer,
      dataChan  |-> [i \in DOMAIN dataChan |->
                       <<dataChan[i].typ, dataChan[i].r>>],
      cmdChan   |-> [i \in DOMAIN cmdChan |->
                       <<cmdChan[i].typ, cmdChan[i].r>>],
      aliasChan |-> [i \in DOMAIN aliasChan |->
                       <<aliasChan[i].typ, aliasChan[i].r>>],
      mbox      |-> [i \in DOMAIN mbox |->
                       <<mbox[i].typ, mbox[i].r, mbox[i].why>>],
      termSent  |-> termSent,
      termType  |-> termType,
      cancelled |-> cancelled ]

===============================================================================
