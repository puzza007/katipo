-------------------------------- MODULE KatipoConn ------------------------------
(***************************************************************************)
(* WHAT THIS MODELS. Ownership and lifetime of one streaming transfer      *)
(* (ConnInfo) inside the C port's single-threaded libevent loop            *)
(* (c_src/katipo.c), across the three things that can end it - completion, *)
(* an Erlang cancel (cancel/2 or the worker's request timer, both arrive   *)
(* as the cancel command) - and the one thing that re-enters it: a flow    *)
(* grant resuming a paused transfer. The subtle part is that a paused      *)
(* transfer's pending body buffer is owned by CURL, not by ConnInfo, and   *)
(* that flow_conn's curl_easy_pause(CONT) can synchronously run write_cb   *)
(* and then check_multi_info, which can FREE the very conn flow_conn is    *)
(* holding a pointer to.                                                   *)
(*                                                                         *)
(* Real code (c_src/katipo.c):                                             *)
(*   - free_conn (~683): unlink, curl_multi_remove_handle, free fields,    *)
(*     curl_easy_cleanup (which releases curl's held pause buffer)         *)
(*   - find_conn (~700): identity lookup {pid, ref} in active_conns - the  *)
(*     ONLY way a command reaches a conn; a freed conn is unreachable      *)
(*   - cancel_conn (~713): find_conn then free_conn; NULL -> no-op         *)
(*   - flow_conn (~723): credits first, then CONT, socket_action,          *)
(*     check_multi_info; does not touch conn after the kick               *)
(*   - check_multi_info (~745): send terminal message, free_conn           *)
(*   - write_cb (~876): window == 0 -> paused, CURL_WRITEFUNC_PAUSE        *)
(*                                                                         *)
(* THE ACTORS:                                                             *)
(*   - loop   - the C event loop, fair, one event per step: a socket read  *)
(*     (write_cb), transfer completion, or one Erlang command.             *)
(*   - erlang - the worker sending cancel / flow commands; NOT fair, and   *)
(*     bounded by MaxCmds.                                                 *)
(*                                                                         *)
(* PROPERTIES: no double free, no use after free, curl's held buffer never *)
(* outlives its easy handle, and no body chunk is emitted after the conn   *)
(* is gone. The sabotage knobs remove the identity lookup and touch the    *)
(* conn after the kick, to prove the invariants notice.                    *)
(*                                                                         *)
(* OUT OF SCOPE: the credit arithmetic (KatipoFlow proves credits-first);  *)
(* the Erlang-side stale-message drop (KatipoReq); multiple transfers      *)
(* (they share nothing but the multi handle).                              *)
(***************************************************************************)
EXTENDS Naturals, Sequences, TLC

CONSTANTS
    MaxCmds,          \* Erlang commands per behaviour
    MaxChunks,        \* body chunks before the transfer completes
    \* SABOTAGE: TRUE lets cancel/flow skip find_conn and act on the conn
    \* pointer whether or not it is still in active_conns. MUST violate
    \* NoDoubleFree / NoUseAfterFree.
    SkipIdentityLookup,
    \* SABOTAGE: TRUE makes flow_conn read conn after curl_easy_pause /
    \* check_multi_info returned. MUST violate NoUseAfterFree.
    TouchAfterKick

(* --algorithm KatipoConn

variables
    conn     = "running",    \* "running" | "paused" | "freed"
    window   = 1,            \* credits (bounded stream_window)
    curlHold = FALSE,        \* curl holds a pause buffer for this easy handle
    left     = MaxChunks,    \* chunks the server still has to send
    cmds     = <<>>,         \* commands from Erlang, FIFO
    sent     = 0,            \* commands issued
    \* ghosts
    doubleFree = FALSE,
    uaf        = FALSE,
    chunkAfterFree = FALSE,
    everPausedCancel = FALSE;

macro free_conn() begin
  if conn = "freed" then doubleFree := TRUE; end if;
  \* curl_easy_cleanup releases whatever curl buffered across the pause
  curlHold := FALSE;
  conn := "freed";
end macro;

macro write_cb() begin
  \* one buffer arrives from the socket (or is re-delivered after CONT)
  if conn = "freed" then
    chunkAfterFree := TRUE;
  elsif window = 0 then
    conn := "paused";
    curlHold := TRUE;
  else
    curlHold := FALSE;
    window := window - 1;
    left := left - 1;
  end if;
end macro;

\* NOT fair, bounded: the worker may send cancel or flow at any time.
process erlang = "erlang"
begin
ESend:
  while sent < MaxCmds do
    sent := sent + 1;
    either cmds := Append(cmds, "cancel");
    or     cmds := Append(cmds, "flow");
    end either;
  end while;
end process;

fair process loop = "loop"
variables cmd = "";
begin
LEvent:
  while TRUE do
    either
      \* socket readable: curl calls write_cb with the next buffer
      await conn = "running" /\ left > 0;
      write_cb();
    or
      \* transfer complete: check_multi_info sends done and frees
      await conn = "running" /\ left = 0;
      free_conn();
    or
      \* one command from Erlang
      await cmds # <<>>;
      cmd := Head(cmds);
      cmds := Tail(cmds);
      if cmd = "cancel" then
        if SkipIdentityLookup \/ conn # "freed" then
          if conn = "paused" then everPausedCancel := TRUE; end if;
          free_conn();
        end if;
      else
        \* flow_conn: find_conn, credits first, CONT re-enters write_cb
        if SkipIdentityLookup \/ conn # "freed" then
          if conn = "freed" then
            uaf := TRUE;
            window := window + 1;
          elsif conn = "paused" then
            \* credits first (window >= 1), then CONT synchronously
            \* re-delivers the held buffer: write_cb consumes one credit and
            \* one chunk (net window unchanged), curl drops its hold; then
            \* check_multi_info inside flow_conn may complete and free.
            curlHold := FALSE;
            left := left - 1;
            if left = 0 then
              conn := "freed";
              uaf := TouchAfterKick;
            else
              conn := "running";
            end if;
          else
            window := window + 1;
          end if;
        end if;
      end if;
    end either;
  end while;
end process;

end algorithm; *)

\* Translate with:  java -cp tla2tools.jar pcal.trans formal/KatipoConn.tla

\* BEGIN TRANSLATION
VARIABLES conn, window, curlHold, left, cmds, sent, doubleFree, uaf, 
          chunkAfterFree, everPausedCancel, pc, cmd

vars == << conn, window, curlHold, left, cmds, sent, doubleFree, uaf, 
           chunkAfterFree, everPausedCancel, pc, cmd >>

ProcSet == {"erlang"} \cup {"loop"}

Init == (* Global variables *)
        /\ conn = "running"
        /\ window = 1
        /\ curlHold = FALSE
        /\ left = MaxChunks
        /\ cmds = <<>>
        /\ sent = 0
        /\ doubleFree = FALSE
        /\ uaf = FALSE
        /\ chunkAfterFree = FALSE
        /\ everPausedCancel = FALSE
        (* Process loop *)
        /\ cmd = ""
        /\ pc = [self \in ProcSet |-> CASE self = "erlang" -> "ESend"
                                        [] self = "loop" -> "LEvent"]

ESend == /\ pc["erlang"] = "ESend"
         /\ IF sent < MaxCmds
               THEN /\ sent' = sent + 1
                    /\ \/ /\ cmds' = Append(cmds, "cancel")
                       \/ /\ cmds' = Append(cmds, "flow")
                    /\ pc' = [pc EXCEPT !["erlang"] = "ESend"]
               ELSE /\ pc' = [pc EXCEPT !["erlang"] = "Done"]
                    /\ UNCHANGED << cmds, sent >>
         /\ UNCHANGED << conn, window, curlHold, left, doubleFree, uaf, 
                         chunkAfterFree, everPausedCancel, cmd >>

erlang == ESend

LEvent == /\ pc["loop"] = "LEvent"
          /\ \/ /\ conn = "running" /\ left > 0
                /\ IF conn = "freed"
                      THEN /\ chunkAfterFree' = TRUE
                           /\ UNCHANGED << conn, window, curlHold, left >>
                      ELSE /\ IF window = 0
                                 THEN /\ conn' = "paused"
                                      /\ curlHold' = TRUE
                                      /\ UNCHANGED << window, left >>
                                 ELSE /\ curlHold' = FALSE
                                      /\ window' = window - 1
                                      /\ left' = left - 1
                                      /\ conn' = conn
                           /\ UNCHANGED chunkAfterFree
                /\ UNCHANGED <<cmds, doubleFree, uaf, everPausedCancel, cmd>>
             \/ /\ conn = "running" /\ left = 0
                /\ IF conn = "freed"
                      THEN /\ doubleFree' = TRUE
                      ELSE /\ TRUE
                           /\ UNCHANGED doubleFree
                /\ curlHold' = FALSE
                /\ conn' = "freed"
                /\ UNCHANGED <<window, left, cmds, uaf, chunkAfterFree, everPausedCancel, cmd>>
             \/ /\ cmds # <<>>
                /\ cmd' = Head(cmds)
                /\ cmds' = Tail(cmds)
                /\ IF cmd' = "cancel"
                      THEN /\ IF SkipIdentityLookup \/ conn # "freed"
                                 THEN /\ IF conn = "paused"
                                            THEN /\ everPausedCancel' = TRUE
                                            ELSE /\ TRUE
                                                 /\ UNCHANGED everPausedCancel
                                      /\ IF conn = "freed"
                                            THEN /\ doubleFree' = TRUE
                                            ELSE /\ TRUE
                                                 /\ UNCHANGED doubleFree
                                      /\ curlHold' = FALSE
                                      /\ conn' = "freed"
                                 ELSE /\ TRUE
                                      /\ UNCHANGED << conn, curlHold, 
                                                      doubleFree, 
                                                      everPausedCancel >>
                           /\ UNCHANGED << window, left, uaf >>
                      ELSE /\ IF SkipIdentityLookup \/ conn # "freed"
                                 THEN /\ IF conn = "freed"
                                            THEN /\ uaf' = TRUE
                                                 /\ window' = window + 1
                                                 /\ UNCHANGED << conn, 
                                                                 curlHold, 
                                                                 left >>
                                            ELSE /\ IF conn = "paused"
                                                       THEN /\ curlHold' = FALSE
                                                            /\ left' = left - 1
                                                            /\ IF left' = 0
                                                                  THEN /\ conn' = "freed"
                                                                       /\ uaf' = TouchAfterKick
                                                                  ELSE /\ conn' = "running"
                                                                       /\ uaf' = uaf
                                                            /\ UNCHANGED window
                                                       ELSE /\ window' = window + 1
                                                            /\ UNCHANGED << conn, 
                                                                            curlHold, 
                                                                            left, 
                                                                            uaf >>
                                 ELSE /\ TRUE
                                      /\ UNCHANGED << conn, window, curlHold, 
                                                      left, uaf >>
                           /\ UNCHANGED << doubleFree, everPausedCancel >>
                /\ UNCHANGED chunkAfterFree
          /\ pc' = [pc EXCEPT !["loop"] = "LEvent"]
          /\ sent' = sent

loop == LEvent

Next == erlang \/ loop

Spec == /\ Init /\ [][Next]_vars
        /\ WF_vars(loop)

\* END TRANSLATION

TypeOK ==
    /\ conn \in {"running", "paused", "freed"}
    /\ window \in 0..(1 + MaxCmds)
    /\ left \in 0..MaxChunks

NoDoubleFree      == ~doubleFree
NoUseAfterFree    == ~uaf
NoChunkAfterFree  == ~chunkAfterFree
\* curl's pause buffer lives and dies with the easy handle
HeldBufferOwned   == conn = "freed" => ~curlHold
\* a paused transfer is exactly one that curl is holding a buffer for
PausedIffHeld     == (conn = "paused") <=> curlHold

\* Witness: cancelling a PAUSED transfer is exercised. EXPECTED: violated.
NeverPausedCancel == ~everPausedCancel

===============================================================================
