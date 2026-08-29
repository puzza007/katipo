-------------------------------- MODULE KatipoFlow --------------------------------
(***************************************************************************)
(* WHAT THIS MODELS. The inside of the C port's flow_conn (katipo.c ~723), *)
(* which KatipoReq treats as one opaque atomic command. The subtle part is *)
(* its re-entrancy: curl_easy_pause(CURLPAUSE_CONT) can SYNCHRONOUSLY      *)
(* re-invoke write_cb with the buffer curl held across the pause, and that *)
(* re-entrant write_cb consults conn->window at that instant. The code     *)
(* adds the credits BEFORE resuming, with only a comment ("Credits first:  *)
(* curl may invoke write_cb synchronously inside curl_easy_pause...")      *)
(* carrying the reason. This model makes the ordering a checkable          *)
(* property: with the real order, a granted credit delivers the held       *)
(* chunk; with the swapped order the re-entrant write_cb still sees        *)
(* window = 0, re-pauses, and the credit lands only after - each pause     *)
(* silently EATS one credit, and a consumer that granted exactly enough    *)
(* stalls forever (in the full system: a spurious operation_timedout).     *)
(*                                                                         *)
(* Real code (file:line as of commit 06f0138):                             *)
(*   - c_src/katipo.c  flow_conn: credits, then resume + kick (~723..742)  *)
(*   - c_src/katipo.c  write_cb streaming branch: window = 0 -> paused = 1 *)
(*     and CURL_WRITEFUNC_PAUSE (curl keeps the buffer, re-delivers on     *)
(*     CONT); else send chunk, window-- (~880..905)                        *)
(*   - c_src/katipo.c  check_multi_info completion (~744..790)             *)
(*                                                                         *)
(* THE ACTORS:                                                             *)
(*   - port     - fair. write_cb / flow_conn / completion are each one     *)
(*     atomic libevent callback; the fine grain lives INSIDE flow_conn,    *)
(*     where the CreditsFirst constant switches the internal order.        *)
(*   - consumer - fair HERE (it grants all its credits): the question is   *)
(*     whether granted credits are honoured, not what happens when the     *)
(*     consumer walks away - KatipoReq's timer liveness covers that.       *)
(*                                                                         *)
(* ABSTRACTION CHOICES:                                                    *)
(*   - The network is folded into write_cb (fair): data is assumed to      *)
(*     keep arriving, because the credit protocol is the question here.    *)
(*   - paused implies curl holds exactly the buffer that hit window = 0;   *)
(*     re-delivery on resume = delivering that chunk (chunksLeft was not   *)
(*     decremented at pause time, so no separate "held" flag is needed).   *)
(*   - Grants arrive one credit at a time (update_flow batching only       *)
(*     changes arithmetic, not ordering).                                  *)
(*                                                                         *)
(* OUT OF SCOPE: the Erlang side and cancel/timeout (KatipoReq); unbounded *)
(* windows (never pause, nothing to check); multiple transfers (flow_conn  *)
(* touches one conn).                                                      *)
(***************************************************************************)
EXTENDS Naturals, TLC

CONSTANTS
    MaxChunks,     \* body chunks the network will deliver
    StreamWindow,  \* initial chunk credits (stream_window)
    MaxGrants,     \* update_flow credits the consumer will grant
    \* TRUE  = the real flow_conn order: window += n BEFORE curl_easy_pause.
    \* FALSE = the swapped order the code comment warns against: resume
    \* first, so the re-entrant write_cb still sees the old window.
    CreditsFirst

(* --algorithm KatipoFlow

variables
    window      = StreamWindow,
    paused      = FALSE,      \* paused with curl holding the triggering buffer
    chunksLeft  = MaxChunks,
    granted     = 0,          \* credits the consumer has issued
    pendingGrants = 0,        \* flow commands not yet processed by the port
    done        = FALSE,
    everPaused  = FALSE;

define
  \* chunks handed to the Erlang side; every delivery consumes exactly one
  \* network chunk, so this is pure bookkeeping, not extra state
  delivered == MaxChunks - chunksLeft
end define;

fair process consumer = "consumer"
begin
CGrant:
  while granted < MaxGrants do
    granted := granted + 1;
    pendingGrants := pendingGrants + 1;
  end while;
end process;

fair process port = "port"
begin
PLoop:
  while ~done do
    either
      \* --- write_cb: a chunk arrives (socket reads stop while paused) ---
      await ~paused /\ chunksLeft > 0;
      if window = 0 then
        paused := TRUE;              \* CURL_WRITEFUNC_PAUSE; buffer held
        everPaused := TRUE;
      else
        chunksLeft := chunksLeft - 1;
        window := window - 1;
      end if;
    or
      \* --- flow_conn: one credit; atomic, but internally ordered ---
      await pendingGrants > 0;
      pendingGrants := pendingGrants - 1;
      if ~CreditsFirst /\ paused /\ window = 0 then
        \* SWAPPED order only: CURLPAUSE_CONT first, so the re-entrant
        \* write_cb still sees window = 0 and re-pauses; the credit lands
        \* too late -- paused stays TRUE, the wakeup is lost
        window := window + 1;
      elsif paused then
        \* the re-entrant write_cb delivers the held buffer. Real order:
        \* +1 credit then -1 delivery. Swapped order reaches here only
        \* with window > 0: -1 delivery then +1 late credit. Either way
        \* the window is net unchanged.
        paused := FALSE;
        chunksLeft := chunksLeft - 1;
      else
        window := window + 1;
      end if;
    or
      \* --- check_multi_info: transfer complete ---
      await chunksLeft = 0 /\ ~paused;
      done := TRUE;
    end either;
  end while;
end process;

end algorithm; *)

\* Translate with:  java -cp tla2tools.jar pcal.trans formal/KatipoFlow.tla

\* BEGIN TRANSLATION
VARIABLES window, paused, chunksLeft, granted, pendingGrants, done, 
          everPaused, pc

(* define statement *)
delivered == MaxChunks - chunksLeft


vars == << window, paused, chunksLeft, granted, pendingGrants, done, 
           everPaused, pc >>

ProcSet == {"consumer"} \cup {"port"}

Init == (* Global variables *)
        /\ window = StreamWindow
        /\ paused = FALSE
        /\ chunksLeft = MaxChunks
        /\ granted = 0
        /\ pendingGrants = 0
        /\ done = FALSE
        /\ everPaused = FALSE
        /\ pc = [self \in ProcSet |-> CASE self = "consumer" -> "CGrant"
                                        [] self = "port" -> "PLoop"]

CGrant == /\ pc["consumer"] = "CGrant"
          /\ IF granted < MaxGrants
                THEN /\ granted' = granted + 1
                     /\ pendingGrants' = pendingGrants + 1
                     /\ pc' = [pc EXCEPT !["consumer"] = "CGrant"]
                ELSE /\ pc' = [pc EXCEPT !["consumer"] = "Done"]
                     /\ UNCHANGED << granted, pendingGrants >>
          /\ UNCHANGED << window, paused, chunksLeft, done, everPaused >>

consumer == CGrant

PLoop == /\ pc["port"] = "PLoop"
         /\ IF ~done
               THEN /\ \/ /\ ~paused /\ chunksLeft > 0
                          /\ IF window = 0
                                THEN /\ paused' = TRUE
                                     /\ everPaused' = TRUE
                                     /\ UNCHANGED << window, chunksLeft >>
                                ELSE /\ chunksLeft' = chunksLeft - 1
                                     /\ window' = window - 1
                                     /\ UNCHANGED << paused, everPaused >>
                          /\ UNCHANGED <<pendingGrants, done>>
                       \/ /\ pendingGrants > 0
                          /\ pendingGrants' = pendingGrants - 1
                          /\ IF ~CreditsFirst /\ paused /\ window = 0
                                THEN /\ window' = window + 1
                                     /\ UNCHANGED << paused, chunksLeft >>
                                ELSE /\ IF paused
                                           THEN /\ paused' = FALSE
                                                /\ chunksLeft' = chunksLeft - 1
                                                /\ UNCHANGED window
                                           ELSE /\ window' = window + 1
                                                /\ UNCHANGED << paused, 
                                                                chunksLeft >>
                          /\ UNCHANGED <<done, everPaused>>
                       \/ /\ chunksLeft = 0 /\ ~paused
                          /\ done' = TRUE
                          /\ UNCHANGED <<window, paused, chunksLeft, pendingGrants, everPaused>>
                    /\ pc' = [pc EXCEPT !["port"] = "PLoop"]
               ELSE /\ pc' = [pc EXCEPT !["port"] = "Done"]
                    /\ UNCHANGED << window, paused, chunksLeft, pendingGrants, 
                                    done, everPaused >>
         /\ UNCHANGED granted

port == PLoop

(* Allow infinite stuttering to prevent deadlock on termination. *)
Terminating == /\ \A self \in ProcSet: pc[self] = "Done"
               /\ UNCHANGED vars

Next == consumer \/ port
           \/ Terminating

Spec == /\ Init /\ [][Next]_vars
        /\ WF_vars(consumer)
        /\ WF_vars(port)

Termination == <>(\A self \in ProcSet: pc[self] = "Done")

\* END TRANSLATION

TypeOK ==
    /\ window \in 0..(StreamWindow + MaxGrants)
    /\ chunksLeft \in 0..MaxChunks
    /\ pendingGrants \in 0..MaxGrants

\* Backpressure accounting, as in KatipoReq: never more chunks than the
\* initial window plus the granted credits.
WindowBound == delivered <= StreamWindow + granted

(***************************************************************************)
(* The point: when the consumer grants enough credits for the whole body   *)
(* (configure MaxChunks = StreamWindow + MaxGrants), the transfer          *)
(* completes. EXPECTED: holds with CreditsFirst, VIOLATED with the swapped *)
(* order (the stall trace shows the eaten credit), and holds again with    *)
(* one surplus grant even when swapped - the defect is a credit LEAK per   *)
(* pause, not a hard deadlock.                                             *)
(***************************************************************************)
EventuallyDone == <>done

\* Witness: the pause path is actually exercised. EXPECTED: violated.
NoPauseEver == ~everPaused

===============================================================================
