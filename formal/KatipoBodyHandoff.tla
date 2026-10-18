-------------------------- MODULE KatipoBodyHandoff --------------------------
(***************************************************************************)
(* Ownership of a buffered response body in the C port (c_src/katipo.c).  *)
(* write_cb appends the body to conn->body, an evbuffer;                   *)
(* send_ok_to_erlang moves its chains into the output evbuffer             *)
(* (evbuffer_add_buffer) instead of copying them.                          *)
(*                                                                         *)
(*  Complete(c)  check_multi_info, CURLE_OK, buffered request:             *)
(*               send_ok_to_erlang appends the frame to the output         *)
(*               evbuffer -- length, prefix, body, suffix -- then          *)
(*               free_conn frees conn->body. With ZeroCopy the body        *)
(*               segment is moved and libevent frees it once written; with *)
(*               HandOver the move leaves conn->body empty, so free_conn   *)
(*               frees nothing of it. Without ZeroCopy the body is copied  *)
(*               in and free_conn frees the original. All of it runs in    *)
(*               one libevent callback, so atomically, unless AtomicFrame  *)
(*               is FALSE (a mutation).                                    *)
(*  Chunk(s)     a streaming transfer's send_chunk_to_erlang: another      *)
(*               frame appended to the same evbuffer, from any callback.   *)
(*  Drain        libevent writes the head of the evbuffer to the pipe,     *)
(*               possibly only part of a segment; a moved body is freed    *)
(*               once its last byte has been written.                      *)
(*  The reader (katipo_worker, {packet, 4}) sees frames in pipe order.     *)
(*                                                                         *)
(* Out of scope: process exit (the OS reclaims everything, and nothing    *)
(* reads a half-written frame from a dead port); the bytes themselves      *)
(* (a body segment is two units, enough for a partial write); a body       *)
(* spanning several chains (each is freed as it drains, like the one       *)
(* segment here).                                                          *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
  Buffered,     \* buffered requests (set of model values)
  Streams,      \* streaming requests sending one chunk each
  ZeroCopy,     \* TRUE: the body is moved; FALSE: the previous copy
  HandOver,     \* the move leaves conn->body empty (shipped: TRUE)
  AtomicFrame   \* the frame is appended within one callback (TRUE)

VARIABLES
  phase,      \* Buffered -> "running" | "done"
  empty,      \* Buffered -> body has zero bytes
  frees,      \* Buffered -> times the body's bytes were freed
  next,       \* Buffered -> next frame segment to append (non-atomic mutation)
  chunked,    \* Streams  -> chunk frame sent
  out,        \* the output evbuffer: segments
  pipe,       \* parts written to the pipe, in order
  uaf         \* a write read bytes from an already freed body

vars == <<phase, empty, frees, next, chunked, out, pipe, uaf>>

Seg(r, p, isRef, rem) == [conn |-> r, part |-> p, ref |-> isRef, rem |-> rem]

\* The segments of request r's frame; an empty body adds none.
Segs(r) ==
  IF r \in Streams
  THEN <<Seg(r, "len", FALSE, 1), Seg(r, "prefix", FALSE, 1),
         Seg(r, "chunk", FALSE, 1)>>
  ELSE <<Seg(r, "len", FALSE, 1), Seg(r, "prefix", FALSE, 1)>>
       \o (IF empty[r] THEN <<>> ELSE <<Seg(r, "body", ZeroCopy, 2)>>)
       \o <<Seg(r, "suffix", FALSE, 1)>>

\* free_conn: frees the body's bytes unless the move took them.
Finish(c) ==
  /\ frees' = [frees EXCEPT ![c] = @ + IF ~empty[c] /\ ~(ZeroCopy /\ HandOver)
                                       THEN 1 ELSE 0]
  /\ phase' = [phase EXCEPT ![c] = "done"]

Init ==
  /\ phase = [c \in Buffered |-> "running"]
  /\ empty \in [Buffered -> BOOLEAN]
  /\ frees = [c \in Buffered |-> 0]
  /\ next = [c \in Buffered |-> 1]
  /\ chunked = [s \in Streams |-> FALSE]
  /\ out = <<>>
  /\ pipe = <<>>
  /\ uaf = FALSE

\* send_ok_to_erlang + free_conn in one callback.
CompleteAtomic(c) ==
  /\ AtomicFrame
  /\ phase[c] = "running"
  /\ out' = out \o Segs(c)
  /\ Finish(c)
  /\ UNCHANGED <<empty, next, chunked, pipe, uaf>>

\* Mutation: the frame's segments are appended across callbacks.
CompleteStep(c) ==
  /\ ~AtomicFrame
  /\ phase[c] = "running"
  /\ out' = Append(out, Segs(c)[next[c]])
  /\ IF next[c] = Len(Segs(c)) THEN Finish(c) ELSE UNCHANGED <<frees, phase>>
  /\ next' = [next EXCEPT ![c] = @ + 1]
  /\ UNCHANGED <<empty, chunked, pipe, uaf>>

Chunk(s) ==
  /\ ~chunked[s]
  /\ out' = out \o Segs(s)
  /\ chunked' = [chunked EXCEPT ![s] = TRUE]
  /\ UNCHANGED <<phase, empty, frees, next, pipe, uaf>>

\* Write one unit of the head segment. A moved body's bytes are the body's
\* own, so reading them after they were freed is a use after free.
Drain ==
  /\ out /= <<>>
  /\ LET h == Head(out) IN
       /\ uaf' = (uaf \/ (h.ref /\ frees[h.conn] > 0))
       /\ IF h.rem > 1
          THEN /\ out' = <<[h EXCEPT !.rem = @ - 1]>> \o Tail(out)
               /\ UNCHANGED <<pipe, frees>>
          ELSE /\ out' = Tail(out)
               /\ pipe' = Append(pipe, [conn |-> h.conn, part |-> h.part])
               \* libevent frees a moved chain once it is written
               /\ frees' = IF h.ref THEN [frees EXCEPT ![h.conn] = @ + 1]
                           ELSE frees
  /\ UNCHANGED <<phase, empty, next, chunked>>

\* Every transfer finished and the evbuffer drained: the run is over (not
\* a deadlock).
Finished ==
  /\ \A c \in Buffered : phase[c] = "done"
  /\ \A s \in Streams : chunked[s]
  /\ out = <<>>
  /\ UNCHANGED vars

Next ==
  \/ \E c \in Buffered : CompleteAtomic(c) \/ CompleteStep(c)
  \/ \E s \in Streams : Chunk(s)
  \/ Drain
  \/ Finished

Spec == Init /\ [][Next]_vars /\ WF_vars(Drain)

-----------------------------------------------------------------------------
(* Properties *)

TypeOK ==
  /\ phase \in [Buffered -> {"running", "done"}]
  /\ frees \in [Buffered -> 0..2]
  /\ uaf \in BOOLEAN

\* No body is freed twice.
NoDoubleFree == \A c \in Buffered : frees[c] <= 1

\* No body byte is written after it was freed.
NoUseAfterFree == ~uaf

\* Once everything has been written, every non-empty body was freed.
NoLeak ==
  (out = <<>> /\ \A c \in Buffered : phase[c] = "done") =>
    \A c \in Buffered : frees[c] = IF empty[c] THEN 0 ELSE 1

\* The reader sees whole frames: each "len" is followed by the rest of the
\* same request's frame, with nothing from another frame in between.
FrameOf(r) == [i \in DOMAIN Segs(r) |-> Segs(r)[i].part]

RECURSIVE Framed(_)
Framed(p) ==
  \/ p = <<>>
  \/ /\ Head(p).part = "len"
     /\ LET r == Head(p).conn
            f == FrameOf(r)
            n == Len(f)
        IN \/ /\ Len(p) >= n
              /\ \A i \in 1..n : p[i] = [conn |-> r, part |-> f[i]]
              /\ Framed(SubSeq(p, n + 1, Len(p)))
           \/ /\ Len(p) < n           \* the tail of the pipe: a frame in flight
              /\ \A i \in 1..Len(p) : p[i] = [conn |-> r, part |-> f[i]]

WholeFrames == Framed(pipe)

\* Every handed-over body is eventually freed.
EventuallyFreed ==
  \A c \in Buffered : (phase[c] = "done" /\ ~empty[c]) ~> (frees[c] >= 1)

=============================================================================
