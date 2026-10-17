import KatipoProofs.Flow.Proofs
import KatipoProofs.Flow.Counterexamples
import KatipoProofs.Flow.Simplify

/-!
# Flow control: headline statements (frozen)

Proofs live in `Flow/Proofs.lean` and `Flow/Counterexamples.lean` under
the `_proof` suffix; this file pins what was agreed and only delegates.
-/

namespace KatipoProofs.Flow.Statements
open KatipoProofs.Flow

/-- While the worker holds the request and the C conn exists, all `W`
credits are accounted for (`CreditConservation`). -/
theorem credit_conservation (P : Params) (s : St) (h : Reach P s)
    (hr : s.inReqs = true) (hl : s.live = true) : credits s = P.W := by
  apply credit_conservation_proof <;> assumption

/-- At most `W` chunks are ever buffered between the C port and the
consumer's code (`BoundedBuffering`), for every window and body size. -/
theorem bounded_buffering (P : Params) (s : St) (h : Reach P s) :
    outstanding s ≤ P.W := by
  apply bounded_buffering_proof <;> assumption

/-- A `done` means the whole body arrived (`NoLostChunks`). -/
theorem no_lost_chunks (P : Params) (s : St) (h : Reach P s)
    (hd : s.seenDone = true) : s.chunksSeen = P.total := by
  apply no_lost_chunks_proof <;> assumption

/-- With the shipped `flow_conn` ordering, katipo's `paused` flag always
agrees with libcurl's pause state (`PausedAgrees`, strengthened to hold
inside `curl_easy_pause` too). -/
theorem paused_agrees (P : Params) (hc : P.clearFirst = true) (s : St)
    (h : Reach P s) : s.paused = s.curlPaused := by
  apply paused_agrees_proof <;> assumption

/-- Every step strictly decreases a potential, so every execution -- fair
or not -- is finite, with an explicit bound of `15 * total + 31` steps
(3 more when the port may die). -/
theorem steps_bounded (P : Params) (f : Nat → St) (n : Nat) (h0 : f 0 = init P)
    (hs : ∀ i, i < n → Step P (f i) (f (i + 1))) :
    n ≤ 15 * P.total + 31 + 3 * P.deaths.toNat := by
  apply steps_bounded_proof <;> assumption

/-- A reachable state with no enabled step is good, provided the consumer
grants in batches no larger than the window. With `steps_bounded`: every
run of the shipped protocol ends with the consumer holding a terminal
message or having cancelled -- even when the C port dies mid-body. -/
theorem stuck_is_good (P : Params) (hc : P.clearFirst = true)
    (hb : P.batch ≤ P.W) (s : St) (h : Reach P s) (hs : Stuck P s) :
    Good s := by
  apply stuck_is_good_proof <;> assumption

/-- `batch ≤ W` is necessary: a consumer waiting for more credits than the
window holds stalls the transfer forever (`KatipoFlowBatchStall.cfg`). -/
theorem batch_gt_window_stalls :
    ∃ (P : Params) (s : St), P.clearFirst = true ∧ P.W < P.batch ∧
      Reach P s ∧ Stuck P s ∧ ¬ Good s := by
  exact batch_gt_window_stalls_proof

/-- The `flow_conn` ordering is load-bearing: clearing `paused` after
`curl_easy_pause(CONT)` reaches a dead state even with a consumer granting
every credit immediately (`KatipoFlowPausedLate.cfg`). -/
theorem clear_late_stalls :
    ∃ (P : Params) (s : St), P.clearFirst = false ∧ P.batch = 1 ∧
      Reach P s ∧ Stuck P s ∧ ¬ Good s := by
  exact clear_late_stalls_proof

/-! ## Redundant mechanisms (`Flow/Simplify.lean`) -/

/-- The worker's `is_map_key` guard on `{flow, Ref, N}` is redundant: the
model that forwards every grant reaches the shipped model's states, up to
extra grants queued behind the point where the port has stopped... -/
theorem flow_guard_redundant (P : Params) (s : St) (h : ReachF P s) :
    ∃ s', Reach P s' ∧ RelF s s' := by
  exact reachF_reach h

/-- ...and the shipped model's states are reached by the one without it. -/
theorem flow_guard_redundant_rev (P : Params) (s' : St) (h : Reach P s') :
    ∃ s, ReachF P s ∧ RelF s s' := by
  exact reach_reachF h

end KatipoProofs.Flow.Statements
