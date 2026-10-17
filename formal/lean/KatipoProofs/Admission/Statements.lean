import KatipoProofs.Admission.Proofs
import KatipoProofs.Admission.Counterexamples
import KatipoProofs.Admission.Orphan
import KatipoProofs.Admission.Liveness
import KatipoProofs.Admission.Simplify

/-!
# Admission and delivery: headline statements (frozen)

`R` is any type of request identities, so these hold for any number of
concurrent requests, crashes and restarts -- TLC checked 2 requests and 1
port death. `Safe P` is the shipped protocol (admission deadline, under the
`ReplyWithinSlack` timing assumption) or the pre-#185 one whose caller
never gave up.
-/

namespace KatipoProofs.Admission.Statements
open KatipoProofs.Admission

variable {R : Type} [DecidableEq R]

/-- `AtMostOneDelivery`: each request gets at most one terminal outcome --
a message, or an error return from `async_req` itself. -/
theorem at_most_once (P : Params) (hP : Safe P) (s : St R) (h : Reach P s) (r : R) :
    s.delivered r ≤ 1 := by
  apply at_most_once_proof <;> assumption

/-- `NoMessageAfterAdmissionError`: an `async_req` that returned
`admission_timeout` is never also admitted or answered by message. -/
theorem no_message_after_admission_error (P : Params) (hP : Safe P) (s : St R)
    (h : Reach P s) (r : R) (hg : s.gaveUp r = true) :
    s.delivered r = 1 ∧ s.reqs r = false := by
  apply no_message_after_admission_error_proof <;> assumption

/-- `NoDeliveryAfterEffectiveCancel`: once a cancel removes a request from
`Reqs`, nothing more is delivered for it. -/
theorem no_delivery_after_effective_cancel (P : Params) (hP : Safe P) (s : St R)
    (h : Reach P s) (r : R) (he : s.effCancel r = true) :
    s.delivered r = s.snap r := by
  apply no_delivery_after_effective_cancel_proof <;> assumption

/-- `NoProgressAfterStop`: no streaming chunk is forwarded for a request
that was cancelled or already resolved. -/
theorem no_progress_after_stop (P : Params) (hP : Safe P) (s : St R)
    (h : Reach P s) : s.progressStop = false := by
  apply no_progress_after_stop_proof <;> assumption

/-- Telemetry: each async request's OpenTelemetry span is ended at most
once and its request metrics are recorded at most once
(`katipo_span:finish_async/4`, `end_async/1`). -/
theorem telemetry_at_most_once (P : Params) (hP : Safe P) (s : St R)
    (h : Reach P s) (r : R) : s.spans r ≤ 1 ∧ s.metrics r ≤ 1 := by
  apply telemetry_at_most_once_proof <;> assumption

/-- The bug, proved: with caller timeouts and no admission deadline (the
code as of #185), a request can be resolved twice -- `admission_timeout`
returned, then a message (`KatipoAdmissionTimeout.cfg`). -/
theorem no_deadline_double_delivery :
    ∃ (P : Params) (s : St Unit), P.callerTimeouts = true ∧ P.deadline = false ∧
      Reach P s ∧ s.delivered () = 2 := by
  exact no_deadline_double_delivery_proof

/-- The same bug double-counted telemetry: the caller ended the span and
recorded an `admission_timeout`, then the worker ended it and recorded the
transfer's outcome. -/
theorem no_deadline_double_telemetry :
    ∃ (P : Params) (s : St Unit), P.callerTimeouts = true ∧ P.deadline = false ∧
      Reach P s ∧ s.spans () = 2 ∧ s.metrics () = 2 := by
  exact no_deadline_double_telemetry_proof

/-- The deadline rests on `ReplyWithinSlack`: without it the caller's timer
can fire between the post-check and the reply (`KatipoDeadlineRace.cfg`). -/
theorem no_slack_double_delivery :
    ∃ (P : Params) (s : St Unit), P.callerTimeouts = true ∧ P.deadline = true ∧
      P.slack = false ∧ Reach P s ∧ s.delivered () = 2 := by
  exact no_slack_double_delivery_proof

/-! ## The exact model (`Full.lean`): `KatipoFixed.tla` with its port -/

open KatipoProofs.Admission.Full in
/-- The exact model refines the loose one, so every theorem above holds
for it too: any number of requests, port deaths and restarts. -/
theorem exact_refines (P : Params) (f : FSt R) (h : FReach P f) : Reach P (proj f) := by
  exact freach_reach h

open KatipoProofs.Admission.Full in
/-- `NoOrphanTransfer`: every transfer the C port is running is in `Reqs`,
being admitted, or has an abort queued behind it. -/
theorem no_orphan_transfer (P : Params) (hP : Safe P) (f : FSt R) (h : FReach P f)
    (r : R) (hc : f.conns r = true) :
    f.c.reqs r = true ∨ admitting f.c r ∨ PMsg.cancel r ∈ f.pQ := by
  apply no_orphan_transfer_proof <;> assumption

open KatipoProofs.Admission.Full in
/-- `EventualOutcome`: in every behaviour fair to the worker and the request
timers, each sent request is eventually answered -- a message, or an error
from `async_req` -- unless its caller cancelled it. No fairness for the
port or the supervisor is needed. -/
theorem eventual_outcome (P : Params) (hP : Safe P) (σ : Nat → FSt R)
    (hb : Behaviour P σ) (hw : Fair σ WEnabled (WStep P))
    (ht : ∀ r, Fair σ (TEnabled r) (TStep r)) (r : R) (i : Nat)
    (hs : (σ i).c.sent r = true) :
    ∃ j, i ≤ j ∧ (0 < (σ j).c.delivered r ∨ (σ j).c.cancelled r = true) := by
  apply eventual_outcome_proof <;> assumption

open KatipoProofs.Admission.Full in
/-- The request timer is necessary: a behaviour fair to the worker, the
port and the supervisor can leave an admitted request unanswered forever
when the C port never completes it. -/
theorem timer_fairness_needed :
    ∃ (P : Params) (σ : Nat → FSt Unit), Safe P ∧ Behaviour P σ ∧
      Fair σ WEnabled (WStep P) ∧ Fair σ PEnabled PStep ∧
      Fair σ (fun f => f.c.wAlive = false) (FStep P) ∧
      (σ 4).c.reqs () = true ∧ ∀ j, ¬ resolved (σ j) () := by
  exact timer_fairness_needed_proof

/-! ## Redundant mechanisms (`Admission/Simplify.lean`) -/

/-- The pre-send deadline check is redundant: the worker without it reaches
a state related by `Rel` (same observables) to one the shipped worker
reaches, for every `P`... -/
theorem pre_check_redundant (P : Params) (s : St R) (h : ReachS P s) :
    ∃ s', Reach P s' ∧ Rel P s s' := by
  exact reachS_reach h

/-- ...and every state the shipped worker reaches, the one without it
reaches too. -/
theorem pre_check_redundant_rev (P : Params) (s : St R) (h : Reach P s) : ReachS P s := by
  exact reach_reachS h

/-- The post-send check is not: without it, the shipped protocol resolves a
request twice when `port_command` blocks past the deadline. -/
theorem no_post_check_double_delivery :
    ∃ s : St Unit, ReachNoPost pShipped s ∧ s.delivered () = 2 := by
  exact no_post_check_double_delivery_proof

end KatipoProofs.Admission.Statements
