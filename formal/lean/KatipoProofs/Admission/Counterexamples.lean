import KatipoProofs.Admission.Model

/-!
# Admission: proved counterexamples

Both hypotheses inside `Safe` are necessary. Each trace is the TLC
counterexample of the matching config, step for step, ending one response
later in a second terminal outcome for the same request.
-/

namespace KatipoProofs.Admission

/-- The code as of #185: bounded admission call, no deadline. -/
def pNoDeadline : Params := ⟨true, false, true⟩
/-- The deadline without the slack assumption. -/
def pNoSlack : Params := ⟨true, true, false⟩

/-- `KatipoAdmissionTimeout.cfg`: SendAsync, Expire, CallerTimeout,
WorkerRecvReq, WorkerAdmitCheck, WorkerAdmitReply -- then the request
timer (or the response) delivers again, ending the span and recording
metrics a second time. -/
theorem no_deadline_trace : ∃ s : St Unit, Reach pNoDeadline s ∧
    s.delivered () = 2 ∧ s.spans () = 2 ∧ s.metrics () = 2 := by
  have r1 := Reach.step (Reach.init (P := pNoDeadline)) (Step.sendLive _ () rfl rfl)
  have r2 := Reach.step r1 (Step.expire _ () rfl (by simp [upd]) rfl)
  have r3 := Reach.step r2 (Step.callerTimeout _ () rfl (by simp [upd]) (by simp [upd])
    (by intro _ h; cases h))
  have r4 := Reach.step r3 (Step.recvReq _ () [] [] rfl rfl rfl rfl)
  have r5 := Reach.step r4 (Step.checkPass _ () rfl rfl rfl)
  have r6 := Reach.step r5 (Step.admitReply _ () rfl rfl)
  have r7 := Reach.step r6 (Step.emitResp _ () rfl)
  have r8 := Reach.step r7 (Step.recvResp _ () [] [] rfl rfl rfl)
  exact ⟨_, r8, by simp [upd, init, resolve], by simp [upd, init, resolve],
    by simp [upd, init, resolve]⟩

theorem no_deadline_double_delivery_proof :
    ∃ (P : Params) (s : St Unit), P.callerTimeouts = true ∧ P.deadline = false ∧
      Reach P s ∧ s.delivered () = 2 :=
  let ⟨s, h, hd, _⟩ := no_deadline_trace; ⟨_, s, rfl, rfl, h, hd⟩

theorem no_deadline_double_telemetry_proof :
    ∃ (P : Params) (s : St Unit), P.callerTimeouts = true ∧ P.deadline = false ∧
      Reach P s ∧ s.spans () = 2 ∧ s.metrics () = 2 :=
  let ⟨s, h, _, hs, hm⟩ := no_deadline_trace; ⟨_, s, rfl, rfl, h, hs, hm⟩

/-- `KatipoDeadlineRace.cfg`: the post-check passes, then the deadline
passes and the caller's timer fires before the reply. -/
theorem no_slack_double_delivery_proof :
    ∃ (P : Params) (s : St Unit), P.callerTimeouts = true ∧ P.deadline = true ∧
      P.slack = false ∧ Reach P s ∧ s.delivered () = 2 := by
  have r1 := Reach.step (Reach.init (P := pNoSlack)) (Step.sendLive _ () rfl rfl)
  have r2 := Reach.step r1 (Step.recvReq _ () [] [] rfl rfl rfl rfl)
  have r3 := Reach.step r2 (Step.checkPass _ () rfl rfl rfl)
  have r4 := Reach.step r3 (Step.expire _ () rfl (by simp [upd]) rfl)
  have r5 := Reach.step r4 (Step.callerTimeout _ () rfl (by simp [upd]) (by simp [upd])
    (by intro h; cases h))
  have r6 := Reach.step r5 (Step.admitReply _ () rfl rfl)
  have r7 := Reach.step r6 (Step.emitResp _ () rfl)
  have r8 := Reach.step r7 (Step.recvResp _ () [] [] rfl rfl rfl)
  exact ⟨_, _, rfl, rfl, rfl, r8, by simp [upd, init, resolve]⟩

end KatipoProofs.Admission
