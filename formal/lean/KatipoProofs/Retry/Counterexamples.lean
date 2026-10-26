import KatipoProofs.Retry.Proofs

/-!
# Retries: what the design needs

Explicit traces, each the one TLC found for the matching config:

* `KatipoRetryReuse.cfg`: with the key reused as each retry's port id, the
  first attempt ends at the port while its request timer fires; the
  timeout aborts it and backs off, the retry goes out under the same id,
  and the first attempt's late output is then taken for the retry's.
* `KatipoRetryReuseOrphan.cfg`: the same, until the port starts the retry
  for a request already resolved.
* `KatipoRetryNoTref.cfg`: without matching `Tref`, the first attempt's
  timer fires as the attempt ends, and after the backoff its message cuts
  the retry short.
-/

namespace KatipoProofs.Retry

/-- Retries under the key. -/
def pReuse : Params := { maxRetries := 1, fresh := false, matchTref := true, cancels := false }

/-- The first attempt's output is still on its way when its timer has made
the request retry under the same id. -/
theorem reuse_prefix :
    ∃ s, Reach pReuse s ∧ s.rs 0 = .held .attempt 1 3 ∧
      s.out = [⟨⟨0, 0⟩, 0, false⟩] ∧ s.pipe = [.cancel ⟨0, 0⟩, .req ⟨0, 0⟩ 1] ∧
      s.running = [] ∧ s.stale = false := by
  have r1 := Reach.step Reach.init (Step.admit (P := pReuse) _ 0 rfl)
  have r2 := Reach.step r1 (Step.portReq _ ⟨0, 0⟩ 0 [] rfl)
  have r3 := Reach.step r2 (Step.portEnd _ [] [] ⟨⟨0, 0⟩, 0⟩ false rfl)
  have r4 := Reach.step r3 (Step.fire _ ⟨0, .req, 1⟩ rfl)
  have r5 := Reach.step r4 (Step.reqTimeout _ ⟨0, .req, 1⟩ 0 1 rfl rfl rfl (Or.inr rfl))
  have r6 := Reach.step r5 (Step.fire _ ⟨0, .retry, 2⟩ rfl)
  have r7 := Reach.step r6 (Step.retry _ ⟨0, .retry, 2⟩ 0 2 rfl rfl rfl (Or.inr rfl))
  exact ⟨_, r7, rfl, rfl, rfl, rfl, rfl⟩

theorem reuse_stale_proof : ∃ s, Reach pReuse s ∧ s.stale = true := by
  obtain ⟨s, h, hr, ho, -, -, hs⟩ := reuse_prefix
  have r := Reach.step h
    (Step.workerOutCur _ [] [] ⟨⟨0, 0⟩, 0, false⟩ 1 3 (by rw [ho]; rfl) hr rfl)
  exact ⟨_, r, by unfold retryOrResolve; simp [hs]⟩

theorem reuse_orphan_proof : ∃ s, Reach pReuse s ∧ ¬ NoOrphan s := by
  obtain ⟨s, h, hr, ho, hp, hrun, -⟩ := reuse_prefix
  have r8 := Reach.step h
    (Step.workerOutCur _ [] [] ⟨⟨0, 0⟩, 0, false⟩ 1 3 (by rw [ho]; rfl) hr rfl)
  have r9 := Reach.step r8 (Step.portCancel _ ⟨0, 0⟩ [.req ⟨0, 0⟩ 1] (by simp [hp]))
  have r10 := Reach.step r9 (Step.portReq _ ⟨0, 0⟩ 1 [] rfl)
  refine ⟨_, r10, fun hN => ?_⟩
  have hx := hN ⟨⟨0, 0⟩, 1⟩ (by simp [hrun])
  rcases hx with ⟨tr, h'⟩ | h'
  · unfold retryOrResolve at h'; simp [upd] at h'
  · simp [cancels] at h'

/-- Fresh ids, without matching `Tref`. -/
def pNoTref : Params := { maxRetries := 1, fresh := true, matchTref := false, cancels := false }

theorem no_tref_spurious_proof : ∃ s, Reach pNoTref s ∧ s.spurious = true := by
  have r1 := Reach.step Reach.init (Step.admit (P := pNoTref) _ 0 rfl)
  have r2 := Reach.step r1 (Step.portReq _ ⟨0, 0⟩ 0 [] rfl)
  have r3 := Reach.step r2 (Step.portEnd _ [] [] ⟨⟨0, 0⟩, 0⟩ true rfl)
  have r4 := Reach.step r3 (Step.fire _ ⟨0, .req, 1⟩ rfl)
  have r5 := Reach.step r4 (Step.workerOutCur _ [] [] ⟨⟨0, 0⟩, 0, true⟩ 0 1 rfl rfl rfl)
  have r6 := Reach.step r5 (Step.fire _ ⟨0, .retry, 2⟩ rfl)
  have r7 := Reach.step r6 (Step.retry _ ⟨0, .retry, 2⟩ 0 2 rfl rfl rfl (Or.inl rfl))
  have r8 := Reach.step r7 (Step.reqTimeout _ ⟨0, .req, 1⟩ 1 3 rfl rfl rfl (Or.inl rfl))
  exact ⟨_, r8, rfl⟩

end KatipoProofs.Retry
