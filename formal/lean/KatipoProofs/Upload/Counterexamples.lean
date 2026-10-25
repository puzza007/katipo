import KatipoProofs.Upload.Proofs

/-!
# Streaming request bodies: what the design needs

Explicit traces, each the shortest TLC found for the matching config:

* `KatipoUploadNoGuard.cfg`: with neither the one-demand guard nor the
  masked resume, a grant's plain `CURLPAUSE_CONT` also resumes the upload,
  `read_stream_cb` runs again with the first demand unanswered, and a
  second goes out.
* `KatipoUploadEager.cfg`: a caller that sends without waiting for demand
  has two chunks between it and curl.
* `KatipoUploadContAgrees.cfg`: with plain `CURLPAUSE_CONT`, resuming the
  upload also resumes the response, so katipo's `paused` flag says paused
  while curl is not.
-/

namespace KatipoProofs.Upload

/-- Neither safeguard: `CURLPAUSE_CONT`, and a demand on every empty read. -/
def pNoGuard : Params :=
  { total := 1, W := 1, resp := 2, length := false, masked := false, guard := false,
    eager := false, liar := false, early := true, timeouts := false, cancels := false,
    failures := false, W_pos := by decide }

theorem no_guard_two_demands_proof :
    ∃ s, Reach pNoGuard s ∧ s.inReqs = true ∧ 2 ≤ demands s := by
  have r1 := Reach.step Reach.init
    (Step.writeChunk (P := pNoGuard) _ rfl rfl (by decide) rfl (by decide))
  have r2 := Reach.step r1 (Step.readDemand _ rfl rfl rfl rfl rfl rfl)
  have r3 := Reach.step r2 (Step.writePause _ rfl rfl (by decide) rfl rfl)
  have r4 := Reach.step r3 (Step.workerFwd _ .chunk [.demand] rfl rfl)
  have r5 := Reach.step r4 (Step.callerRecv _ .chunk [] rfl)
  have r6 := Reach.step r5 (Step.callerGrant _ (by decide) rfl)
  have r7 := Reach.step r6 (Step.workerFlow _ 1 [] rfl)
  have r8 := Reach.step r7 (Step.flowResume _ 1 [] rfl rfl rfl rfl)
  have r9 := Reach.step r8 (Step.readDemand _ rfl rfl rfl rfl rfl rfl)
  exact ⟨_, r9, rfl, by decide⟩

/-- A caller that sends without a demand. -/
def pEager : Params :=
  { total := 2, W := 1, resp := 1, length := false, masked := true, guard := true,
    eager := true, liar := false, early := false, timeouts := false, cancels := false,
    failures := false, W_pos := by decide }

theorem eager_two_chunks_proof : ∃ s, Reach pEager s ∧ 2 ≤ inFlight s := by
  have r1 := Reach.step Reach.init
    (Step.callerData (P := pEager) _ rfl rfl (Or.inr rfl) (by decide))
  have r2 := Reach.step r1 (Step.callerData _ rfl rfl (Or.inr rfl) (by decide))
  exact ⟨_, r2, by decide⟩

/-- Plain `CURLPAUSE_CONT`, with the guard. -/
def pCont : Params :=
  { total := 1, W := 1, resp := 2, length := false, masked := false, guard := true,
    eager := false, liar := false, early := true, timeouts := false, cancels := false,
    failures := false, W_pos := by decide }

theorem cont_flags_drift_proof :
    ∃ s, Reach pCont s ∧ s.unpausing = false ∧ s.paused ≠ s.curlRecvPaused := by
  have r1 := Reach.step Reach.init (Step.readDemand (P := pCont) _ rfl rfl rfl rfl rfl rfl)
  have r2 := Reach.step r1 (Step.writeChunk _ rfl rfl (by decide) rfl (by decide))
  have r3 := Reach.step r2 (Step.writePause _ rfl rfl (by decide) rfl rfl)
  have r4 := Reach.step r3 (Step.workerFwd _ .demand [.chunk] rfl rfl)
  have r5 := Reach.step r4 (Step.callerRecv _ .demand [] rfl)
  have r6 := Reach.step r5 (Step.callerData _ rfl rfl (Or.inl (by decide)) (by decide))
  have r7 := Reach.step r6 (Step.workerBody _ .data [] rfl)
  have r8 := Reach.step r7 (Step.bodyResume _ .data [] rfl rfl rfl rfl rfl rfl)
  have r9 := Reach.step r8 (Step.unpauseReturn _ rfl)
  exact ⟨_, r9, rfl, by decide⟩

end KatipoProofs.Upload
