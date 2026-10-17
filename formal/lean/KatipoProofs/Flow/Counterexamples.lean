import KatipoProofs.Flow.Model

/-!
# Flow control: proved counterexamples

Each hypothesis of `stuck_is_good` is necessary: a concrete instance, an
explicit trace from `init`, and a final state with no enabled step that is
not `Good`. These mirror `KatipoFlowBatchStall.cfg` and
`KatipoFlowPausedLate.cfg`, which TLC reports as VIOLATED.
-/

namespace KatipoProofs.Flow

/-- Window 1, two chunks, consumer waits for 2 owed credits. -/
def pStall : Params :=
  ⟨1, 2, 2, false, false, false, false, true, by decide, by decide⟩

/-- Window 1, three chunks, consumer grants each credit at once, and the
pre-fix `flow_conn` ordering. -/
def pLate : Params :=
  ⟨1, 3, 1, false, false, false, false, false, by decide, by decide⟩

/-- Proves `Stuck` for a concrete state by refuting every constructor's
guards. -/
macro "refute_steps" : tactic =>
  `(tactic| (intro t h; cases h <;> simp_all [recv, terminal, init, pStall, pLate]))

/-- Out of credits with 1 owed, which is below the batch of 2. -/
def sStall : St :=
  { init pStall with
    toW := [], headersSent := true, window := 0, remaining := 1,
    paused := true, curlPaused := true,
    toC := [], seenHeaders := true, chunksSeen := 1, owed := 1 }

theorem stall_reach : Reach pStall sStall := by
  have r1 := Reach.step (Reach.init (P := pStall))
    (Step.writeChunk _ rfl rfl (by decide) (by decide))
  have r2 := Reach.step r1 (Step.writePause _ rfl rfl (by decide) rfl)
  have r3 := Reach.step r2 (Step.workerFwd _ .headers [.chunk] rfl rfl rfl)
  have r4 := Reach.step r3 (Step.workerFwd _ .chunk [] rfl rfl rfl)
  have r5 := Reach.step r4 (Step.consumerRecv _ .headers [.chunk] rfl)
  have r6 := Reach.step r5 (Step.consumerRecv _ .chunk [] rfl)
  exact r6

theorem batch_gt_window_stalls_proof :
    ∃ (P : Params) (s : St), P.clearFirst = true ∧ P.W < P.batch ∧
      Reach P s ∧ Stuck P s ∧ ¬ Good s :=
  ⟨pStall, sStall, rfl, by decide, stall_reach, by unfold Stuck sStall; refute_steps,
   by simp [Good, sStall, init]⟩

/-- libcurl is paused, katipo's flag says it is not, and a credit is
waiting: no grant will ever call `curl_easy_pause(CONT)` again. -/
def sLate : St :=
  { init pLate with
    toW := [], headersSent := true, window := 1, remaining := 1,
    paused := false, curlPaused := true, unpausing := false,
    toC := [], seenHeaders := true, chunksSeen := 2, owed := 0 }

theorem late_reach : Reach pLate sLate := by
  have r1 := Reach.step (Reach.init (P := pLate))
    (Step.writeChunk _ rfl rfl (by decide) (by decide))
  have r2 := Reach.step r1 (Step.writePause _ rfl rfl (by decide) rfl)
  have r3 := Reach.step r2 (Step.workerFwd _ .headers [.chunk] rfl rfl rfl)
  have r4 := Reach.step r3 (Step.workerFwd _ .chunk [] rfl rfl rfl)
  have r5 := Reach.step r4 (Step.consumerRecv _ .headers [.chunk] rfl)
  have r6 := Reach.step r5 (Step.consumerRecv _ .chunk [] rfl)
  have r7 := Reach.step r6 (Step.consumerGrant _ (by decide) rfl)
  have r8 := Reach.step r7 (Step.workerFlow _ 1 [] rfl rfl)
  -- flow_conn: credits first, then curl_easy_pause(CONT) -- paused not yet cleared
  have r9 := Reach.step r8 (Step.flowUnpause _ 1 [] rfl rfl (by decide) rfl rfl rfl)
  -- inside curl_easy_pause: the held chunk, then a re-pause
  have r10 := Reach.step r9 (Step.writeChunk _ rfl rfl (by decide) (by decide))
  have r11 := Reach.step r10 (Step.writePause _ rfl rfl (by decide) rfl)
  -- curl_easy_pause returns; the late `paused = 0` erases the re-pause
  have r12 := Reach.step r11 (Step.unpauseReturn _ rfl)
  have r13 := Reach.step r12 (Step.workerFwd _ .chunk [] rfl rfl rfl)
  have r14 := Reach.step r13 (Step.consumerRecv _ .chunk [] rfl)
  have r15 := Reach.step r14 (Step.consumerGrant _ (by decide) rfl)
  have r16 := Reach.step r15 (Step.workerFlow _ 1 [] rfl rfl)
  -- the grant takes the not-paused branch: window += 1, no resume
  have r17 := Reach.step r16 (Step.flowRun _ 1 [] rfl rfl (by decide) rfl rfl rfl)
  exact r17

theorem clear_late_stalls_proof :
    ∃ (P : Params) (s : St), P.clearFirst = false ∧ P.batch = 1 ∧
      Reach P s ∧ Stuck P s ∧ ¬ Good s :=
  ⟨pLate, sLate, rfl, rfl, late_reach, by unfold Stuck sLate; refute_steps,
   by simp [Good, sLate, init]⟩

end KatipoProofs.Flow
