import KatipoProofs.Defaults.Model

/-!
# Pool defaults: proved counterexamples

Explicit traces from `init` showing the generation check is necessary;
`KatipoPoolDefaultsWindow.cfg` and `KatipoPoolDefaultsStale.cfg` are the
same with TLC.
-/

namespace KatipoProofs.Defaults

/-- Requests not tagged with their generation, and no fallback: the
design without generations. -/
def pUnchecked : Params := ⟨false, false⟩

/-- What ships: generations checked, and the fallback. -/
def pShipped : Params := ⟨true, true⟩

/-- Generations checked, but no fallback. -/
def pNoAsk : Params := ⟨true, false⟩

/-- A caller finds the pool's name as it first starts, before its options
are stored, and reads wpool's rebuild without the defaults; the pool comes
up and serves it with none. -/
theorem window_reach : ∃ s, Reach pUnchecked s ∧ (0, RV.nodef, some 0) ∈ s.ran := by
  have r1 := Reach.step (Reach.init (P := pUnchecked)) (Step.start _ 0 rfl rfl)
  have r2 := Reach.step r1 (Step.whereSome _ 0 rfl (by decide))
  have r3 := Reach.step r2 (Step.getNone _ 0 (by simp [upd]) rfl)
  have r4 := Reach.step r3 (Step.rebuild _ 0 (by simp [upd]))
  have r5 := Reach.step r4 (Step.useNoDef _ 0 (by simp [upd]) rfl)
  have r6 := Reach.step r5 (Step.store _ rfl)
  have r7 := Reach.step r6 (Step.workersUp _ rfl)
  have r8 := Reach.step r7 (Step.callServe _ 0 (by simp [upd]) rfl (by simp [pUnchecked]))
  exact ⟨_, r8, by simp [upd, init]⟩

/-- A caller finds the name of a pool being replaced, and reads its
options after the next start has taken the name but before it has stored
its own; that pool serves the request with the old defaults. -/
theorem stale_reach : ∃ s, Reach pUnchecked s ∧ (0, RV.gen 0, some 1) ∈ s.ran := by
  have r1 := Reach.step (Reach.init (P := pUnchecked)) (Step.start _ 0 rfl rfl)
  have r2 := Reach.step r1 (Step.store _ rfl)
  have r3 := Reach.step r2 (Step.workersUp _ rfl)
  have r4 := Reach.step r3 (Step.whereSome _ 0 rfl (by decide))
  have r5 := Reach.step r4 (Step.stopBegin _ rfl rfl)
  have r6 := Reach.step r5 (Step.poolGone _ rfl)
  have r7 := Reach.step r6 (Step.stopEnd _ rfl rfl)
  have r8 := Reach.step r7 (Step.start _ 1 rfl rfl)
  have r9 := Reach.step r8 (Step.get _ 0 0 (by simp [upd]) rfl)
  have r10 := Reach.step r9 (Step.store _ rfl)
  have r11 := Reach.step r10 (Step.workersUp _ rfl)
  have r12 := Reach.step r11 (Step.callServe _ 0 (by simp [upd]) rfl (by simp [pUnchecked]))
  exact ⟨_, r12, by simp [upd]⟩

/-- In what ships, a caller that finds the name as the pool first starts,
but not its options, stores wpool's rebuild after the pool has stored its
own: the pool runs with the rebuild. -/
theorem rebuild_reach : ∃ s, Reach pShipped s ∧ s.reg = .up ∧ s.term = .rebuilt := by
  have r1 := Reach.step (Reach.init (P := pShipped)) (Step.start _ 0 rfl rfl)
  have r2 := Reach.step r1 (Step.whereSome _ 0 rfl (by decide))
  have r3 := Reach.step r2 (Step.getNone _ 0 (by simp [upd]) rfl)
  have r4 := Reach.step r3 (Step.store _ rfl)
  have r5 := Reach.step r4 (Step.rebuild _ 0 (by simp [upd]))
  have r6 := Reach.step r5 (Step.workersUp _ rfl)
  exact ⟨_, r6, rfl, rfl⟩

/-- Without the fallback, a request read then has no generation while the
pool runs, which every worker refuses. -/
theorem noask_reach :
    ∃ s, Reach pNoAsk s ∧ s.reg = .up ∧ s.pc 0 = .read ∧ s.v 0 = .nodef := by
  have r1 := Reach.step (Reach.init (P := pNoAsk)) (Step.start _ 0 rfl rfl)
  have r2 := Reach.step r1 (Step.whereSome _ 0 rfl (by decide))
  have r3 := Reach.step r2 (Step.getNone _ 0 (by simp [upd]) rfl)
  have r4 := Reach.step r3 (Step.store _ rfl)
  have r5 := Reach.step r4 (Step.rebuild _ 0 (by simp [upd]))
  have r6 := Reach.step r5 (Step.workersUp _ rfl)
  have r7 := Reach.step r6 (Step.useNoDef _ 0 (by simp [upd]) rfl)
  exact ⟨_, r7, rfl, by simp [upd], by simp [upd]⟩

end KatipoProofs.Defaults
