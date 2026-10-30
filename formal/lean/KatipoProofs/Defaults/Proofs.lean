import KatipoProofs.Defaults.Model

/-! # Pool defaults: proofs -/

namespace KatipoProofs.Defaults

/-- The inductive invariant; `LeanInv` in `KatipoPoolDefaults.tla`. -/
structure Inv (P : Params) (s : St) : Prop where
  /-- `RanWithItsDefaults` (with the generation check) -/
  ranSame : P.genCheck = true → ∀ r ∈ s.ran, same r.2.1 r.2.2 = true
  /-- `NeverWithout` (with the fallback) -/
  withGen : P.fallback = true → ∀ c, s.v c ≠ .nodef
  /-- `TermWithPool` -/
  termPool : (s.reg = .stored ∨ s.reg = .up) → s.term = termOf s.child ∨ s.term = .rebuilt
  workersPool : s.reg = .up → s.wgen = s.child
  /-- workers that can serve have a configuration -/
  workersSome : serving s = true → s.wgen.isSome
  /-- `NothingLeft` -/
  nothingLeft : s.child = none → s.reg = .down
  /-- only a pool that was started is stopped -/
  stopChild : s.stopping = true → s.child.isSome

theorem inv_init (P : Params) : Inv P init := by
  constructor <;> simp [init, serving]

/-- A changed caller's read keeps `withGen` if the new read is not `nodef`. -/
theorem withGen_upd {P : Params} {s : St} (h : P.fallback = true → ∀ c, s.v c ≠ .nodef)
    (c : Nat) (r : RV) (hr : P.fallback = true → r ≠ .nodef) :
    P.fallback = true → ∀ c', upd s.v c r c' ≠ .nodef := by
  intro hf c'
  unfold upd
  split
  · exact hr hf
  · exact h hf c'

theorem inv_step {P : Params} {s t : St} (hI : Inv P s) (h : Step P s t) : Inv P t := by
  obtain ⟨hran, hwg, htp, hwp, hws, hnl, hsc⟩ := hI
  cases h with
  | start g hc hr =>
    exact ⟨hran, hwg, fun h => by simp at h, fun h => by simp at h, fun h => by simp [serving] at h,
      fun h => by simp at h, fun h => by simp⟩
  | store hr =>
    exact ⟨hran, hwg, fun _ => Or.inl rfl, fun h => by simp at h,
      fun h => by simp [serving] at h, fun h => by simp_all, hsc⟩
  | workersUp hr =>
    refine ⟨hran, hwg, fun _ => htp (Or.inl hr), fun _ => rfl, fun _ => ?_,
      fun h => by simp_all, hsc⟩
    cases hc : s.child with
    | none => simp_all
    | some _ => simp
  | stopBegin hr hs =>
    exact ⟨hran, hwg, fun h => by simp at h, fun h => by simp at h,
      fun _ => hws (by simp [serving, hr]), fun h => by simp_all,
      fun _ => by cases hc : s.child <;> simp_all⟩
  | stopEnd hs hr =>
    exact ⟨hran, hwg, fun h => by simp_all, fun h => by simp_all,
      fun h => by simp_all [serving], fun _ => hr, fun h => by simp at h⟩
  | crash hr hs =>
    exact ⟨hran, hwg, fun h => by simp at h, fun h => by simp at h,
      fun _ => hws (by simp [serving, hr]), fun h => by simp_all, hsc⟩
  | poolGone hr =>
    exact ⟨hran, hwg, fun h => by simp at h, fun h => by simp at h,
      fun h => by simp [serving] at h, fun _ => rfl, hsc⟩
  | restart hr hc hs =>
    exact ⟨hran, hwg, fun h => by simp at h, fun h => by simp at h,
      fun h => by simp [serving] at h, fun h => by simp_all, hsc⟩
  | whereNone c hp hr => exact ⟨hran, hwg, htp, hwp, hws, hnl, hsc⟩
  | whereSome c hp hr => exact ⟨hran, hwg, htp, hwp, hws, hnl, hsc⟩
  | get c g hp ht =>
    exact ⟨hran, withGen_upd hwg c _ (fun _ => by simp), htp, hwp, hws, hnl, hsc⟩
  | getRebuilt c hp ht => exact ⟨hran, hwg, htp, hwp, hws, hnl, hsc⟩
  | getNone c hp ht => exact ⟨hran, hwg, htp, hwp, hws, hnl, hsc⟩
  | rebuild c hp => exact ⟨hran, hwg, fun _ => Or.inr rfl, hwp, hws, hnl, hsc⟩
  | rebuildGiveUp c hp => exact ⟨hran, hwg, htp, hwp, hws, hnl, hsc⟩
  | useAsk c hp hf => exact ⟨hran, hwg, htp, hwp, hws, hnl, hsc⟩
  | useNoDef c hp hf =>
    exact ⟨hran, withGen_upd hwg c _ (fun h => by simp_all), htp, hwp, hws, hnl, hsc⟩
  | ask c hp hs =>
    refine ⟨hran, withGen_upd hwg c _ (fun _ => ?_), htp, hwp, hws, hnl, hsc⟩
    have := hws hs
    cases hw : s.wgen <;> simp_all [readOf]
  | askFail c hp hs => exact ⟨hran, hwg, htp, hwp, hws, hnl, hsc⟩
  | callServe c hp hr hg =>
    refine ⟨?_, hwg, htp, hwp, hws, hnl, hsc⟩
    intro hgc r hm
    simp only [List.mem_cons] at hm
    rcases hm with rfl | hm
    · exact hg hgc
    · exact hran hgc r hm
  | callRefuse c hp hr => exact ⟨hran, hwg, htp, hwp, hws, hnl, hsc⟩

theorem inv_reach {P : Params} {s : St} (h : Reach P s) : Inv P s := by
  induction h with
  | init => exact inv_init P
  | step _ hs ih => exact inv_step ih hs

end KatipoProofs.Defaults
