import KatipoProofs.Flow.Model

/-!
# Flow control: proofs

`Inv` is the inductive invariant; each field is named for what it says and
carries the TLA+ property it backs. `inv_step` proves it preserved by every
`Step` constructor; the headline theorems are corollaries.
-/

namespace KatipoProofs.Flow

@[simp] theorem cnt_nil (x : Msg) : cnt x [] = 0 := rfl
@[simp] theorem cnt_cons (x m : Msg) (ms : List Msg) :
    cnt x (m :: ms) = (if m = x then 1 else 0) + cnt x ms := rfl
@[simp] theorem cnt_append (x : Msg) (a b : List Msg) :
    cnt x (a ++ b) = cnt x a + cnt x b := by
  induction a with
  | nil => simp
  | cons m ms ih => simp [ih]; omega

@[simp] theorem sum_nil : sum [] = 0 := rfl
@[simp] theorem sum_cons (n : Nat) (ns : List Nat) : sum (n :: ns) = n + sum ns := rfl
@[simp] theorem sum_append (a b : List Nat) : sum (a ++ b) = sum a + sum b := by
  induction a with
  | nil => simp
  | cons m ms ih => simp [ih]; omega

@[simp] theorem cnt_hdrs_chunk (s : St) : cnt .chunk (hdrs s) = 0 := by
  unfold hdrs; split <;> simp
@[simp] theorem done_not_mem_hdrs (s : St) : Msg.done ∉ hdrs s := by
  unfold hdrs; split <;> simp
@[simp] theorem error_not_mem_hdrs (s : St) : Msg.error ∉ hdrs s := by
  unfold hdrs; split <;> simp

/-- If `x` occurs only as the last element of `m :: rest`, then either
`m = x` and nothing follows, or `x` still occurs only last in `rest`. -/
theorem last_only_cons {x m : Msg} {rest pre : List Msg}
    (h : m :: rest = pre ++ [x]) (hx : x ∉ pre) :
    (m = x ∧ rest = []) ∨ (m ≠ x ∧ ∃ pre', rest = pre' ++ [x] ∧ x ∉ pre') := by
  cases pre with
  | nil => simp at h; exact Or.inl ⟨h.1, h.2⟩
  | cons p ps =>
    simp at h hx
    obtain ⟨rfl, rfl⟩ := h
    exact Or.inr ⟨fun e => hx.1 e.symm, ps, rfl, hx.2⟩

structure Inv (P : Params) (s : St) : Prop where
  /-- credits only leave the system, never appear (`BoundedBuffering`) -/
  creditsLe : credits s ≤ P.W
  /-- `CreditConservation` -/
  creditsEq : s.inReqs = true → s.live = true → credits s = P.W
  /-- chunk accounting while the worker still forwards -/
  chunksEq : s.inReqs = true →
    s.remaining + cnt .chunk s.toW + cnt .chunk s.toC + s.chunksSeen = P.total
  /-- a `done` in the pipe is the last thing the port ever sent -/
  doneW : Msg.done ∈ s.toW → s.remaining = 0 ∧ s.live = false ∧
    ∃ pre, s.toW = pre ++ [.done] ∧ Msg.done ∉ pre
  /-- a forwarded `done` is last at the consumer, behind the rest of the body -/
  doneC : Msg.done ∈ s.toC → s.inReqs = false ∧
    cnt .chunk s.toC + s.chunksSeen = P.total ∧
    ∃ pre, s.toC = pre ++ [.done] ∧ Msg.done ∉ pre
  /-- `NoLostChunks`, plus: nothing follows a received `done` -/
  seenDoneAll : s.seenDone = true →
    s.inReqs = false ∧ s.toC = [] ∧ s.chunksSeen = P.total
  /-- `PausedAgrees` (shipped `flow_conn` ordering) -/
  pausedAgree : P.clearFirst = true → s.paused = s.curlPaused
  /-- libcurl is only ever paused by an out-of-credits `write_cb` -/
  pausedWin : P.clearFirst = true → s.curlPaused = true → s.window = 0
  /-- once the worker lets go, the consumer has or will get a terminal, or cancelled -/
  outReqs : s.inReqs = false → s.cancelled = true ∨ s.seenDone = true ∨
    s.seenError = true ∨ Msg.done ∈ s.toC ∨ Msg.error ∈ s.toC
  /-- a conn freed while the worker still holds the request left a terminal in the
  pipe, or the port died and its `'EXIT'` is queued -/
  deadPort : s.inReqs = true → s.live = false →
    Msg.done ∈ s.toW ∨ Msg.error ∈ s.toW ∨ s.exitQ = true
  /-- a cancel command is only sent after the worker dropped the request -/
  cancelOut : 0 ∈ s.pQ → s.inReqs = false
  /-- consumer grants are positive, so never mistaken for a cancel -/
  flowPos : ∀ n ∈ s.flowQ, n ≠ 0
  /-- a queued cancel was issued by the consumer -/
  cancelQc : s.cancelQ = true → s.cancelled = true
  /-- a running port has a running worker and no `'EXIT'` queued -/
  portLife : s.pAlive = true → s.wAlive = true ∧ s.exitQ = false
  /-- a dead port runs nothing; its worker is stopping or stopped -/
  portDead : s.pAlive = false → s.live = false ∧ s.unpausing = false ∧
    (s.exitQ = true ∨ s.wAlive = false)
  /-- a stopped worker read everything and let go of the request -/
  workerDead : s.wAlive = false →
    s.toW = [] ∧ s.inReqs = false ∧ s.exitQ = false ∧ s.pAlive = false

theorem inv_init (P : Params) : Inv P (init P) := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩ <;>
    simp [init, credits, outstanding]

section Steps
variable {P : Params} {s : St} (hI : Inv P s)
include hI

/-- A live conn means the port and the worker are both running. -/
theorem alive_of_live (hl : s.live = true) : s.pAlive = true ∧ s.wAlive = true := by
  cases hp : s.pAlive
  · simp [(hI.portDead hp).1] at hl
  · exact ⟨rfl, (hI.portLife hp).1⟩

theorem inv_writePause (hw : s.window = 0) :
    Inv P { s with paused := true, curlPaused := true } :=
  { hI with pausedAgree := fun _ => rfl, pausedWin := fun _ _ => hw }

theorem inv_writeChunk (hl : s.live = true) (hc : s.curlPaused = false)
    (hr : 0 < s.remaining) (hw : s.window ≠ 0) :
    Inv P { s with toW := s.toW ++ hdrs s ++ [.chunk], headersSent := true,
                   window := s.window - 1, remaining := s.remaining - 1 } := by
  have c1 := hI.creditsLe; have c2 := hI.creditsEq; have c3 := hI.chunksEq
  have c4 := hI.doneW; have c10 := hI.deadPort
  simp only [credits, outstanding] at c1 c2
  refine { hI with creditsLe := ?_, creditsEq := ?_, chunksEq := ?_, doneW := ?_,
                   pausedWin := ?_, deadPort := ?_,
                   workerDead := fun h => by simp [(alive_of_live hI hl).2] at h }
  · simp only [credits, outstanding, cnt_append, cnt_hdrs_chunk]; simp; omega
  · intro h1 h2; have := c2 h1 hl
    simp only [credits, outstanding, cnt_append, cnt_hdrs_chunk]; simp; omega
  · intro h1; have := c3 h1; simp only [cnt_append, cnt_hdrs_chunk]; simp; omega
  · intro h
    simp only [List.mem_append, List.mem_singleton] at h
    rcases h with (h | h) | h
    · simp [(c4 h).2.1] at hl
    · exact absurd h (done_not_mem_hdrs s)
    · cases h
  · intro _ h; simp [hc] at h
  · intro _ h; simp [hl] at h

theorem inv_flowDead (n : Nat) (rest : List Nat) (hq : s.pQ = n :: rest)
    (hl : s.live = false) : Inv P { s with pQ := rest } := by
  have c1 := hI.creditsLe
  simp only [credits, outstanding, hq, sum_cons] at c1
  exact { hI with
    creditsLe := by simp only [credits, outstanding]; omega
    creditsEq := fun _ h => by simp [hl] at h
    cancelOut := fun h => hI.cancelOut (by simp [hq, h]) }

theorem inv_flowRun (n : Nat) (rest : List Nat) (hq : s.pQ = n :: rest)
    (hp : s.paused = false) :
    Inv P { s with pQ := rest, window := s.window + n } := by
  have c1 := hI.creditsLe; have c2 := hI.creditsEq
  simp only [credits, outstanding, hq, sum_cons] at c1 c2
  exact { hI with
    creditsLe := by simp only [credits, outstanding]; omega
    creditsEq := fun h1 h2 => by have := c2 h1 h2; simp only [credits, outstanding]; omega
    pausedWin := fun hc h => by
      have := hI.pausedAgree hc; simp_all
    cancelOut := fun h => hI.cancelOut (by simp [hq, h]) }

theorem inv_flowUnpause (n : Nat) (rest : List Nat) (hq : s.pQ = n :: rest)
    (hl : s.live = true) :
    Inv P { s with pQ := rest, window := s.window + n, curlPaused := false,
                   unpausing := true,
                   paused := if P.clearFirst then false else s.paused } := by
  have c1 := hI.creditsLe; have c2 := hI.creditsEq
  simp only [credits, outstanding, hq, sum_cons] at c1 c2
  exact { hI with
    creditsLe := by simp only [credits, outstanding]; omega
    creditsEq := fun h1 h2 => by have := c2 h1 h2; simp only [credits, outstanding]; omega
    pausedAgree := fun hc => by simp [hc]
    pausedWin := fun _ h => by simp at h
    cancelOut := fun h => hI.cancelOut (by simp [hq, h])
    portDead := fun h => by simp [(hI.portDead h).1] at hl }

theorem inv_unpauseReturn :
    Inv P { s with unpausing := false,
                   paused := if P.clearFirst then s.paused else false } :=
  { hI with pausedAgree := fun hc => by simpa [hc] using hI.pausedAgree hc
            portDead := fun h => ⟨(hI.portDead h).1, rfl, (hI.portDead h).2.2⟩ }

theorem inv_complete (hl : s.live = true) (hr : s.remaining = 0) :
    Inv P { s with toW := s.toW ++ hdrs s ++ [.done], headersSent := true,
                   live := false } := by
  have c1 := hI.creditsLe; have c3 := hI.chunksEq; have c4 := hI.doneW
  have hnd : Msg.done ∉ s.toW := fun h => by simp [(c4 h).2.1] at hl
  simp only [credits, outstanding] at c1
  refine { hI with creditsLe := ?_, creditsEq := fun _ h => by simp at h,
                   chunksEq := ?_, doneW := ?_, deadPort := fun _ _ => by simp,
                   portDead := fun h => ⟨rfl, (hI.portDead h).2⟩,
                   workerDead := fun h => by simp [(alive_of_live hI hl).2] at h }
  · simp only [credits, outstanding, cnt_append, cnt_hdrs_chunk]; simp; omega
  · intro h1; have := c3 h1; simp only [cnt_append, cnt_hdrs_chunk]; simp; omega
  · intro _
    refine ⟨hr, rfl, s.toW ++ hdrs s, by simp, ?_⟩
    simp only [List.mem_append, not_or]; exact ⟨hnd, done_not_mem_hdrs s⟩

theorem inv_fail (hl : s.live = true) :
    Inv P { s with toW := s.toW ++ [.error], live := false } := by
  have c1 := hI.creditsLe; have c3 := hI.chunksEq; have c4 := hI.doneW
  have hnd : Msg.done ∉ s.toW := fun h => by simp [(c4 h).2.1] at hl
  simp only [credits, outstanding] at c1
  refine { hI with creditsLe := ?_, creditsEq := fun _ h => by simp at h,
                   chunksEq := ?_, doneW := ?_, deadPort := fun _ _ => by simp,
                   portDead := fun h => ⟨rfl, (hI.portDead h).2⟩,
                   workerDead := fun h => by simp [(alive_of_live hI hl).2] at h }
  · simp only [credits, outstanding, cnt_append]; simp; omega
  · intro h1; have := c3 h1; simp only [cnt_append]; simp; omega
  · intro h; simp at h; exact absurd h hnd

theorem inv_portCancel (rest : List Nat) (hq : s.pQ = 0 :: rest) :
    Inv P { s with pQ := rest, live := false } := by
  have c1 := hI.creditsLe
  have hout := hI.cancelOut (by simp [hq])
  simp only [credits, outstanding, hq, sum_cons] at c1
  exact { hI with
    creditsLe := by simp only [credits, outstanding]; omega
    creditsEq := fun _ h => by simp at h
    doneW := fun h => ⟨(hI.doneW h).1, rfl, (hI.doneW h).2.2⟩
    deadPort := fun h => by simp [hout] at h
    cancelOut := fun h => hI.cancelOut (by simp [hq, h])
    portDead := fun h => ⟨rfl, (hI.portDead h).2⟩ }

/-- Shared by the two steps that pop the port -> worker pipe. -/
theorem doneW_tail {m : Msg} {rest : List Msg} (hq : s.toW = m :: rest)
    (h : Msg.done ∈ rest) :
    s.remaining = 0 ∧ s.live = false ∧ ∃ pre, rest = pre ++ [.done] ∧ Msg.done ∉ pre := by
  obtain ⟨h1, h2, pre, hp, hn⟩ := hI.doneW (by simp [hq, h])
  rw [hq] at hp
  rcases last_only_cons hp hn with ⟨_, rfl⟩ | ⟨_, pre', hp', hn'⟩
  · simp at h
  · exact ⟨h1, h2, pre', hp', hn'⟩

theorem inv_workerFwd (m : Msg) (rest : List Msg) (hq : s.toW = m :: rest)
    (hr : s.inReqs = true) (hw : s.wAlive = true) :
    Inv P { s with toW := rest, toC := s.toC ++ [m],
                   inReqs := (m == .headers || m == .chunk) } := by
  have c1 := hI.creditsLe; have c2 := hI.creditsEq; have c3 := hI.chunksEq hr
  simp only [credits, outstanding, hq, cnt_cons] at c1 c2 c3
  have c2 := c2 hr
  have hdc : Msg.done ∉ s.toC := fun h => by simp [(hI.doneC h).1] at hr
  refine { hI with creditsLe := ?_, creditsEq := ?_, chunksEq := ?_,
                   doneW := doneW_tail hI hq, doneC := ?_, seenDoneAll := ?_,
                   outReqs := ?_, deadPort := ?_, cancelOut := ?_,
                   workerDead := fun h => by simp [hw] at h }
  · simp only [credits, outstanding, cnt_append, cnt_cons, cnt_nil]; omega
  · intro _ hl; have := c2 hl
    simp only [credits, outstanding, cnt_append, cnt_cons, cnt_nil]; omega
  · intro _; simp only [cnt_append, cnt_cons, cnt_nil]; omega
  · intro h
    simp only [List.mem_append, List.mem_singleton] at h
    rcases h with h | rfl
    · exact absurd h hdc
    · obtain ⟨hrem, -, pre, hp, hn⟩ := hI.doneW (by simp [hq])
      rw [hq] at hp
      rcases last_only_cons hp hn with ⟨-, rfl⟩ | ⟨hne, -⟩
      · refine ⟨rfl, ?_, s.toC, rfl, hdc⟩
        simp only [cnt_append, cnt_cons, cnt_nil] at c3 ⊢; simp at c3 ⊢; omega
      · exact absurd rfl hne
  · intro h; simp [(hI.seenDoneAll h).1] at hr
  · intro h
    cases m <;> simp at h ⊢
  · intro h hl
    rcases hI.deadPort hr hl with h' | h' | h'
    · rw [hq] at h'; cases m <;> simp_all
    · rw [hq] at h'; cases m <;> simp_all
    · simp [h']
  · intro h; simp [hI.cancelOut h] at hr

theorem inv_workerDrop (m : Msg) (rest : List Msg) (hq : s.toW = m :: rest)
    (hr : s.inReqs = false) (hw : s.wAlive = true) : Inv P { s with toW := rest } := by
  have c1 := hI.creditsLe
  simp only [credits, outstanding, hq, cnt_cons] at c1
  exact { hI with
    creditsLe := by simp only [credits, outstanding]; omega
    creditsEq := fun h => by simp [hr] at h
    chunksEq := fun h => by simp [hr] at h
    doneW := doneW_tail hI hq
    deadPort := fun h => by simp [hr] at h
    workerDead := fun h => by simp [hw] at h }

theorem inv_workerFlow (n : Nat) (rest : List Nat) (hq : s.flowQ = n :: rest) :
    Inv P { s with flowQ := rest, pQ := if s.inReqs then s.pQ ++ [n] else s.pQ } := by
  have c1 := hI.creditsLe; have c2 := hI.creditsEq
  have hn : n ≠ 0 := hI.flowPos n (by simp [hq])
  simp only [credits, outstanding, hq, sum_cons] at c1 c2
  cases hr : s.inReqs
  · exact { hI with
      creditsLe := by simp only [credits, outstanding]; simp; omega
      creditsEq := fun h => by simp at h
      chunksEq := fun h => by simp at h
      doneC := fun h => ⟨rfl, (hI.doneC h).2⟩
      seenDoneAll := fun h => ⟨rfl, (hI.seenDoneAll h).2⟩
      outReqs := fun _ => hI.outReqs hr
      deadPort := fun h => by simp at h
      cancelOut := fun _ => rfl
      flowPos := fun k hk => hI.flowPos k (by simp [hq, hk])
      workerDead := fun h => by simpa [hr] using hI.workerDead h }
  · have c2 := c2 hr
    exact { hI with
      creditsLe := by simp only [credits, outstanding]; simp; omega
      creditsEq := fun _ hl => by
        have := c2 hl; simp only [credits, outstanding]; simp; omega
      chunksEq := fun _ => hI.chunksEq hr
      doneC := fun h => by simp [(hI.doneC h).1] at hr
      seenDoneAll := fun h => by simp [(hI.seenDoneAll h).1] at hr
      outReqs := fun h => by simp at h
      deadPort := fun _ hl => hI.deadPort hr hl
      cancelOut := fun h => by
        simp only [if_true, List.mem_append, List.mem_singleton] at h
        rcases h with h | h
        · simp [hI.cancelOut h] at hr
        · exact absurd h.symm hn
      flowPos := fun k hk => hI.flowPos k (by simp [hq, hk])
      workerDead := fun h => by simpa [hr] using hI.workerDead h }

theorem inv_workerCancel (hc : s.cancelQ = true) (hw : s.wAlive = true) :
    Inv P { s with cancelQ := false, inReqs := false,
                   pQ := if s.inReqs then s.pQ ++ [0] else s.pQ } := by
  have c1 := hI.creditsLe
  simp only [credits, outstanding] at c1
  exact { hI with
    creditsLe := by
      simp only [credits, outstanding]
      split <;> (try simp only [sum_append, sum_cons, sum_nil]) <;> omega
    creditsEq := fun h => by simp at h
    chunksEq := fun h => by simp at h
    doneC := fun h => ⟨rfl, (hI.doneC h).2⟩
    seenDoneAll := fun h => ⟨rfl, (hI.seenDoneAll h).2⟩
    outReqs := fun _ => Or.inl (hI.cancelQc hc)
    deadPort := fun h => by simp at h
    cancelOut := fun _ => rfl
    cancelQc := fun h => by cases h
    workerDead := fun h => by simp [hw] at h }

theorem inv_workerTimeout (hr : s.inReqs = true) (hw : s.wAlive = true) :
    Inv P { s with inReqs := false, toC := s.toC ++ [.error], pQ := s.pQ ++ [0] } := by
  have c1 := hI.creditsLe
  simp only [credits, outstanding] at c1
  have hdc : Msg.done ∉ s.toC := fun h => by simp [(hI.doneC h).1] at hr
  exact { hI with
    creditsLe := by simp only [credits, outstanding, sum_append, cnt_append]; simp; omega
    creditsEq := fun h => by simp at h
    chunksEq := fun h => by simp at h
    doneC := fun h => by simp at h; exact absurd h hdc
    seenDoneAll := fun h => by simp [(hI.seenDoneAll h).1] at hr
    outReqs := fun _ => by simp
    deadPort := fun h => by simp at h
    cancelOut := fun _ => rfl
    workerDead := fun h => by simp [hw] at h }

theorem inv_portDies (hp : s.pAlive = true) :
    Inv P { s with pAlive := false, live := false, exitQ := true, unpausing := false,
                   paused := false, curlPaused := false } :=
  { hI with
    creditsEq := fun _ h => by simp at h
    doneW := fun h => ⟨(hI.doneW h).1, rfl, (hI.doneW h).2.2⟩
    pausedAgree := fun _ => rfl
    pausedWin := fun _ h => by simp at h
    deadPort := fun _ _ => by simp
    portLife := fun h => by simp at h
    portDead := fun _ => ⟨rfl, rfl, Or.inl rfl⟩
    workerDead := fun h => by simp [(hI.portLife hp).1] at h }

theorem inv_workerExit (hx : s.exitQ = true) (hW : s.toW = []) :
    Inv P { s with wAlive := false, exitQ := false, inReqs := false,
                   toC := if s.inReqs then s.toC ++ [.error] else s.toC } := by
  have c1 := hI.creditsLe
  have hp : s.pAlive = false := by
    cases hp : s.pAlive
    · rfl
    · simp [(hI.portLife hp).2] at hx
  simp only [credits, outstanding] at c1
  cases hr : s.inReqs
  · exact { hI with
      creditsLe := by simp only [credits, outstanding]; simp; omega
      creditsEq := fun h => by simp at h
      chunksEq := fun h => by simp at h
      doneC := fun h => ⟨rfl, by simpa using (hI.doneC (by simpa using h)).2⟩
      seenDoneAll := fun h => ⟨rfl, by simpa using (hI.seenDoneAll h).2⟩
      outReqs := fun _ => by simpa using hI.outReqs hr
      deadPort := fun h => by simp at h
      cancelOut := fun _ => rfl
      portLife := fun h => by simp [hp] at h
      portDead := fun _ => ⟨(hI.portDead hp).1, (hI.portDead hp).2.1, Or.inr rfl⟩
      workerDead := fun _ => ⟨hW, rfl, rfl, hp⟩ }
  · have hdc : Msg.done ∉ s.toC := fun h => by simp [(hI.doneC h).1] at hr
    exact { hI with
      creditsLe := by simp only [credits, outstanding]; simp; omega
      creditsEq := fun h => by simp at h
      chunksEq := fun h => by simp at h
      doneC := fun h => by simp at h; exact absurd h hdc
      seenDoneAll := fun h => by simp [(hI.seenDoneAll h).1] at hr
      outReqs := fun _ => by simp
      deadPort := fun h => by simp at h
      cancelOut := fun _ => rfl
      portLife := fun h => by simp [hp] at h
      portDead := fun _ => ⟨(hI.portDead hp).1, (hI.portDead hp).2.1, Or.inr rfl⟩
      workerDead := fun _ => ⟨hW, rfl, rfl, hp⟩ }

theorem inv_consumerRecv (m : Msg) (rest : List Msg) (hq : s.toC = m :: rest) :
    Inv P (recv s m rest) := by
  have c1 := hI.creditsLe; have c2 := hI.creditsEq
  simp only [credits, outstanding, hq, cnt_cons] at c1 c2
  refine { hI with creditsLe := ?_, creditsEq := ?_, chunksEq := ?_, doneC := ?_,
                   seenDoneAll := ?_, outReqs := ?_ }
  · simp only [credits, outstanding, recv]; cases m <;> simp at c1 ⊢ <;> omega
  · intro h1 h2; have := c2 h1 h2
    simp only [credits, outstanding, recv]; cases m <;> simp at this ⊢ <;> omega
  · intro h1; have := hI.chunksEq h1
    simp only [hq, cnt_cons, recv] at this ⊢; cases m <;> simp at this ⊢ <;> omega
  · intro h
    simp only [recv] at h ⊢
    obtain ⟨h1, h2, pre, hp, hn⟩ := hI.doneC (by simp [hq, h])
    simp only [hq, cnt_cons] at h2 hp
    rcases last_only_cons hp hn with ⟨-, rfl⟩ | ⟨hne, pre', hp', hn'⟩
    · simp at h
    · refine ⟨h1, ?_, pre', hp', hn'⟩; cases m <;> simp at h2 hne ⊢ <;> omega
  · intro h
    simp only [recv, Bool.or_eq_true, beq_iff_eq] at h ⊢
    rcases h with h | rfl
    · simp [(hI.seenDoneAll h).2.1] at hq
    · obtain ⟨h1, h2, pre, hp, hn⟩ := hI.doneC (by simp [hq])
      simp only [hq, cnt_cons] at h2 hp
      rcases last_only_cons hp hn with ⟨-, rfl⟩ | ⟨hne, -⟩
      · simp at h2; exact ⟨h1, rfl, h2⟩
      · exact absurd rfl hne
  · intro h
    simp only [recv] at h ⊢
    rcases hI.outReqs h with h' | h' | h' | h' | h'
    · exact Or.inl h'
    · simp [h']
    · simp [h']
    · rw [hq] at h'; cases m <;> simp_all
    · rw [hq] at h'; cases m <;> simp_all

theorem inv_consumerGrant (hb : P.batch ≤ s.owed) :
    Inv P { s with flowQ := s.flowQ ++ [s.owed], owed := 0 } := by
  have c1 := hI.creditsLe; have c2 := hI.creditsEq
  have hp := P.batch_pos
  simp only [credits, outstanding] at c1 c2
  exact { hI with
    creditsLe := by simp only [credits, outstanding, sum_append]; simp; omega
    creditsEq := fun h1 h2 => by
      have := c2 h1 h2; simp only [credits, outstanding, sum_append]; simp; omega
    flowPos := fun k hk => by
      simp only [List.mem_append, List.mem_singleton] at hk
      rcases hk with hk | rfl
      · exact hI.flowPos k hk
      · omega }

theorem inv_consumerCancel :
    Inv P { s with cancelQ := true, cancelled := true } :=
  { hI with outReqs := fun _ => Or.inl rfl, cancelQc := fun _ => rfl }

end Steps

theorem inv_step {P : Params} {s t : St} (hI : Inv P s) (h : Step P s t) : Inv P t := by
  cases h with
  | writePause _ _ _ hw => exact inv_writePause hI hw
  | writeChunk hl hc hr hw => exact inv_writeChunk hI hl hc hr hw
  | flowDead n rest _ hq _ hl => exact inv_flowDead hI n rest hq hl
  | flowRun n rest _ hq _ _ hp => exact inv_flowRun hI n rest hq hp
  | flowUnpause n rest _ hq _ hl => exact inv_flowUnpause hI n rest hq hl
  | unpauseReturn => exact inv_unpauseReturn hI
  | complete hl _ hr => exact inv_complete hI hl hr
  | fail _ hl => exact inv_fail hI hl
  | portCancel rest _ hq => exact inv_portCancel hI rest hq
  | workerFwd m rest hq hr hw => exact inv_workerFwd hI m rest hq hr hw
  | workerDrop m rest hq hr hw => exact inv_workerDrop hI m rest hq hr hw
  | workerFlow n rest hq => exact inv_workerFlow hI n rest hq
  | workerCancel hc hw => exact inv_workerCancel hI hc hw
  | workerTimeout _ hr hw => exact inv_workerTimeout hI hr hw
  | portDies _ hp => exact inv_portDies hI hp
  | workerExit _ hx hW => exact inv_workerExit hI hx hW
  | consumerRecv m rest hq => exact inv_consumerRecv hI m rest hq
  | consumerGrant hb => exact inv_consumerGrant hI hb
  | consumerCancel => exact inv_consumerCancel hI

theorem inv_reach {P : Params} {s : St} (h : Reach P s) : Inv P s := by
  induction h with
  | init => exact inv_init P
  | step _ hs ih => exact inv_step ih hs


/-! ## Headline corollaries -/

theorem credit_conservation_proof (P : Params) (s : St) (h : Reach P s)
    (hr : s.inReqs = true) (hl : s.live = true) : credits s = P.W :=
  (inv_reach h).creditsEq hr hl

theorem bounded_buffering_proof (P : Params) (s : St) (h : Reach P s) :
    outstanding s ≤ P.W := by
  have := (inv_reach h).creditsLe; simp only [credits] at this; omega

theorem no_lost_chunks_proof (P : Params) (s : St) (h : Reach P s)
    (hd : s.seenDone = true) : s.chunksSeen = P.total :=
  ((inv_reach h).seenDoneAll hd).2.2

theorem paused_agrees_proof (P : Params) (hc : P.clearFirst = true) (s : St)
    (h : Reach P s) : s.paused = s.curlPaused :=
  (inv_reach h).pausedAgree hc

/-! ## Termination: a potential every step decreases -/

/-- Weights decrease along each item's path (pipe 7 > consumer mailbox 6 >
owed 5 > grant 4 > port command 3), a body chunk outweighs the two
messages it can produce, and each one-way flag pays for what flipping it
enqueues. A port death costs 3 (`P.deaths` only) and queues an `'EXIT'`
worth 1. -/
def pot (P : Params) (s : St) : Nat :=
  15 * s.remaining + 7 * s.toW.length + 6 * s.toC.length + 5 * s.owed
    + 4 * s.flowQ.length + 3 * s.pQ.length + 4 * s.cancelQ.toNat
    + 15 * s.live.toNat + (1 - s.curlPaused.toNat) + s.unpausing.toNat
    + 10 * s.inReqs.toNat + 5 * (1 - s.cancelled.toNat)
    + 3 * (P.deaths && s.pAlive).toNat + s.exitQ.toNat

theorem hdrs_length (s : St) : (hdrs s).length ≤ 1 := by
  unfold hdrs; split <;> simp

theorem pot_init (P : Params) : pot P (init P) = 15 * P.total + 31 + 3 * P.deaths.toNat := by
  simp [pot, init]

theorem pot_step {P : Params} {s t : St} (h : Step P s t) : pot P t < pot P s := by
  have hb := P.batch_pos
  have hh := hdrs_length s
  have := Bool.toNat_le s.cancelQ; have := Bool.toNat_le s.live; have := Bool.toNat_le s.curlPaused
  have := Bool.toNat_le s.unpausing; have := Bool.toNat_le s.inReqs; have := Bool.toNat_le s.cancelled
  cases h with
  | writePause _ hc => simp only [pot, hc, Bool.toNat_true, Bool.toNat_false]; omega
  | writeChunk hl =>
    simp only [pot, List.length_append, List.length_cons, List.length_nil] at *; omega
  | flowDead _ _ _ hq => simp only [pot, hq, List.length_cons]; omega
  | flowRun _ _ _ hq => simp only [pot, hq, List.length_cons]; omega
  | flowUnpause _ _ hu hq => simp only [pot, hq, hu, List.length_cons, Bool.toNat_true, Bool.toNat_false]; omega
  | unpauseReturn hu => simp only [pot, hu, Bool.toNat_true, Bool.toNat_false]; omega
  | complete hl =>
    simp only [pot, hl, List.length_append, List.length_cons, List.length_nil,
      Bool.toNat_true, Bool.toNat_false] at *; omega
  | fail _ hl =>
    simp only [pot, hl, List.length_append, List.length_cons, List.length_nil,
      Bool.toNat_true, Bool.toNat_false]; omega
  | portCancel _ _ hq => simp only [pot, hq, List.length_cons, Bool.toNat_false]; omega
  | workerFwd m _ hq hr =>
    simp only [pot, hq, hr, List.length_append, List.length_cons, List.length_nil,
      Bool.toNat_true]
    have := Bool.toNat_le (m == .headers || m == .chunk); omega
  | workerDrop _ _ hq => simp only [pot, hq, List.length_cons]; omega
  | workerFlow _ _ hq =>
    simp only [pot, hq, List.length_cons]
    split <;> (try simp only [List.length_append, List.length_cons, List.length_nil]) <;> omega
  | workerCancel hc =>
    simp only [pot, hc, Bool.toNat_true, Bool.toNat_false]
    cases hr : s.inReqs <;> simp [hr] at * <;> omega
  | workerTimeout _ hr =>
    simp only [pot, hr, List.length_append, List.length_cons, List.length_nil,
      Bool.toNat_true, Bool.toNat_false]; omega
  | consumerRecv m _ hq =>
    simp only [pot, recv, hq, List.length_cons]
    cases m <;> simp <;> omega
  | consumerGrant hg =>
    simp only [pot, List.length_append, List.length_cons, List.length_nil]; omega
  | consumerCancel _ _ hc => simp only [pot, hc, Bool.toNat_true, Bool.toNat_false]; omega
  | portDies hd hp =>
    simp only [pot, hd, hp, Bool.and_true, Bool.and_false, Bool.toNat_true, Bool.toNat_false]
    omega
  | workerExit _ hx =>
    simp only [pot, hx, Bool.toNat_true, Bool.toNat_false]
    cases hr : s.inReqs <;> simp [hr] at * <;> omega

theorem steps_bounded_proof (P : Params) (f : Nat → St) (n : Nat) (h0 : f 0 = init P)
    (hs : ∀ i, i < n → Step P (f i) (f (i + 1))) :
    n ≤ 15 * P.total + 31 + 3 * P.deaths.toNat := by
  have key : ∀ i, i ≤ n → pot P (f i) + i ≤ pot P (f 0) := by
    intro i
    induction i with
    | zero => intro _; omega
    | succ k ih =>
      intro hk
      have := pot_step (hs k (by omega))
      have := ih (by omega)
      omega
  have := key n (Nat.le_refl n)
  rw [h0, pot_init] at this
  omega

/-! ## Stuck states are good -/

theorem stuck_is_good_proof (P : Params) (hc : P.clearFirst = true)
    (hb : P.batch ≤ P.W) (s : St) (h : Reach P s) (hs : Stuck P s) :
    Good s := by
  have hI := inv_reach h
  have hC : s.toC = [] := by
    cases hq : s.toC with
    | nil => rfl
    | cons m rest => exact absurd (Step.consumerRecv s m rest hq) (hs _)
  have outGood : s.inReqs = false → Good s := fun hr => by
    unfold Good; rcases hI.outReqs hr with h' | h' | h' | h' | h' <;> simp_all
  cases hwa : s.wAlive
  · exact outGood (hI.workerDead hwa).2.1
  have hW : s.toW = [] := by
    cases hq : s.toW with
    | nil => rfl
    | cons m rest =>
      cases hr : s.inReqs
      · exact absurd (Step.workerDrop s m rest hq hr hwa) (hs _)
      · exact absurd (Step.workerFwd s m rest hq hr hwa) (hs _)
  have hX : s.exitQ = false := by
    cases hx : s.exitQ
    · rfl
    · exact absurd (Step.workerExit s hwa hx hW) (hs _)
  have hpa : s.pAlive = true := by
    cases hp : s.pAlive
    · rcases (hI.portDead hp).2.2 with h' | h' <;> simp_all
    · rfl
  have hF : s.flowQ = [] := by
    cases hq : s.flowQ with
    | nil => rfl
    | cons n rest => exact absurd (Step.workerFlow s n rest hq hwa) (hs _)
  have hU : s.unpausing = false := by
    cases hq : s.unpausing
    · rfl
    · exact absurd (Step.unpauseReturn s hq) (hs _)
  have hQ : s.pQ = [] := by
    cases hq : s.pQ with
    | nil => rfl
    | cons n rest =>
      by_cases hn : n = 0
      · subst hn; exact absurd (Step.portCancel s rest hU hq hpa) (hs _)
      · cases hl : s.live
        · exact absurd (Step.flowDead s n rest hU hq hn hl hpa) (hs _)
        · cases hp : s.paused
          · exact absurd (Step.flowRun s n rest hU hq hn hl hp hpa) (hs _)
          · exact absurd (Step.flowUnpause s n rest hU hq hn hl hp hpa) (hs _)
  cases hr : s.inReqs
  · exact outGood hr
  · unfold Good
    have hl : s.live = true := by
      cases hl : s.live
      · rcases hI.deadPort hr hl with h' | h' | h' <;> simp_all
      · rfl
    have hcp : s.curlPaused = true := by
      cases hcp : s.curlPaused
      · by_cases hrem : s.remaining = 0
        · exact absurd (Step.complete s hl hU hrem hcp) (hs _)
        · by_cases hw : s.window = 0
          · exact absurd (Step.writePause s hl hcp (by omega) hw) (hs _)
          · exact absurd (Step.writeChunk s hl hcp (by omega) hw) (hs _)
      · rfl
    have hw := hI.pausedWin hc hcp
    have hcr := hI.creditsEq hr hl
    simp only [credits, outstanding, hW, hC, hF, hQ, hw, cnt_nil, sum_nil] at hcr
    cases ht : terminal s
    · exact absurd (Step.consumerGrant s (by omega) ht) (hs _)
    · simp only [terminal, Bool.or_eq_true] at ht
      rcases ht with h' | h' <;> simp [h']

end KatipoProofs.Flow
