import KatipoProofs.Flow.Model

/-!
# Flow control: computable successor function

`succs P s` lists the successors of `s`, one block per `Step` constructor.
`succs_sound` and `succs_complete` make it the `Step` relation by proof, so
the state graph `scripts/FlowGraph.lean` enumerates from it *is* the Lean
model's graph -- which `scripts/crosscheck_flow.py` then diffs against
TLC's dump of `KatipoFlow.tla`.
-/

namespace KatipoProofs.Flow

deriving instance Hashable for Msg
deriving instance Hashable for St

def succs (P : Params) (s : St) : List St :=
  (if s.live = true ∧ s.curlPaused = false ∧ 0 < s.remaining ∧ s.window = 0 ∧
      s.failed = false
   then [{ s with paused := true, curlPaused := true }] else []) ++
  (if s.live = true ∧ s.curlPaused = false ∧ 0 < s.remaining ∧ s.window ≠ 0 ∧
      s.failed = false
   then [{ s with toW := s.toW ++ hdrs s ++ [.chunk], headersSent := true,
                  window := s.window - 1, remaining := s.remaining - 1 }] else []) ++
  (match s.pQ with
   | n :: rest =>
     if s.pAlive = false then []
     else if s.unpausing = false ∧ n ≠ 0 then
       if s.live = false then [{ s with pQ := rest }]
       else if s.paused = false then [{ s with pQ := rest, window := s.window + n }]
       else [{ s with pQ := rest, window := s.window + n, curlPaused := false,
                      unpausing := true,
                      paused := if P.clearFirst then false else s.paused }]
     else if s.unpausing = false ∧ n = 0 then [{ s with pQ := rest, live := false }]
     else []
   | [] => []) ++
  (if s.unpausing = true ∧ (P.completeOnFail && s.failed) = false
   then [{ s with unpausing := false,
                  paused := if P.clearFirst then s.paused else false }] else []) ++
  (if s.live = true ∧ s.unpausing = false ∧ s.remaining = 0 ∧ s.curlPaused = false
   then [{ s with toW := s.toW ++ hdrs s ++ [.done], headersSent := true,
                  live := false }] else []) ++
  (if P.failures = true ∧ s.live = true ∧ s.unpausing = false
   then [{ s with toW := s.toW ++ [.error], live := false }] else []) ++
  (match s.toW with
   | m :: rest =>
     if s.wAlive = false then []
     else if s.inReqs = true
     then [{ s with toW := rest, toC := s.toC ++ [m],
                    inReqs := (m == .headers || m == .chunk) }]
     else [{ s with toW := rest }]
   | [] => []) ++
  (match s.flowQ with
   | n :: rest =>
     if s.wAlive = true
     then [{ s with flowQ := rest, pQ := if s.inReqs then s.pQ ++ [n] else s.pQ }]
     else []
   | [] => []) ++
  (if s.cancelQ = true ∧ s.wAlive = true
   then [{ s with cancelQ := false, inReqs := false,
                  pQ := if s.inReqs then s.pQ ++ [0] else s.pQ }] else []) ++
  (if P.timeouts = true ∧ s.inReqs = true ∧ s.wAlive = true
   then [{ s with inReqs := false, toC := s.toC ++ [.error], pQ := s.pQ ++ [0] }]
   else []) ++
  (if P.deaths = true ∧ s.pAlive = true
   then [{ s with pAlive := false, live := false, exitQ := true, unpausing := false,
                  paused := false, curlPaused := false }] else []) ++
  (if s.wAlive = true ∧ s.exitQ = true ∧ s.toW = []
   then [{ s with wAlive := false, exitQ := false, inReqs := false,
                  toC := if s.inReqs then s.toC ++ [.error] else s.toC }] else []) ++
  (match s.toC with
   | m :: rest => [recv s m rest]
   | [] => []) ++
  (if P.batch ≤ s.owed ∧ terminal s = false
   then [{ s with flowQ := s.flowQ ++ [s.owed], owed := 0 }] else []) ++
  (if P.cancels = true ∧ terminal s = false ∧ s.cancelled = false
   then [{ s with cancelQ := true, cancelled := true }] else []) ++
  (if P.limits = true ∧ s.live = true ∧ s.curlPaused = false ∧ 0 < s.remaining ∧
      s.window ≠ 0 ∧ s.failed = false ∧ s.unpausing = false
   then [{ s with toW := s.toW ++ [.error], live := false }] else []) ++
  (if P.limits = true ∧ s.live = true ∧ s.curlPaused = false ∧ 0 < s.remaining ∧
      s.window ≠ 0 ∧ s.failed = false ∧ s.unpausing = true
   then [{ s with failed := true }] else []) ++
  (if s.unpausing = true ∧ P.completeOnFail = true ∧ s.failed = true
   then [{ s with unpausing := false, toW := s.toW ++ [.error], live := false }] else [])

theorem succs_complete {P : Params} {s t : St} (h : Step P s t) : t ∈ succs P s := by
  cases h <;> simp_all [succs]

theorem succs_sound {P : Params} {s t : St} (h : t ∈ succs P s) : Step P s t := by
  simp only [succs, List.mem_append] at h
  rcases h with
    (((((((((((((((((h | h) | h) | h) | h) | h) | h) | h) | h) | h) | h) | h) | h) | h) | h) |
       h) | h) | h)
  · split at h <;> simp only [List.mem_singleton, List.not_mem_nil] at h
    rename_i hg; subst h; exact .writePause s hg.1 hg.2.1 hg.2.2.1 hg.2.2.2.1 hg.2.2.2.2
  · split at h <;> simp only [List.mem_singleton, List.not_mem_nil] at h
    rename_i hg; subst h; exact .writeChunk s hg.1 hg.2.1 hg.2.2.1 hg.2.2.2.1 hg.2.2.2.2
  · split at h
    · rename_i n rest hq
      split at h
      · simp only [List.not_mem_nil] at h
      · rename_i hpa
        have hpa : s.pAlive = true := by simpa using hpa
        split at h
        · rename_i hg
          split at h
          · rename_i hl; simp only [List.mem_singleton] at h; subst h
            exact .flowDead s n rest hg.1 hq hg.2 hl hpa
          · rename_i hl
            split at h
            · rename_i hp; simp only [List.mem_singleton] at h; subst h
              exact .flowRun s n rest hg.1 hq hg.2 (by simpa using hl) hp hpa
            · rename_i hp; simp only [List.mem_singleton] at h; subst h
              exact .flowUnpause s n rest hg.1 hq hg.2 (by simpa using hl) (by simpa using hp) hpa
        · split at h
          · rename_i _ hg; simp only [List.mem_singleton] at h; subst h; rw [hg.2] at hq
            exact .portCancel s rest hg.1 hq hpa
          · simp only [List.not_mem_nil] at h
    · simp only [List.not_mem_nil] at h
  · split at h <;> simp only [List.mem_singleton, List.not_mem_nil] at h
    rename_i hg; subst h; exact .unpauseReturn s hg.1 hg.2
  · split at h <;> simp only [List.mem_singleton, List.not_mem_nil] at h
    rename_i hg; subst h; exact .complete s hg.1 hg.2.1 hg.2.2.1 hg.2.2.2
  · split at h <;> simp only [List.mem_singleton, List.not_mem_nil] at h
    rename_i hg; subst h; exact .fail s hg.1 hg.2.1 hg.2.2
  · split at h
    · rename_i m rest hq
      split at h
      · simp only [List.not_mem_nil] at h
      · rename_i hw
        have hw : s.wAlive = true := by simpa using hw
        split at h
        · rename_i hr; simp only [List.mem_singleton] at h; subst h
          exact .workerFwd s m rest hq hr hw
        · rename_i hr; simp only [List.mem_singleton] at h; subst h
          exact .workerDrop s m rest hq (by simpa using hr) hw
    · simp only [List.not_mem_nil] at h
  · split at h
    · rename_i n rest hq
      split at h <;> simp only [List.mem_singleton, List.not_mem_nil] at h
      rename_i hw; subst h; exact .workerFlow s n rest hq hw
    · simp only [List.not_mem_nil] at h
  · split at h <;> simp only [List.mem_singleton, List.not_mem_nil] at h
    rename_i hg; subst h; exact .workerCancel s hg.1 hg.2
  · split at h <;> simp only [List.mem_singleton, List.not_mem_nil] at h
    rename_i hg; subst h; exact .workerTimeout s hg.1 hg.2.1 hg.2.2
  · split at h <;> simp only [List.mem_singleton, List.not_mem_nil] at h
    rename_i hg; subst h; exact .portDies s hg.1 hg.2
  · split at h <;> simp only [List.mem_singleton, List.not_mem_nil] at h
    rename_i hg; subst h; exact .workerExit s hg.1 hg.2.1 hg.2.2
  · split at h
    · rename_i m rest hq; simp only [List.mem_singleton] at h; subst h; exact .consumerRecv s m rest hq
    · simp only [List.not_mem_nil] at h
  · split at h <;> simp only [List.mem_singleton, List.not_mem_nil] at h
    rename_i hg; subst h; exact .consumerGrant s hg.1 hg.2
  · split at h <;> simp only [List.mem_singleton, List.not_mem_nil] at h
    rename_i hg; subst h; exact .consumerCancel s hg.1 hg.2.1 hg.2.2
  · split at h <;> simp only [List.mem_singleton, List.not_mem_nil] at h
    rename_i hg; subst h
    exact .writeFailEvent s hg.1 hg.2.1 hg.2.2.1 hg.2.2.2.1 hg.2.2.2.2.1 hg.2.2.2.2.2.1
      hg.2.2.2.2.2.2
  · split at h <;> simp only [List.mem_singleton, List.not_mem_nil] at h
    rename_i hg; subst h
    exact .writeFailSync s hg.1 hg.2.1 hg.2.2.1 hg.2.2.2.1 hg.2.2.2.2.1 hg.2.2.2.2.2.1
      hg.2.2.2.2.2.2
  · split at h <;> simp only [List.mem_singleton, List.not_mem_nil] at h
    rename_i hg; subst h; exact .unpauseFail s hg.1 hg.2.1 hg.2.2

theorem succs_iff {P : Params} {s t : St} : t ∈ succs P s ↔ Step P s t :=
  ⟨succs_sound, succs_complete⟩

end KatipoProofs.Flow
