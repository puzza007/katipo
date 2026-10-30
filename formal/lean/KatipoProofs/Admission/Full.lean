import KatipoProofs.Admission.Proofs

/-!
# The exact admission model: `KatipoFixed.tla` with its port

`Model.lean` is deliberately loose: an environment that injects any message
at any time, a worker that may crash anywhere and read its mailbox in any
order. That is right for safety and wrong for liveness, and it has no C port,
so it cannot state `NoOrphanTransfer`. This file transcribes the TLA+ spec
as it is: one FIFO mailbox with timeout and exit messages, the worker -> port
command pipe `pQ`, the port's running transfers `conns`, port deaths and
per-request timers. One `FStep` constructor per TLA+ action branch.

`proj` forgets the port and folds timeouts into responses; `fstep_proj`
shows every `FStep` is a `Step` (or a stutter) of the loose model, so every
safety theorem holds here too (`freach_reach`).

## Differences from the TLA+ spec
* No state-space bounds: port deaths and chunks per transfer are unbounded
  (`MaxPortDeaths`, `MaxChunks` dropped, with `deaths`, `chunksEmitted`).
* `WorkerRestart` leaves `reqs` alone instead of emptying it: it is empty
  whenever the worker is dead (`FInv.dead`), so this changes nothing.
* `cancelPollution` is constantly `FALSE` in the spec and is omitted.
-/

namespace KatipoProofs.Admission.Full
open KatipoProofs.Admission

variable {R : Type} [DecidableEq R]
set_option linter.unusedSectionVars false

/-- The worker's mailbox (`ReqMsg` ... `ExitMsg`). -/
inductive FMsg (R : Type) where
  | req (r : R)
  | cancel (r : R)
  | resp (r : R)
  | timeout (r : R)
  | chunk (r : R)
  | exit
  deriving DecidableEq

/-- Worker -> port commands. -/
inductive PMsg (R : Type) where
  | req (r : R)
  | cancel (r : R)
  deriving DecidableEq

def FMsg.toW : FMsg R → Option (WMsg R)
  | .req r => some (.req r)
  | .cancel r => some (.cancel r)
  | .resp r => some (.resp r)
  | .timeout r => some (.resp r)
  | .chunk r => some (.chunk r)
  | .exit => none

structure FSt (R : Type) where
  /-- every variable of the loose model except its mailbox, which `proj`
  derives from `fq` (`c.wQ` is never read) -/
  c : St R
  fq : List (FMsg R)
  pAlive : Bool
  pQ : List (PMsg R)
  conns : R → Bool
  fired : R → Bool

def proj (f : FSt R) : St R := { f.c with wQ := f.fq.filterMap FMsg.toW }

def finit : FSt R := ⟨init, [], true, [], fun _ => false, fun _ => false⟩

/-- `AbortPQ`: best-effort port cancel, nothing to write to a dead port. -/
def abortPQ (f : FSt R) (r : R) : List (PMsg R) :=
  if f.pAlive then f.pQ ++ [.cancel r] else f.pQ

/-- `Crash`: the incarnation and its port are gone. -/
def fcrash (f : FSt R) : FSt R :=
  { f with c := crash f.c, fq := [], pAlive := false, pQ := [], conns := fun _ => false }

/-- `WorkerDispatch`: the worker's steps, one constructor per branch. -/
inductive WStep (P : Params) : FSt R → FSt R → Prop
  | recvReqExpired (f : FSt R) (r : R) (rest : List (FMsg R)) : f.c.wAlive = true →
      f.c.phase = .idle → f.fq = .req r :: rest → (P.deadline && f.c.expired r) = true →
      WStep P f { f with c := replyExpired f.c r, fq := rest }
  | recvReqSend (f : FSt R) (r : R) (rest : List (FMsg R)) : f.c.wAlive = true →
      f.c.phase = .idle → f.fq = .req r :: rest → (P.deadline && f.c.expired r) = false →
      f.pAlive = true →
      WStep P f { f with c := { f.c with phase := .sent r }, fq := rest,
                         pQ := f.pQ ++ [.req r] }
  | recvReqCrash (f : FSt R) (r : R) (rest : List (FMsg R)) : f.c.wAlive = true →
      f.c.phase = .idle → f.fq = .req r :: rest → (P.deadline && f.c.expired r) = false →
      f.pAlive = false →
      WStep P f (fcrash f)
  | checkRefuse (f : FSt R) (r : R) : f.c.wAlive = true → f.c.phase = .sent r →
      (P.deadline && f.c.expired r) = true →
      WStep P f { f with c := { replyExpired f.c r with phase := .idle }, pQ := abortPQ f r }
  | checkPass (f : FSt R) (r : R) : f.c.wAlive = true → f.c.phase = .sent r →
      (P.deadline && f.c.expired r) = false →
      WStep P f { f with c := { f.c with phase := .checked r } }
  | admitReply (f : FSt R) (r : R) : f.c.wAlive = true → f.c.phase = .checked r →
      WStep P f { f with c := { f.c with reqs := upd f.c.reqs r true,
                                         pending := upd f.c.pending r false,
                                         accepted := upd f.c.accepted r
                                           (f.c.accepted r || f.c.pending r),
                                         phase := .idle } }
  | recvCancel (f : FSt R) (r : R) (rest : List (FMsg R)) : f.c.wAlive = true →
      f.c.phase = .idle → f.fq = .cancel r :: rest →
      WStep P f (if f.c.reqs r then
          { f with c := { f.c with reqs := upd f.c.reqs r false,
                                   effCancel := upd f.c.effCancel r true,
                                   snap := upd f.c.snap r (f.c.delivered r),
                                   spans := upd f.c.spans r (f.c.spans r + 1) },
                   fq := rest, pQ := abortPQ f r }
        else { f with fq := rest })
  | recvResp (f : FSt R) (r : R) (rest : List (FMsg R)) : f.c.wAlive = true →
      f.c.phase = .idle → f.fq = .resp r :: rest →
      WStep P f (if f.c.reqs r then
          { f with c := { resolve f.c r 1 with reqs := upd f.c.reqs r false }, fq := rest }
        else { f with fq := rest })
  | recvTimeout (f : FSt R) (r : R) (rest : List (FMsg R)) : f.c.wAlive = true →
      f.c.phase = .idle → f.fq = .timeout r :: rest →
      WStep P f (if f.c.reqs r then
          { f with c := { resolve f.c r 1 with reqs := upd f.c.reqs r false }, fq := rest,
                   pQ := abortPQ f r }
        else { f with fq := rest })
  | recvChunk (f : FSt R) (r : R) (rest : List (FMsg R)) : f.c.wAlive = true →
      f.c.phase = .idle → f.fq = .chunk r :: rest →
      WStep P f { f with c := { f.c with progressStop := f.c.progressStop ||
                          (f.c.reqs r && (f.c.effCancel r || decide (0 < f.c.delivered r))) },
                         fq := rest }
  | recvExit (f : FSt R) (rest : List (FMsg R)) : f.c.wAlive = true →
      f.c.phase = .idle → f.fq = .exit :: rest →
      WStep P f (fcrash f)

inductive FStep (P : Params) : FSt R → FSt R → Prop
  -- Caller and environment
  | sendLive (f : FSt R) (r : R) : f.c.sent r = false → f.c.wAlive = true →
      FStep P f { f with c := { f.c with sent := upd f.c.sent r true,
                                         pending := upd f.c.pending r true },
                         fq := f.fq ++ [.req r] }
  | sendDead (f : FSt R) (r : R) : f.c.sent r = false → f.c.wAlive = false →
      FStep P f { f with c := { resolve f.c r 1 with sent := upd f.c.sent r true } }
  | expire (f : FSt R) (r : R) : (P.callerTimeouts || P.deadline) = true →
      f.c.pending r = true → f.c.expired r = false →
      FStep P f { f with c := { f.c with expired := upd f.c.expired r true } }
  | callerTimeout (f : FSt R) (r : R) : P.callerTimeouts = true →
      f.c.pending r = true → f.c.expired r = true →
      (P.slack = true → f.c.phase ≠ .checked r) →
      FStep P f { f with c := { resolve f.c r 1 with pending := upd f.c.pending r false,
                                                     gaveUp := upd f.c.gaveUp r true } }
  | sendCancel (f : FSt R) (r : R) : f.c.accepted r = true → f.c.cancelled r = false →
      FStep P f { f with c := { f.c with cancelled := upd f.c.cancelled r true },
                         fq := if f.c.wAlive then f.fq ++ [.cancel r] else f.fq }
  | worker {f g : FSt R} : WStep P f g → FStep P f g
  -- C port (`PortDispatch`, `PortComplete`, `PortEmitChunk`, `PortDies`)
  | portRecvReq (f : FSt R) (r : R) (rest : List (PMsg R)) : f.pAlive = true →
      f.pQ = .req r :: rest →
      FStep P f { f with pQ := rest, conns := upd f.conns r true }
  | portRecvCancel (f : FSt R) (r : R) (rest : List (PMsg R)) : f.pAlive = true →
      f.pQ = .cancel r :: rest →
      FStep P f { f with pQ := rest, conns := upd f.conns r false }
  | portComplete (f : FSt R) (r : R) : f.pAlive = true → f.conns r = true →
      FStep P f { f with conns := upd f.conns r false, fq := f.fq ++ [.resp r] }
  | portEmitChunk (f : FSt R) (r : R) : f.pAlive = true → f.conns r = true →
      FStep P f { f with fq := f.fq ++ [.chunk r] }
  | portDies (f : FSt R) : f.c.wAlive = true → f.pAlive = true →
      FStep P f { f with pAlive := false, conns := fun _ => false, pQ := [],
                         fq := f.fq ++ [.exit] }
  -- Request timer and supervisor
  | timerFire (f : FSt R) (r : R) : f.c.wAlive = true → f.c.reqs r = true →
      f.fired r = false →
      FStep P f { f with fired := upd f.fired r true, fq := f.fq ++ [.timeout r] }
  | restart (f : FSt R) : f.c.wAlive = false →
      FStep P f { f with c := { f.c with wAlive := true }, fq := [], pAlive := true, pQ := [],
                         conns := fun _ => false }

inductive FReach (P : Params) : FSt R → Prop
  | init : FReach P finit
  | step {f g : FSt R} : FReach P f → FStep P f g → FReach P g

/-! ## Refinement of the loose model -/

/-- What the refinement needs about dead workers and ports. -/
structure FInv (f : FSt R) : Prop where
  portLive : f.pAlive = true → f.c.wAlive = true
  dead : f.c.wAlive = false → f.fq = [] ∧ f.c.phase = .idle ∧ ∀ r, f.c.reqs r = false

theorem finv_init : FInv (finit : FSt R) := ⟨fun _ => rfl, fun h => by simp [finit, init] at h⟩

@[simp] theorem toW_req (r : R) : (FMsg.req r).toW = some (.req r) := rfl
@[simp] theorem toW_cancel (r : R) : (FMsg.cancel r).toW = some (.cancel r) := rfl
@[simp] theorem toW_resp (r : R) : (FMsg.resp r).toW = some (.resp r) := rfl
@[simp] theorem toW_timeout (r : R) : (FMsg.timeout r).toW = some (.resp r) := rfl
@[simp] theorem toW_chunk (r : R) : (FMsg.chunk r).toW = some (.chunk r) := rfl
@[simp] theorem toW_exit : (FMsg.exit : FMsg R).toW = none := rfl

theorem finv_step {P : Params} {f g : FSt R} (hI : FInv f) (h : FStep P f g) : FInv g := by
  obtain ⟨hp, hd⟩ := hI
  cases h with
  | worker hw =>
    cases hw <;> (try split) <;> refine ⟨fun h => ?_, fun h => ?_⟩ <;>
      simp_all [fcrash, crash, replyExpired, resolve]
  | _ => (try split) <;> refine ⟨fun h => ?_, fun h => ?_⟩ <;> simp_all [resolve]

theorem finv_reach {P : Params} {f : FSt R} (h : FReach P f) : FInv f := by
  induction h with
  | init => exact finv_init
  | step _ hs ih => exact finv_step ih hs

/-- Every exact step is a loose step, or leaves the projection unchanged. -/
theorem fstep_proj {P : Params} {f g : FSt R} (hI : FInv f) (h : FStep P f g) :
    Step P (proj f) (proj g) ∨ proj f = proj g := by
  cases h with
  | worker hw =>
    cases hw with
    | recvReqExpired r rest hw hi hq hd =>
      left; have := Step.recvReqExpired (P := P) (proj f) r [] (rest.filterMap FMsg.toW) hw hi
        (by simp [proj, hq]) hd
      simpa [proj, replyExpired, resolve] using this
    | recvReqSend r rest hw hi hq hd _ =>
      left; have := Step.recvReq (P := P) (proj f) r [] (rest.filterMap FMsg.toW) hw hi
        (by simp [proj, hq]) hd
      simpa [proj] using this
    | recvReqCrash r rest hw =>
      left; have := Step.crash (P := P) (proj f) hw
      simpa [proj, fcrash, crash] using this
    | checkRefuse r hw hph hd =>
      left; have := Step.checkRefuse (P := P) (proj f) r hw hph hd
      simpa [proj, replyExpired, resolve] using this
    | checkPass r hw hph hd =>
      left; have := Step.checkPass (P := P) (proj f) r hw hph hd
      simpa [proj] using this
    | admitReply r hw hph =>
      left; have := Step.admitReply (P := P) (proj f) r hw hph
      simpa [proj] using this
    | recvCancel r rest hw hi hq =>
      left; have := Step.recvCancel (P := P) (proj f) r [] (rest.filterMap FMsg.toW) hw hi
        (by simp [proj, hq])
      by_cases hr : f.c.reqs r = true <;> simp_all [proj]
    | recvResp r rest hw hi hq =>
      left; have := Step.recvResp (P := P) (proj f) r [] (rest.filterMap FMsg.toW) hw hi
        (by simp [proj, hq])
      by_cases hr : f.c.reqs r = true <;> simp_all [proj, resolve]
    | recvTimeout r rest hw hi hq =>
      left; have := Step.recvResp (P := P) (proj f) r [] (rest.filterMap FMsg.toW) hw hi
        (by simp [proj, hq])
      by_cases hr : f.c.reqs r = true <;> simp_all [proj, resolve]
    | recvChunk r rest hw hi hq =>
      left; have := Step.recvChunk (P := P) (proj f) r [] (rest.filterMap FMsg.toW) hw hi
        (by simp [proj, hq])
      simp only [proj] at this ⊢
      exact this
    | recvExit rest hw hi hq =>
      left; have := Step.crash (P := P) (proj f) hw
      simpa [proj, fcrash, crash] using this
  | sendLive r hs hw =>
    left; have := Step.sendLive (P := P) (proj f) r hs hw
    simpa [proj, List.filterMap_append] using this
  | sendDead r hs hw =>
    left; have := Step.sendDead (P := P) (proj f) r hs hw
    simpa [proj, resolve] using this
  | expire r h1 h2 h3 =>
    left; have := Step.expire (P := P) (proj f) r h1 h2 h3
    simpa [proj] using this
  | callerTimeout r h1 h2 h3 h4 =>
    left; have := Step.callerTimeout (P := P) (proj f) r h1 h2 h3 h4
    simpa [proj, resolve] using this
  | sendCancel r h1 h2 =>
    left; have := Step.sendCancel (P := P) (proj f) r h1 h2
    by_cases hw : f.c.wAlive = true <;> simp_all [proj, List.filterMap_append]
  | portRecvReq => right; rfl
  | portRecvCancel => right; rfl
  | portComplete r hpa _ =>
    left; have := Step.emitResp (P := P) (proj f) r (hI.portLive hpa)
    simpa [proj, List.filterMap_append] using this
  | portEmitChunk r hpa _ =>
    left; have := Step.emitChunk (P := P) (proj f) r (hI.portLive hpa)
    simpa [proj, List.filterMap_append] using this
  | portDies => right; simp [proj, List.filterMap_append]
  | timerFire r hw _ _ =>
    left; have := Step.emitResp (P := P) (proj f) r hw
    simpa [proj, List.filterMap_append] using this
  | restart hw =>
    left; have := Step.restart (P := P) (proj f) hw
    simpa [proj] using this

theorem freach_reach {P : Params} {f : FSt R} (h : FReach P f) : Reach P (proj f) := by
  induction h with
  | init => exact Reach.init
  | step hf hs ih =>
    rcases fstep_proj (finv_reach hf) hs with h | h
    · exact .step ih h
    · exact h ▸ ih

end KatipoProofs.Admission.Full
