import KatipoProofs.Admission.Full

/-!
# `NoOrphanTransfer`: every running C transfer is owned

A transfer the port is running (`conns r`) is in `Reqs`, is being admitted,
or already has an abort queued for it in `pQ`. An orphan would run to
completion -- side effects and all -- with nobody to deliver to.

The heart of it is `aborted`: an abort for `r` is always queued *behind*
its request in the FIFO pipe, so the port never sees the abort first and
then starts the transfer. `ua r pQ` ("unaborted") says some `req r` in the
pipe has no `cancel r` after it.
-/

namespace KatipoProofs.Admission.Full
open KatipoProofs.Admission

variable {R : Type} [DecidableEq R]
set_option linter.unusedSectionVars false

/-- `req r` commands in the pipe. -/
def cntP (r : R) : List (PMsg R) → Nat
  | [] => 0
  | .req x :: l => (if x = r then 1 else 0) + cntP r l
  | .cancel _ :: l => cntP r l

/-- Some `req r` in the pipe has no `cancel r` behind it. -/
def ua (r : R) : List (PMsg R) → Bool
  | [] => false
  | .req x :: l => (decide (x = r) && !l.contains (.cancel r)) || ua r l
  | .cancel _ :: l => ua r l

@[simp] theorem cntP_nil (r : R) : cntP r ([] : List (PMsg R)) = 0 := rfl
@[simp] theorem cntP_req (r x : R) (l : List (PMsg R)) :
    cntP r (.req x :: l) = (if x = r then 1 else 0) + cntP r l := rfl
@[simp] theorem cntP_cancel (r x : R) (l : List (PMsg R)) :
    cntP r (.cancel x :: l) = cntP r l := rfl
@[simp] theorem cntP_append (r : R) (a b : List (PMsg R)) :
    cntP r (a ++ b) = cntP r a + cntP r b := by
  induction a with
  | nil => simp
  | cons m ms ih => cases m <;> simp [ih] <;> omega

theorem cntP_pos (r : R) : ∀ l : List (PMsg R), 0 < cntP r l ↔ PMsg.req r ∈ l
  | [] => by simp
  | .req x :: l => by
    have := cntP_pos r l
    by_cases h : x = r <;> simp [h, this] <;> grind
  | .cancel x :: l => by simp [cntP_pos r l]

@[simp] theorem ua_nil (r : R) : ua r ([] : List (PMsg R)) = false := rfl

theorem ua_mem (r : R) : ∀ l : List (PMsg R), ua r l = true → PMsg.req r ∈ l
  | [] => by simp
  | .req x :: l => by
    intro h; simp [ua] at h
    rcases h with ⟨rfl, -⟩ | h
    · simp
    · simp [ua_mem r l h]
  | .cancel x :: l => by intro h; simp [ua] at h; simp [ua_mem r l h]

theorem ua_append (r : R) (m : PMsg R) : ∀ l : List (PMsg R),
    ua r (l ++ [m]) = (match m with
      | .req x => decide (x = r) || ua r l
      | .cancel x => if x = r then false else ua r l)
  | [] => by cases m <;> simp [ua] <;> split <;> simp_all
  | .req y :: l => by
    have ih := ua_append r m l
    cases m with
    | req x => simp only [ua, List.cons_append, ih]; by_cases hy : y = r <;> by_cases hx : x = r <;> simp_all
    | cancel x =>
      simp only [ua, List.cons_append, ih]
      by_cases hx : x = r <;> by_cases hy : y = r <;> simp_all
      have : ¬ r = x := fun h => hx h.symm
      simp [this]
  | .cancel y :: l => by
    have ih := ua_append r m l
    simp only [ua, List.cons_append, ih]


@[simp] theorem ua_abortPQ (f : FSt R) (r x : R) :
    ua x (abortPQ f r) = (if f.pAlive then (if r = x then false else ua x f.pQ) else ua x f.pQ) := by
  unfold abortPQ; split <;> simp [ua_append, *]

@[simp] theorem cntP_abortPQ (f : FSt R) (r x : R) : cntP x (abortPQ f r) = cntP x f.pQ := by
  unfold abortPQ; split <;> simp

@[simp] theorem mem_abortPQ_req (f : FSt R) (r x : R) :
    PMsg.req x ∈ abortPQ f r ↔ PMsg.req x ∈ f.pQ := by
  unfold abortPQ; split <;> simp

@[simp] theorem mem_abortPQ_cancel (f : FSt R) (r x : R) :
    PMsg.cancel x ∈ abortPQ f r ↔ (f.pAlive = true ∧ x = r) ∨ PMsg.cancel x ∈ f.pQ := by
  by_cases h : f.pAlive = true <;> simp [abortPQ, h, or_comm]

@[simp] theorem abortPQ_nil (f : FSt R) (r : R) :
    abortPQ f r = [] ↔ f.pAlive = false ∧ f.pQ = [] := by
  by_cases h : f.pAlive = true <;> simp [abortPQ, h]

/-- `NoOrphanTransfer`, with what makes it inductive. -/
structure OInv (f : FSt R) : Prop where
  /-- the property itself -/
  owned : ∀ r, f.conns r = true →
    f.c.reqs r = true ∨ admitting f.c r ∨ PMsg.cancel r ∈ f.pQ
  /-- a request still in the pipe with no abort behind it is owned -/
  aborted : ∀ r, ua r f.pQ = true → f.c.reqs r = true ∨ admitting f.c r
  /-- the port has finished `r`: it will not start it again -/
  done : ∀ r, FMsg.resp r ∈ f.fq → f.conns r = false ∧ PMsg.req r ∉ f.pQ
  /-- a dead port runs nothing and has nothing queued -/
  deadPort : ∀ r, f.pAlive = false → f.conns r = false ∧ f.pQ = []
  /-- a request still in the mailbox has not reached the port -/
  queued : ∀ r, FMsg.req r ∈ f.fq →
    PMsg.req r ∉ f.pQ ∧ f.conns r = false ∧ FMsg.resp r ∉ f.fq
  /-- nor has one never sent -/
  fresh : ∀ r, f.c.sent r = false →
    PMsg.req r ∉ f.pQ ∧ f.conns r = false ∧ FMsg.resp r ∉ f.fq ∧ FMsg.req r ∉ f.fq
  /-- the port starts each transfer once -/
  once : ∀ r, cntP r f.pQ + (f.conns r).toNat ≤ 1

theorem oinv_init : OInv (finit : FSt R) := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_⟩ <;> simp [finit]

/-- Membership in the mailbox, as the loose model's counter sees it. -/
theorem req_mem_of_cnt (r : R) : ∀ l : List (FMsg R),
    FMsg.req r ∈ l ↔ 0 < cntReq r (l.filterMap FMsg.toW)
  | [] => by simp
  | m :: l => by
    have ih := req_mem_of_cnt r l
    cases m <;> simp [ih] <;> grind


/-- Prove every `OInv` field after a step that touches request `r`
(`orphq r hq`: and whose guard `hq` pins a queue's head). -/
syntax "orph" ident : tactic
syntax "orphq" ident ident : tactic
set_option hygiene false in
macro_rules
  | `(tactic| orph $r) => `(tactic| (
      obtain ⟨o1, o2, o3, o4, o5, o6, o7⟩ := hO
      have hp := hF.portLive
      have hd := hF.dead
      refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
      all_goals
        intro x
        have a1 := o1 x; have a2 := o2 x; have a3 := o3 x; have a4 := o4 x
        have a5 := o5 x; have a6 := o6 x; have a7 := o7 x
        have b1 := o1 $r; have b2 := o2 $r; have b3 := o3 $r; have b4 := o4 $r
        have b5 := o5 $r; have b6 := o6 $r; have b7 := o7 $r
        have jq := hJ.queued x; have jf := hJ.fresh x; have ja := hJ.inAdmit x
        have jc := hJ.acc x; have jr := hJ.reqsAcc x
        have kq := hJ.queued $r; have kf := hJ.fresh $r; have ka := hJ.inAdmit $r
        have kc := hJ.acc $r; have kr := hJ.reqsAcc $r
        clear o1 o2 o3 o4 o5 o6 o7
        by_cases hx : x = $r
        · subst hx
          simp only [proj, upd_same, admitting, abortPQ_nil, ua_abortPQ, cntP_abortPQ, mem_abortPQ_req, mem_abortPQ_cancel, ua_append, cntP_append, cntP_nil,
            cntP_req, cntP_cancel, replyExpired, resolve, Bool.toNat, if_true, List.mem_append,
            List.mem_singleton, List.mem_cons, FMsg.req.injEq, FMsg.resp.injEq, FMsg.cancel.injEq,
            PMsg.req.injEq, PMsg.cancel.injEq, reduceCtorEq, List.not_mem_nil, req_mem_of_cnt, List.filterMap_append, cntReq_append] at *
          grind [ua_mem, cntP_pos]
        · have hx' : ¬ $r = x := fun h => hx h.symm
          simp only [proj, upd_other _ _ _ _ hx, if_neg hx, if_neg hx', decide_eq_false hx, decide_eq_false hx', admitting, abortPQ_nil, ua_abortPQ, cntP_abortPQ, mem_abortPQ_req, mem_abortPQ_cancel, ua_append,
            cntP_append, cntP_nil, cntP_req, cntP_cancel, replyExpired, resolve, Bool.toNat,
            if_false, List.mem_append, List.mem_singleton, List.mem_cons, FMsg.req.injEq,
            FMsg.resp.injEq, FMsg.cancel.injEq, PMsg.req.injEq, PMsg.cancel.injEq, reduceCtorEq,
            List.not_mem_nil, req_mem_of_cnt, List.filterMap_append, cntReq_append] at *
          grind [ua_mem, cntP_pos]))
set_option hygiene false in
macro_rules
  | `(tactic| orphq $r $hq) => `(tactic| (
      obtain ⟨o1, o2, o3, o4, o5, o6, o7⟩ := hO
      have hp := hF.portLive
      have hd := hF.dead
      refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
      all_goals
        intro x
        have a1 := o1 x; have a2 := o2 x; have a3 := o3 x; have a4 := o4 x
        have a5 := o5 x; have a6 := o6 x; have a7 := o7 x
        have b1 := o1 $r; have b2 := o2 $r; have b3 := o3 $r; have b4 := o4 $r
        have b5 := o5 $r; have b6 := o6 $r; have b7 := o7 $r
        have jq := hJ.queued x; have jf := hJ.fresh x; have ja := hJ.inAdmit x
        have jc := hJ.acc x; have jr := hJ.reqsAcc x
        have kq := hJ.queued $r; have kf := hJ.fresh $r; have ka := hJ.inAdmit $r
        have kc := hJ.acc $r; have kr := hJ.reqsAcc $r
        clear o1 o2 o3 o4 o5 o6 o7
        by_cases hx : x = $r
        · subst hx
          simp only [$hq:ident, ua, List.filterMap_cons, toW_req, toW_cancel, toW_resp, toW_timeout, toW_chunk, toW_exit, cntReq_req, cntReq_cancel, cntReq_resp, cntReq_chunk, proj, upd_same, admitting, abortPQ_nil, ua_abortPQ, cntP_abortPQ, mem_abortPQ_req, mem_abortPQ_cancel, ua_append, cntP_append, cntP_nil,
            cntP_req, cntP_cancel, replyExpired, resolve, Bool.toNat, if_true, List.mem_append,
            List.mem_singleton, List.mem_cons, FMsg.req.injEq, FMsg.resp.injEq, FMsg.cancel.injEq,
            PMsg.req.injEq, PMsg.cancel.injEq, reduceCtorEq, List.not_mem_nil, req_mem_of_cnt, List.filterMap_append, cntReq_append] at *
          grind [ua_mem, cntP_pos]
        · have hx' : ¬ $r = x := fun h => hx h.symm
          simp only [$hq:ident, ua, List.filterMap_cons, toW_req, toW_cancel, toW_resp, toW_timeout, toW_chunk, toW_exit, cntReq_req, cntReq_cancel, cntReq_resp, cntReq_chunk, proj, upd_other _ _ _ _ hx, if_neg hx, if_neg hx', decide_eq_false hx, decide_eq_false hx', admitting, abortPQ_nil, ua_abortPQ, cntP_abortPQ, mem_abortPQ_req, mem_abortPQ_cancel, ua_append,
            cntP_append, cntP_nil, cntP_req, cntP_cancel, replyExpired, resolve, Bool.toNat,
            if_false, List.mem_append, List.mem_singleton, List.mem_cons, FMsg.req.injEq,
            FMsg.resp.injEq, FMsg.cancel.injEq, PMsg.req.injEq, PMsg.cancel.injEq, reduceCtorEq,
            List.not_mem_nil, req_mem_of_cnt, List.filterMap_append, cntReq_append] at *
          grind [ua_mem, cntP_pos]))

theorem oinv_crash (f : FSt R) : OInv (fcrash f) := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_⟩ <;> intro x <;> simp [fcrash]

set_option maxHeartbeats 8000000 in
theorem oinv_step {P : Params} {f g : FSt R} (hJ : Inv P (proj f)) (hF : FInv f)
    (hO : OInv f) (h : FStep P f g) : OInv g := by
  cases h with
  | worker hw =>
    cases hw with
    | recvReqExpired r rest _ _ hq => orphq r hq
    | recvReqSend r rest _ _ hq => orphq r hq
    | recvReqCrash => exact oinv_crash f
    | checkRefuse r => orph r
    | checkPass r => orph r
    | admitReply r => orph r
    | recvCancel r rest _ _ hq => split <;> orphq r hq
    | recvResp r rest _ _ hq => split <;> orphq r hq
    | recvTimeout r rest _ _ hq => split <;> orphq r hq
    | recvChunk r rest _ _ hq => orphq r hq
    | recvExit => exact oinv_crash f
  | sendLive r => orph r
  | sendDead r => orph r
  | expire r => orph r
  | callerTimeout r => orph r
  | sendCancel r => split <;> orph r
  | portRecvReq r rest _ hq => orphq r hq
  | portRecvCancel r rest _ hq => orphq r hq
  | portComplete r => orph r
  | portEmitChunk r => orph r
  | portDies =>
    obtain ⟨o1, o2, o3, o4, o5, o6, o7⟩ := hO
    refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_⟩ <;> intro x
    all_goals have := o3 x; have := o5 x; have := o6 x
    all_goals simp_all
  | timerFire r => orph r
  | restart =>
    obtain ⟨o1, o2, o3, o4, o5, o6, o7⟩ := hO
    refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_⟩ <;> intro x <;> simp

theorem oinv_reach {P : Params} (hP : Safe P) {f : FSt R} (h : FReach P f) : OInv f := by
  induction h with
  | init => exact oinv_init
  | step hf hs ih => exact oinv_step (inv_reach hP (freach_reach hf)) (finv_reach hf) ih hs

/-- `NoOrphanTransfer`, for any number of requests, port deaths and
restarts. -/
theorem no_orphan_transfer_proof (P : Params) (hP : Safe P) (f : FSt R) (h : FReach P f)
    (r : R) (hc : f.conns r = true) :
    f.c.reqs r = true ∨ admitting f.c r ∨ PMsg.cancel r ∈ f.pQ :=
  (oinv_reach hP h).owned r hc

end KatipoProofs.Admission.Full
