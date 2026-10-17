import KatipoProofs.Admission.Orphan

/-!
# `EventualOutcome`: every request is answered or cancelled

For the exact model (`Full.lean`), every behaviour that is fair to the
worker (`WF_vars(WorkerDispatch)`) and to each request timer
(`WF_vars(TimerFire(r))`) gives every sent request a terminal outcome,
unless its caller cancelled it. The TLA+ spec also assumes fairness for the
port and the supervisor; this proof needs neither. A stalled C port is
covered by the request timer, and a dead worker has already resolved
everything it held.

A behaviour is `σ : ℕ → FSt R` starting at `finit` whose every step is an
`FStep` or a stutter. Fairness is stated with explicit enabling conditions,
and `wenabled_step` / `tenabled_step` show each implies TLA's `ENABLED` (a
real, state-changing step exists). So these hypotheses are no stronger than
the spec's `WF_vars`.

The argument follows one request `r` through four stages, each ending
because a fair action keeps a measure falling:
1. its admission call is queued: the worker drains the mailbox ahead of it;
2. the worker is admitting it: `admit_call`'s two remaining steps;
3. it is in `Reqs` with its timer armed: timer fairness fires it;
4. its timeout is queued: the worker drains the mailbox ahead of it, and
   delivers.

Leaving any stage unresolved only ever lands in a later one.
-/

namespace KatipoProofs.Admission.Full
open KatipoProofs.Admission

variable {R : Type} [DecidableEq R]
set_option linter.unusedSectionVars false

/-! ## The fair actions -/

/-- `TimerFire(r)`. -/
inductive TStep (r : R) : FSt R → FSt R → Prop
  | fire (f : FSt R) : f.c.wAlive = true → f.c.reqs r = true → f.fired r = false →
      TStep r f { f with fired := upd f.fired r true, fq := f.fq ++ [.timeout r] }

def WEnabled (f : FSt R) : Prop := f.c.wAlive = true ∧ (f.c.phase ≠ .idle ∨ f.fq ≠ [])

def TEnabled (r : R) (f : FSt R) : Prop :=
  f.c.wAlive = true ∧ f.c.reqs r = true ∧ f.fired r = false

theorem wenabled_phase (P : Params) (f : FSt R) (hw : f.c.wAlive = true)
    (hph : f.c.phase ≠ .idle) : ∃ g, WStep P f g ∧ g ≠ f := by
  match hp : f.c.phase with
  | .idle => exact absurd hp hph
  | .sent r =>
    by_cases hd : (P.deadline && f.c.expired r) = true
    · exact ⟨_, .checkRefuse f r hw hp hd, fun e => by
        have := congrArg (fun g => g.c.phase) e; simp [hp] at this⟩
    · exact ⟨_, .checkPass f r hw hp (by simpa using hd), fun e => by
        have := congrArg (fun g => g.c.phase) e; simp [hp] at this⟩
  | .checked r =>
    exact ⟨_, .admitReply f r hw hp, fun e => by
      have := congrArg (fun g => g.c.phase) e; simp [hp] at this⟩

/-- `WEnabled` implies `ENABLED <<WorkerDispatch>>_vars`. -/
theorem wenabled_step (P : Params) (f : FSt R) (h : WEnabled f) :
    ∃ g, WStep P f g ∧ g ≠ f := by
  obtain ⟨hw, hph | hq⟩ := h
  · exact wenabled_phase P f hw hph
  · by_cases hph : f.c.phase = .idle
    · match hfq : f.fq, hq with
      | m :: rest, _ =>
        have len : ∀ g : FSt R, g.fq = rest → g ≠ f := fun g hg e => by
          have := congrArg (fun g => g.fq.length) e; simp [hg, hfq] at this
        have crash_ne : fcrash f ≠ f := fun e => by
          have := congrArg (fun g => g.fq.length) e; simp [fcrash, hfq] at this
        cases m with
        | req r =>
          by_cases hd : (P.deadline && f.c.expired r) = true
          · exact ⟨_, .recvReqExpired f r rest hw hph hfq hd, len _ rfl⟩
          · by_cases hp : f.pAlive = true
            · exact ⟨_, .recvReqSend f r rest hw hph hfq (by simpa using hd) hp, len _ rfl⟩
            · exact ⟨_, .recvReqCrash f r rest hw hph hfq (by simpa using hd) (by simpa using hp),
                crash_ne⟩
        | cancel r =>
          refine ⟨_, .recvCancel f r rest hw hph hfq, ?_⟩
          split <;> exact len _ rfl
        | resp r =>
          refine ⟨_, .recvResp f r rest hw hph hfq, ?_⟩
          split <;> exact len _ rfl
        | timeout r =>
          refine ⟨_, .recvTimeout f r rest hw hph hfq, ?_⟩
          split <;> exact len _ rfl
        | chunk r => exact ⟨_, .recvChunk f r rest hw hph hfq, len _ rfl⟩
        | exit => exact ⟨_, .recvExit f rest hw hph hfq, crash_ne⟩
    · exact wenabled_phase P f hw hph

/-- `TEnabled r` implies `ENABLED <<TimerFire(r)>>_vars`. -/
theorem tenabled_step (r : R) (f : FSt R) (h : TEnabled r f) : ∃ g, TStep r f g ∧ g ≠ f :=
  ⟨_, .fire f h.1 h.2.1 h.2.2, fun e => by
    have := congrArg (fun g => g.fired r) e; simp [h.2.2] at this⟩

/-! ## Behaviours and fairness -/

def Behaviour (P : Params) (σ : Nat → FSt R) : Prop :=
  σ 0 = finit ∧ ∀ i, FStep P (σ i) (σ (i + 1)) ∨ σ (i + 1) = σ i

/-- `WF`: an action enabled at every step from some point on is eventually
taken. -/
def Fair (σ : Nat → FSt R) (En : FSt R → Prop) (A : FSt R → FSt R → Prop) : Prop :=
  ∀ i, (∀ j, i ≤ j → En (σ j)) → ∃ j, i ≤ j ∧ A (σ j) (σ (j + 1))

def resolved (f : FSt R) (r : R) : Prop := 0 < f.c.delivered r ∨ f.c.cancelled r = true

/-! ## What liveness needs to know about reachable states -/

/-- `KatipoFixed.tla`'s `delivered[r] > 0 \/ r \in cancelled`. -/
theorem count_req_eq (r : R) : ∀ l : List (FMsg R),
    l.count (.req r) = cntReq r (l.filterMap FMsg.toW)
  | [] => rfl
  | m :: l => by
    have ih := count_req_eq r l
    cases m <;> simp [List.count_cons, ih] <;> grind

structure LInv (f : FSt R) : Prop where
  /-- where an unresolved request can be -/
  stage : ∀ r, f.c.sent r = true →
    resolved f r ∨ FMsg.req r ∈ f.fq ∨ admitting f.c r ∨ f.c.reqs r = true
  /-- before admission the caller is waiting, or already has its outcome -/
  waiting : ∀ r, (FMsg.req r ∈ f.fq ∨ admitting f.c r) →
    f.c.pending r = true ∨ 0 < f.c.delivered r
  /-- a queued cancel was issued by the caller -/
  cancelIssued : ∀ r, FMsg.cancel r ∈ f.fq → f.c.cancelled r = true
  /-- a fired timer's message is still queued while the request is held -/
  timeoutQueued : ∀ r, f.c.reqs r = true → f.fired r = true → FMsg.timeout r ∈ f.fq
  /-- at most one timeout, and only once fired -/
  timeoutOnce : ∀ r, f.fq.count (.timeout r) ≤ (f.fired r).toNat
  /-- timers belong to admitted requests -/
  firedAdmitted : ∀ r, f.fired r = true →
    f.c.sent r = true ∧ FMsg.req r ∉ f.fq ∧ ¬ admitting f.c r
  /-- an accepted request leaves `Reqs` only by being resolved -/
  acceptedHeld : ∀ r, f.c.accepted r = true → resolved f r ∨ f.c.reqs r = true

theorem linv_init : LInv (finit : FSt R) := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_⟩ <;> intro r <;> simp [finit, init, admitting, resolved]

/-- Prove every `LInv` field after a step touching request `r`
(`liveq r hq`: whose guard `hq` pins the mailbox head). -/
syntax "live" ident : tactic
syntax "liveq" ident ident : tactic
set_option hygiene false in
macro_rules
  | `(tactic| live $r) => `(tactic| (
      obtain ⟨l1, l2, l3, l4, l5, l6, l7⟩ := hL
      have hd := hF.dead
      refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
      all_goals
        intro x
        have a1 := l1 x; have a2 := l2 x; have a3 := l3 x; have a4 := l4 x
        have a5 := l5 x; have a6 := l6 x; have a7 := l7 x
        have b1 := l1 $r; have b2 := l2 $r; have b3 := l3 $r; have b4 := l4 $r
        have b5 := l5 $r; have b6 := l6 $r; have b7 := l7 $r
        have jq := hJ.queued x; have jf := hJ.fresh x; have ja := hJ.inAdmit x
        have jc := hJ.acc x; have jr := hJ.reqsAcc x; have jp := hJ.checkedPending x
        have kq := hJ.queued $r; have kf := hJ.fresh $r; have ka := hJ.inAdmit $r
        have kc := hJ.acc $r; have kr := hJ.reqsAcc $r; have kp := hJ.checkedPending $r
        clear l1 l2 l3 l4 l5 l6 l7
        by_cases hx : x = $r
        · subst hx
          simp only [upd_same, if_true, admitting, resolved, abortPQ_nil, ua_abortPQ, cntP_abortPQ, mem_abortPQ_req,
            mem_abortPQ_cancel, replyExpired, resolve, Bool.toNat, List.mem_append,
            List.mem_singleton, List.mem_cons, FMsg.req.injEq, FMsg.resp.injEq, FMsg.cancel.injEq,
            FMsg.timeout.injEq, reduceCtorEq, List.not_mem_nil, req_mem_of_cnt,
            List.filterMap_append, cntReq_append, List.count_append, List.count_cons, List.count_nil,
            beq_iff_eq, List.filterMap_cons, toW_req, toW_cancel, toW_resp, toW_timeout, toW_chunk,
            toW_exit, cntReq_req, cntReq_cancel, cntReq_resp, cntReq_chunk, cntReq_nil, proj] at *
          grind
        · have hx' : ¬ $r = x := fun h => hx h.symm
          simp only [upd_other _ _ _ _ hx, if_neg hx, if_neg hx', decide_eq_false hx,
            decide_eq_false hx', admitting, resolved, abortPQ_nil, ua_abortPQ, cntP_abortPQ, mem_abortPQ_req,
            mem_abortPQ_cancel, replyExpired, resolve, Bool.toNat, List.mem_append,
            List.mem_singleton, List.mem_cons, FMsg.req.injEq, FMsg.resp.injEq, FMsg.cancel.injEq,
            FMsg.timeout.injEq, reduceCtorEq, List.not_mem_nil, req_mem_of_cnt,
            List.filterMap_append, cntReq_append, List.count_append, List.count_cons, List.count_nil,
            beq_iff_eq, List.filterMap_cons, toW_req, toW_cancel, toW_resp, toW_timeout, toW_chunk,
            toW_exit, cntReq_req, cntReq_cancel, cntReq_resp, cntReq_chunk, cntReq_nil, proj] at *
          grind))
set_option hygiene false in
macro_rules
  | `(tactic| liveq $r $hq) => `(tactic| (
      obtain ⟨l1, l2, l3, l4, l5, l6, l7⟩ := hL
      have hd := hF.dead
      refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
      all_goals
        intro x
        have a1 := l1 x; have a2 := l2 x; have a3 := l3 x; have a4 := l4 x
        have a5 := l5 x; have a6 := l6 x; have a7 := l7 x
        have b1 := l1 $r; have b2 := l2 $r; have b3 := l3 $r; have b4 := l4 $r
        have b5 := l5 $r; have b6 := l6 $r; have b7 := l7 $r
        have jq := hJ.queued x; have jf := hJ.fresh x; have ja := hJ.inAdmit x
        have jc := hJ.acc x; have jr := hJ.reqsAcc x; have jp := hJ.checkedPending x
        have kq := hJ.queued $r; have kf := hJ.fresh $r; have ka := hJ.inAdmit $r
        have kc := hJ.acc $r; have kr := hJ.reqsAcc $r; have kp := hJ.checkedPending $r
        clear l1 l2 l3 l4 l5 l6 l7
        by_cases hx : x = $r
        · subst hx
          simp only [$hq:ident, upd_same, if_true, admitting, resolved, abortPQ_nil, ua_abortPQ, cntP_abortPQ, mem_abortPQ_req,
            mem_abortPQ_cancel, replyExpired, resolve, Bool.toNat, List.mem_append,
            List.mem_singleton, List.mem_cons, FMsg.req.injEq, FMsg.resp.injEq, FMsg.cancel.injEq,
            FMsg.timeout.injEq, reduceCtorEq, List.not_mem_nil, req_mem_of_cnt,
            List.filterMap_append, cntReq_append, List.count_append, List.count_cons, List.count_nil,
            beq_iff_eq, List.filterMap_cons, toW_req, toW_cancel, toW_resp, toW_timeout, toW_chunk,
            toW_exit, cntReq_req, cntReq_cancel, cntReq_resp, cntReq_chunk, cntReq_nil, proj] at *
          grind
        · have hx' : ¬ $r = x := fun h => hx h.symm
          simp only [$hq:ident, upd_other _ _ _ _ hx, if_neg hx, if_neg hx', decide_eq_false hx,
            decide_eq_false hx', admitting, resolved, abortPQ_nil, ua_abortPQ, cntP_abortPQ, mem_abortPQ_req,
            mem_abortPQ_cancel, replyExpired, resolve, Bool.toNat, List.mem_append,
            List.mem_singleton, List.mem_cons, FMsg.req.injEq, FMsg.resp.injEq, FMsg.cancel.injEq,
            FMsg.timeout.injEq, reduceCtorEq, List.not_mem_nil, req_mem_of_cnt,
            List.filterMap_append, cntReq_append, List.count_append, List.count_cons, List.count_nil,
            beq_iff_eq, List.filterMap_cons, toW_req, toW_cancel, toW_resp, toW_timeout, toW_chunk,
            toW_exit, cntReq_req, cntReq_cancel, cntReq_resp, cntReq_chunk, cntReq_nil, proj] at *
          grind))



theorem linv_crash {P : Params} {f : FSt R} (hJ : Inv P (proj f)) (hL : LInv f) :
    LInv (fcrash f) := by
  obtain ⟨l1, l2, l3, l4, l5, l6, l7⟩ := hL
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_⟩ <;> intro x
  all_goals
    have a1 := l1 x; have a2 := l2 x; have a6 := l6 x; have a7 := l7 x
    have jr := hJ.reqsAcc x; have jc := hJ.acc x
    simp only [fcrash, crash, resolved, admitting, Bool.toNat, List.not_mem_nil,
      List.count_nil, req_mem_of_cnt, proj] at *
    grind

set_option maxHeartbeats 8000000 in
theorem linv_step {P : Params} {f g : FSt R} (hJ : Inv P (proj f)) (hF : FInv f)
    (hL : LInv f) (h : FStep P f g) : LInv g := by
  cases h with
  | worker hw =>
    cases hw with
    | recvReqExpired r rest _ _ hq => liveq r hq
    | recvReqSend r rest _ _ hq => liveq r hq
    | recvReqCrash => exact linv_crash hJ hL
    | checkRefuse r => live r
    | checkPass r => live r
    | admitReply r => live r
    | recvCancel r rest _ _ hq => split <;> liveq r hq
    | recvResp r rest _ _ hq => split <;> liveq r hq
    | recvTimeout r rest _ _ hq => split <;> liveq r hq
    | recvChunk r rest _ _ hq => liveq r hq
    | recvExit => exact linv_crash hJ hL
  | sendLive r => live r
  | sendDead r => live r
  | expire r => live r
  | callerTimeout r => live r
  | sendCancel r => split <;> live r
  | portRecvReq r => live r
  | portRecvCancel r => live r
  | portComplete r => live r
  | portEmitChunk r => live r
  | portDies =>
    obtain ⟨l1, l2, l3, l4, l5, l6, l7⟩ := hL
    refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_⟩ <;> intro x
    all_goals
      have a1 := l1 x; have a2 := l2 x; have a3 := l3 x; have a4 := l4 x
      have a5 := l5 x; have a6 := l6 x; have a7 := l7 x
      simp only [resolved, admitting, List.mem_append, List.mem_singleton, reduceCtorEq,
        List.count_append, List.count_cons, List.count_nil, beq_iff_eq, or_false] at *
      grind
  | timerFire r => live r
  | restart hw =>
    obtain ⟨l1, l2, l3, l4, l5, l6, l7⟩ := hL
    have hd := hF.dead hw
    refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_⟩ <;> intro x
    all_goals
      have a1 := l1 x; have a2 := l2 x; have a5 := l5 x; have a6 := l6 x; have a7 := l7 x
      simp only [resolved, admitting, List.not_mem_nil, List.count_nil, hd.1, hd.2.1,
        hd.2.2 x] at *
      grind

theorem linv_reach {P : Params} (hP : Safe P) {f : FSt R} (h : FReach P f) : LInv f := by
  induction h with
  | init => exact linv_init
  | step hf hs ih => exact linv_step (inv_reach hP (freach_reach hf)) (finv_reach hf) ih hs

/-! ## Monotone facts along a step -/

theorem le_upd_add (d : R → Nat) (x r : R) (k : Nat) : d r ≤ upd d x (d x + k) r := by
  unfold upd; split <;> subst_vars <;> omega

theorem delivered_mono {P : Params} {f g : FSt R} (h : FStep P f g) (r : R) :
    f.c.delivered r ≤ g.c.delivered r := by
  cases h with
  | worker hw =>
    cases hw <;> (try split) <;>
      simp only [resolve, replyExpired, fcrash, crash, Nat.le_refl, le_upd_add, Nat.le_add_right]
  | _ => simp only [resolve, Nat.le_refl, le_upd_add]

theorem bool_mono {P : Params} {f g : FSt R} (h : FStep P f g) (r : R) :
    (f.c.cancelled r = true → g.c.cancelled r = true) ∧
    (f.c.sent r = true → g.c.sent r = true) ∧
    (f.c.accepted r = true → g.c.accepted r = true) ∧
    (f.fired r = true → g.fired r = true) := by
  cases h with
  | worker hw =>
    cases hw <;> (try split) <;> refine ⟨?_, ?_, ?_, ?_⟩ <;> intro h1 <;>
      simp_all [upd, resolve, replyExpired, fcrash, crash] <;> grind
  | _ => (try split) <;> refine ⟨?_, ?_, ?_, ?_⟩ <;> intro h1 <;> simp_all [upd, resolve] <;> grind

theorem resolved_mono {P : Params} {f g : FSt R} (h : FStep P f g) (r : R)
    (hr : resolved f r) : resolved g r := by
  rcases hr with h1 | h1
  · exact Or.inl (Nat.lt_of_lt_of_le h1 (delivered_mono h r))
  · exact Or.inr ((bool_mono h r).1 h1)

theorem unqueued_stays {P : Params} {f g : FSt R} (h : FStep P f g) (r : R)
    (hs : f.c.sent r = true) (hq : FMsg.req r ∉ f.fq) : FMsg.req r ∉ g.fq := by
  cases h with
  | sendLive x hx =>
    simp only [List.mem_append, List.mem_singleton, FMsg.req.injEq, not_or]
    exact ⟨hq, fun e => by subst e; simp_all⟩
  | sendCancel => split <;> simp_all
  | worker hw =>
    cases hw with
    | recvReqCrash | recvExit => simp [fcrash]
    | recvCancel _ _ _ _ e | recvResp _ _ _ _ e | recvTimeout _ _ _ _ e => split <;> simp_all
    | _ => simp_all
  | _ => simp_all

/-! ## Measures -/

def rem : Phase R → Nat
  | .idle => 0
  | .sent _ => 2
  | .checked _ => 1

/-- Messages ahead of the first `m`. -/
def pos (m : FMsg R) : List (FMsg R) → Nat
  | [] => 0
  | x :: xs => if x = m then 0 else pos m xs + 1

theorem pos_append (m : FMsg R) : ∀ (l l' : List (FMsg R)), m ∈ l → pos m (l ++ l') = pos m l
  | [], _, h => by simp at h
  | x :: xs, l', h => by
    by_cases hx : x = m
    · simp [pos, hx]
    · have : m ∈ xs := by simp at h; rcases h with h | h; exact absurd h.symm hx; exact h
      simp [pos, hx, pos_append m xs l' this]

/-- Worker steps ahead of `m` reaching the head of the mailbox. -/
def mu (m : FMsg R) (f : FSt R) : Nat := 3 * pos m f.fq + rem f.c.phase

theorem pop_mu (m x : FMsg R) (rest : List (FMsg R)) (hm : m ∈ rest)
    (hu : (x :: rest).count m ≤ 1) : pos m (x :: rest) = pos m rest + 1 := by
  have hx : x ≠ m := by
    rintro rfl; have := List.count_pos_iff.mpr hm; simp at hu; omega
  simp [pos, hx]

theorem rem_le (p : Phase R) : rem p ≤ 2 := by cases p <;> simp [rem]

@[simp] theorem rem_idle : rem (.idle : Phase R) = 0 := rfl

theorem wstep_mu {P : Params} {f g : FSt R} (h : WStep P f g) (m : FMsg R) (hm : m ∈ g.fq)
    (hu : f.fq.count m ≤ 1) : mu m g < mu m f := by
  have pop : ∀ (x : FMsg R) (rest : List (FMsg R)) (p p' : Phase R), f.fq = x :: rest →
      p = .idle → m ∈ rest → 3 * pos m rest + rem p' < 3 * pos m f.fq + rem p := by
    intro x rest p p' hq hp hm'
    rw [hq, pop_mu m x rest hm' (hq ▸ hu), hp, rem_idle]; have := rem_le p'; omega
  cases h with
  | recvReqExpired x rest _ hi hq =>
    simp only at hm; exact pop _ rest _ _ hq hi hm
  | recvReqSend x rest _ hi hq =>
    simp only at hm; exact pop _ rest _ _ hq hi hm
  | recvReqCrash => simp [fcrash] at hm
  | recvExit => simp [fcrash] at hm
  | checkRefuse x _ hp => simp [mu, hp, rem]
  | checkPass x _ hp => simp [mu, hp, rem]
  | admitReply x _ hp => simp [mu, hp, rem]
  | recvCancel x rest _ hi hq =>
    unfold mu
    by_cases hr : f.c.reqs x = true <;> simp only [hr, if_true, if_false, Bool.false_eq_true,] at hm ⊢ <;>
      exact pop _ rest _ _ hq hi hm
  | recvResp x rest _ hi hq =>
    unfold mu
    by_cases hr : f.c.reqs x = true <;> simp only [hr, if_true, if_false, Bool.false_eq_true, resolve,] at hm ⊢ <;>
      exact pop _ rest _ _ hq hi hm
  | recvTimeout x rest _ hi hq =>
    unfold mu
    by_cases hr : f.c.reqs x = true <;> simp only [hr, if_true, if_false, Bool.false_eq_true, resolve,] at hm ⊢ <;>
      exact pop _ rest _ _ hq hi hm
  | recvChunk x rest _ hi hq =>
    simp only at hm; exact pop _ rest _ _ hq hi hm

theorem fstep_mu {P : Params} {f g : FSt R} (h : FStep P f g) (m : FMsg R) (hm : m ∈ g.fq)
    (hmf : m ∈ f.fq) (hu : f.fq.count m ≤ 1) : mu m g ≤ mu m f := by
  have app : ∀ l : List (FMsg R), 3 * pos m (f.fq ++ l) + rem f.c.phase ≤ mu m f := fun l => by
    rw [pos_append m _ _ hmf]; exact Nat.le_refl _
  cases h with
  | worker hw => exact Nat.le_of_lt (wstep_mu hw m hm hu)
  | sendLive => exact app _
  | sendCancel => unfold mu; split; exact app _; exact Nat.le_refl _
  | portComplete => exact app _
  | portEmitChunk => exact app _
  | portDies => exact app _
  | timerFire => exact app _
  | restart => simp at hm
  | sendDead => simp [mu, resolve]
  | expire => simp [mu]
  | callerTimeout => simp [mu, resolve]
  | portRecvReq => simp [mu]
  | portRecvCancel => simp [mu]

theorem wstep_rem {P : Params} {f g : FSt R} (h : WStep P f g) (r : R)
    (ha : admitting f.c r) (hb : admitting g.c r) : rem g.c.phase < rem f.c.phase := by
  unfold admitting at ha hb
  cases h <;> (try split at hb) <;> simp_all [rem]

theorem fstep_rem {P : Params} {f g : FSt R} (h : FStep P f g) (r : R)
    (ha : admitting f.c r) (hb : admitting g.c r) : rem g.c.phase ≤ rem f.c.phase := by
  unfold admitting at ha hb
  cases h with
  | worker hw => exact Nat.le_of_lt (wstep_rem hw r ha hb)
  | _ => simp_all [rem, resolve]

/-! ## The drain argument -/

/-- While `C` holds no step raises `μ`, and the fair action `A` is enabled
and lowers it; so `C` eventually fails. -/
theorem drain {σ : Nat → FSt R} {En : FSt R → Prop} {A : FSt R → FSt R → Prop}
    (hf : Fair σ En A) (C : FSt R → Prop) (μ : FSt R → Nat)
    (hmono : ∀ i, C (σ i) → C (σ (i + 1)) → μ (σ (i + 1)) ≤ μ (σ i))
    (hdec : ∀ i, C (σ i) → A (σ i) (σ (i + 1)) → C (σ (i + 1)) → μ (σ (i + 1)) < μ (σ i))
    (hen : ∀ i, C (σ i) → En (σ i)) (i : Nat) : ∃ j, i ≤ j ∧ ¬ C (σ j) := by
  suffices H : ∀ n i, μ (σ i) ≤ n → ∃ j, i ≤ j ∧ ¬ C (σ j) from H _ i (Nat.le_refl _)
  intro n
  induction n with
  | zero => ?_
  | succ n ih => ?_
  all_goals
    intro i hi
    refine Classical.byContradiction fun hall => ?_
    have hC : ∀ j, i ≤ j → C (σ j) := fun j hj =>
      Classical.byContradiction fun h => hall ⟨j, hj, h⟩
    have hle : ∀ k, μ (σ (i + k)) ≤ μ (σ i) := by
      intro k; induction k with
      | zero => exact Nat.le_refl _
      | succ k ihk =>
        exact Nat.le_trans (hmono (i + k) (hC (i + k) (Nat.le_add_right _ _))
          (hC (i + k + 1) (by omega))) ihk
    obtain ⟨j, hij, hA⟩ := hf i (fun j hj => hen j (hC j hj))
    have h1 := hdec j (hC j hij) hA (hC (j + 1) (by omega))
    have h2 := hle (j - i); rw [Nat.add_sub_cancel' hij] at h2
  · omega
  · obtain ⟨k, hk, hk'⟩ := ih (j + 1) (by omega)
    exact hk' (hC k (by omega))

/-! ## The four stages -/

theorem alive_of_reqs {f : FSt R} (hF : FInv f) {r : R} (h : f.c.reqs r = true) :
    f.c.wAlive = true := by
  cases hw : f.c.wAlive
  · simp [(hF.dead hw).2.2 r] at h
  · rfl

theorem alive_of_fq {f : FSt R} (hF : FInv f) (h : f.fq ≠ []) : f.c.wAlive = true := by
  cases hw : f.c.wAlive
  · exact absurd (hF.dead hw).1 h
  · rfl

theorem alive_of_admitting {f : FSt R} (hF : FInv f) {r : R} (h : admitting f.c r) :
    f.c.wAlive = true := by
  cases hw : f.c.wAlive
  · have := (hF.dead hw).2.1; unfold admitting at h; simp_all
  · rfl

theorem TStep.fired_true {r : R} {f g : FSt R} (h : TStep r f g) : g.fired r = true := by
  cases h; simp


section Stages
variable {P : Params} {σ : Nat → FSt R} (hP : Safe P) (hb : Behaviour P σ)
  (hw : Fair σ WEnabled (WStep P)) (ht : ∀ r, Fair σ (TEnabled r) (TStep r))
include hP hb

theorem behaviour_reach : ∀ i, FReach P (σ i)
  | 0 => hb.1 ▸ FReach.init
  | i + 1 => by
    rcases hb.2 i with h | h
    · exact .step (behaviour_reach i) h
    · exact h ▸ behaviour_reach i

/-- A fact preserved by every step persists along the behaviour. -/
theorem persists (Q : FSt R → Prop) (hQ : ∀ f g, FReach P f → FStep P f g → Q f → Q g)
    (i : Nat) (hi : Q (σ i)) : ∀ j, i ≤ j → Q (σ j) := by
  intro j hj
  obtain ⟨k, rfl⟩ : ∃ k, j = i + k := ⟨j - i, by omega⟩
  clear hj
  induction k with
  | zero => exact hi
  | succ k ih =>
    rcases hb.2 (i + k) with h | h
    · exact hQ _ _ (behaviour_reach hP hb _) h ih
    · rw [← Nat.add_assoc, h]; exact ih

theorem step_le (μ : FSt R → Nat) (i : Nat)
    (h : FStep P (σ i) (σ (i + 1)) → μ (σ (i + 1)) ≤ μ (σ i)) : μ (σ (i + 1)) ≤ μ (σ i) := by
  rcases hb.2 i with hs | hs
  · exact h hs
  · rw [hs]; exact Nat.le_refl _

theorem facts (i : Nat) : Inv P (proj (σ i)) ∧ FInv (σ i) ∧ LInv (σ i) :=
  have h := behaviour_reach hP hb i
  ⟨inv_reach hP (freach_reach h), finv_reach h, linv_reach hP h⟩

include hw in
theorem stage4 (r : R) (i : Nat) (hr : (σ i).c.reqs r = true) (hf : (σ i).fired r = true) :
    ∃ j, i ≤ j ∧ resolved (σ j) r := by
  let C : FSt R → Prop := fun f => ¬ resolved f r ∧ f.c.reqs r = true ∧ f.fired r = true
  obtain ⟨j, hij, hj⟩ := drain hw C (mu (.timeout r))
    (fun k hk hk' => step_le hP hb _ k fun hs => by
      obtain ⟨-, -, hL⟩ := facts hP hb k
      obtain ⟨-, -, hL'⟩ := facts hP hb (k + 1)
      have := hL.timeoutOnce r; simp [hk.2.2, Bool.toNat] at this
      exact fstep_mu hs _ (hL'.timeoutQueued r hk'.2.1 hk'.2.2) (hL.timeoutQueued r hk.2.1 hk.2.2)
        this)
    (fun k hk hA hk' => by
      obtain ⟨-, -, hL⟩ := facts hP hb k
      have := hL.timeoutOnce r; simp [hk.2.2, Bool.toNat] at this
      exact wstep_mu hA _ (by
        obtain ⟨-, -, hL'⟩ := facts hP hb (k + 1)
        exact hL'.timeoutQueued r hk'.2.1 hk'.2.2) this)
    (fun k hk => by
      obtain ⟨-, hF, hL⟩ := facts hP hb k
      refine ⟨alive_of_reqs hF hk.2.1, Or.inr ?_⟩
      have := hL.timeoutQueued r hk.2.1 hk.2.2
      intro e; rw [e] at this; simp at this) i
  refine ⟨j, hij, ?_⟩
  have hacc := persists hP hb (fun f => f.c.accepted r = true)
    (fun _ _ _ h => (bool_mono h r).2.2.1) i ((facts hP hb i).1.reqsAcc r hr) j hij
  have hfj := persists hP hb (fun f => f.fired r = true)
    (fun _ _ _ h => (bool_mono h r).2.2.2) i hf j hij
  rcases (facts hP hb j).2.2.acceptedHeld r hacc with h | h
  · exact h
  · exact Classical.byContradiction fun hn => hj ⟨hn, h, hfj⟩

include hw ht in
/-- Held in `Reqs`: from timer still armed or already fired. -/
theorem stage34 (r : R) (i : Nat) (hr : (σ i).c.reqs r = true) :
    ∃ j, i ≤ j ∧ resolved (σ j) r := by
  cases hf : (σ i).fired r
  case true => exact stage4 hP hb hw r i hr hf
  let C : FSt R → Prop := fun f => ¬ resolved f r ∧ f.c.reqs r = true ∧ f.fired r = false
  obtain ⟨j, hij, hj⟩ := drain (ht r) C (fun _ => 0)
    (fun _ _ _ => Nat.le_refl _)
    (fun k _ hA hk' => absurd hA.fired_true (by simp [hk'.2.2]))
    (fun k hk => ⟨alive_of_reqs (facts hP hb k).2.1 hk.2.1, hk.2.1, hk.2.2⟩) i
  have hacc := persists hP hb (fun f => f.c.accepted r = true)
    (fun _ _ _ h => (bool_mono h r).2.2.1) i ((facts hP hb i).1.reqsAcc r hr) j hij
  rcases (facts hP hb j).2.2.acceptedHeld r hacc with h | h
  · exact ⟨j, hij, h⟩
  · by_cases hres : resolved (σ j) r
    · exact ⟨j, hij, hres⟩
    · have hfj : (σ j).fired r = true := by
        cases e : (σ j).fired r
        · exact absurd ⟨hres, h, e⟩ hj
        · rfl
      obtain ⟨k, hjk, hk⟩ := stage4 hP hb hw r j h hfj
      exact ⟨k, by omega, hk⟩

include hw ht in
/-- Being admitted. -/
theorem stage2 (r : R) (i : Nat) (ha : admitting (σ i).c r) :
    ∃ j, i ≤ j ∧ resolved (σ j) r := by
  let C : FSt R → Prop := fun f => ¬ resolved f r ∧ admitting f.c r
  obtain ⟨j, hij, hj⟩ := drain hw C (fun f => rem f.c.phase)
    (fun k hk hk' => step_le hP hb (fun f => rem f.c.phase) k fun hs => fstep_rem hs r hk.2 hk'.2)
    (fun k hk hA hk' => wstep_rem hA r hk.2 hk'.2)
    (fun k hk => ⟨alive_of_admitting (facts hP hb k).2.1 hk.2, Or.inl fun e => by
      have := hk.2; unfold admitting at this; simp_all⟩) i
  obtain ⟨hJ, -, -⟩ := facts hP hb i
  have hsent : (σ i).c.sent r = true := by
    cases e : (σ i).c.sent r
    · exact absurd ha ((hJ.fresh r e).2.2.2.2.2.1)
    · rfl
  have hunq : FMsg.req r ∉ (σ i).fq := fun hm => by
    have := (hJ.queued r ((req_mem_of_cnt r _).mp hm)).2.2.1; exact this ha
  have hsj := persists hP hb (fun f => f.c.sent r = true)
    (fun _ _ _ h => (bool_mono h r).2.1) i hsent j hij
  have hunqj := persists hP hb (fun f => f.c.sent r = true ∧ FMsg.req r ∉ f.fq)
    (fun _ _ _ h hq => ⟨(bool_mono h r).2.1 hq.1, unqueued_stays h r hq.1 hq.2⟩) i
    ⟨hsent, hunq⟩ j hij
  by_cases hres : resolved (σ j) r
  · exact ⟨j, hij, hres⟩
  · rcases (facts hP hb j).2.2.stage r hsj with h | h | h | h
    · exact absurd h hres
    · exact absurd h hunqj.2
    · exact absurd ⟨hres, h⟩ hj
    · obtain ⟨k, hjk, hk⟩ := stage34 hP hb hw ht r j h
      exact ⟨k, by omega, hk⟩

include hw ht in
/-- Queued in the mailbox. -/
theorem stage1 (r : R) (i : Nat) (hq : FMsg.req r ∈ (σ i).fq) :
    ∃ j, i ≤ j ∧ resolved (σ j) r := by
  let C : FSt R → Prop := fun f => ¬ resolved f r ∧ FMsg.req r ∈ f.fq
  have once : ∀ k, FMsg.req r ∈ (σ k).fq → (σ k).fq.count (.req r) ≤ 1 := fun k hk => by
    obtain ⟨hJ, -, -⟩ := facts hP hb k
    have := (hJ.queued r ((req_mem_of_cnt r _).mp hk)).1
    rw [count_req_eq]; simp only [proj] at this; omega
  obtain ⟨j, hij, hj⟩ := drain hw C (mu (.req r))
    (fun k hk hk' => step_le hP hb _ k fun hs => fstep_mu hs _ hk'.2 hk.2 (once k hk.2))
    (fun k hk hA hk' => wstep_mu hA _ hk'.2 (once k hk.2))
    (fun k hk => by
      have hne : (σ k).fq ≠ [] := fun e => by have := hk.2; rw [e] at this; simp at this
      exact ⟨alive_of_fq (facts hP hb k).2.1 hne, Or.inr hne⟩) i
  have hsent : (σ i).c.sent r = true := by
    obtain ⟨hJ, -, -⟩ := facts hP hb i
    cases e : (σ i).c.sent r
    · have := (hJ.fresh r e).2.2.2.2.1; simp only [proj] at this
      have := (req_mem_of_cnt r _).mp hq; omega
    · rfl
  have hsj := persists hP hb (fun f => f.c.sent r = true)
    (fun _ _ _ h => (bool_mono h r).2.1) i hsent j hij
  by_cases hres : resolved (σ j) r
  · exact ⟨j, hij, hres⟩
  · rcases (facts hP hb j).2.2.stage r hsj with h | h | h | h
    · exact absurd h hres
    · exact absurd ⟨hres, h⟩ hj
    · obtain ⟨k, hjk, hk⟩ := stage2 hP hb hw ht r j h
      exact ⟨k, by omega, hk⟩
    · obtain ⟨k, hjk, hk⟩ := stage34 hP hb hw ht r j h
      exact ⟨k, by omega, hk⟩

include hw ht in
theorem eventual_outcome_proof (r : R) (i : Nat) (hs : (σ i).c.sent r = true) :
    ∃ j, i ≤ j ∧ (0 < (σ j).c.delivered r ∨ (σ j).c.cancelled r = true) := by
  rcases (facts hP hb i).2.2.stage r hs with h | h | h | h
  · exact ⟨i, Nat.le_refl _, h⟩
  · exact stage1 hP hb hw ht r i h
  · exact stage2 hP hb hw ht r i h
  · exact stage34 hP hb hw ht r i h

end Stages

/-! ## Timer fairness is necessary -/

/-- `PortDispatch`. -/
inductive PStep : FSt R → FSt R → Prop
  | recvReq (f : FSt R) (r : R) (rest : List (PMsg R)) : f.pAlive = true →
      f.pQ = .req r :: rest → PStep f { f with pQ := rest, conns := upd f.conns r true }
  | recvCancel (f : FSt R) (r : R) (rest : List (PMsg R)) : f.pAlive = true →
      f.pQ = .cancel r :: rest → PStep f { f with pQ := rest, conns := upd f.conns r false }

def PEnabled (f : FSt R) : Prop := f.pAlive = true ∧ f.pQ ≠ []

/-- The shipped protocol, one request: admitted, handed to the port, and
then the port never completes it. Every step after the fifth is a stutter
with the worker idle and the pipe empty. -/
def stall : Nat → FSt Unit
  | 0 => finit
  | 1 => { finit with c := { init with sent := upd (fun _ => false) () true,
                                       pending := upd (fun _ => false) () true },
                      fq := [.req ()] }
  | 2 => { finit with c := { init with sent := upd (fun _ => false) () true,
                                       pending := upd (fun _ => false) () true,
                                       phase := .sent () },
                      pQ := [.req ()] }
  | 3 => { finit with c := { init with sent := upd (fun _ => false) () true,
                                       pending := upd (fun _ => false) () true,
                                       phase := .checked () },
                      pQ := [.req ()] }
  | 4 => stall4
  | _ => { stall4 with pQ := [], conns := upd (fun _ => false) () true }
where stall4 : FSt Unit :=
  { finit with c := { init with sent := upd (fun _ => false) () true,
                                pending := upd (upd (fun _ => false) () true) () false,
                                reqs := upd (fun _ => false) () true,
                                accepted := upd (fun _ => false) () true },
               pQ := [.req ()] }

def pShip : Params := ⟨true, true, true⟩

theorem stall_late (n : Nat) (h : 5 ≤ n) : stall n = stall 5 := by
  match n, h with
  | k + 5, _ => rfl

theorem stall_behaviour : Behaviour pShip stall := by
  refine ⟨rfl, fun i => ?_⟩
  match i with
  | 0 => left; exact FStep.sendLive finit () rfl rfl
  | 1 => left; exact .worker (.recvReqSend _ () [] rfl rfl rfl rfl rfl)
  | 2 => left; exact .worker (.checkPass _ () rfl rfl rfl)
  | 3 =>
    left
    have := FStep.worker (WStep.admitReply (P := pShip) (stall 3) () rfl rfl)
    simpa [stall, stall.stall4, upd] using this
  | 4 => left; exact FStep.portRecvReq _ () [] rfl rfl
  | k + 5 => right; rfl

/-- Worker, port and supervisor fairness all hold, the request was
admitted, and it is never answered: `EventualOutcome` needs the request
timer. -/
theorem timer_fairness_needed_proof :
    ∃ (P : Params) (σ : Nat → FSt Unit), Safe P ∧ Behaviour P σ ∧
      Fair σ WEnabled (WStep P) ∧ Fair σ PEnabled PStep ∧
      Fair σ (fun f => f.c.wAlive = false) (FStep P) ∧
      (σ 4).c.reqs () = true ∧ ∀ j, ¬ resolved (σ j) () := by
  refine ⟨pShip, stall, Or.inr ⟨rfl, rfl⟩, stall_behaviour, ?_, ?_, ?_, rfl, ?_⟩
  · intro i hi
    have := hi (i + 5) (by omega)
    rw [stall_late _ (by omega)] at this
    simp [WEnabled, stall, stall.stall4, finit, init] at this
  · intro i hi
    have := hi (i + 5) (by omega)
    rw [stall_late _ (by omega)] at this
    simp [PEnabled, stall] at this
  · intro i hi
    have := hi i (Nat.le_refl _)
    match i with
    | 0 | 1 | 2 | 3 | 4 => simp [stall, stall.stall4, finit, init] at this
    | k + 5 => simp [stall, stall.stall4, finit, init] at this
  · intro j
    match j with
    | 0 | 1 | 2 | 3 | 4 => simp [resolved, stall, stall.stall4, finit, init]
    | k + 5 => simp [resolved, stall, stall.stall4, finit, init]

end KatipoProofs.Admission.Full
