import KatipoProofs.Admission.Model

/-!
# Admission and delivery: proofs

`Inv` is per-request (every field is `∀ r`); it is inductive under
`Safe P`. Each field says why the protocol cannot double-deliver.
-/

namespace KatipoProofs.Admission

variable {R : Type} [DecidableEq R]

/-- Queued admission calls for `r` in the worker's mailbox. -/
def cntReq (r : R) : List (WMsg R) → Nat
  | [] => 0
  | .req x :: l => (if x = r then 1 else 0) + cntReq r l
  | .cancel _ :: l => cntReq r l
  | .resp _ :: l => cntReq r l
  | .chunk _ :: l => cntReq r l

@[simp] theorem cntReq_nil (r : R) : cntReq r ([] : List (WMsg R)) = 0 := rfl
@[simp] theorem cntReq_req (r x : R) (l : List (WMsg R)) :
    cntReq r (.req x :: l) = (if x = r then 1 else 0) + cntReq r l := rfl
@[simp] theorem cntReq_cancel (r x : R) (l : List (WMsg R)) :
    cntReq r (.cancel x :: l) = cntReq r l := rfl
@[simp] theorem cntReq_resp (r x : R) (l : List (WMsg R)) :
    cntReq r (.resp x :: l) = cntReq r l := rfl
@[simp] theorem cntReq_chunk (r x : R) (l : List (WMsg R)) :
    cntReq r (.chunk x :: l) = cntReq r l := rfl
@[simp] theorem cntReq_append (r : R) (a b : List (WMsg R)) :
    cntReq r (a ++ b) = cntReq r a + cntReq r b := by
  induction a with
  | nil => simp
  | cons m ms ih => cases m <;> simp [ih] <;> omega

structure Inv (P : Params) (s : St R) : Prop where
  /-- one terminal outcome per request, counting the obligations still open:
  a waiting admission call and a `Reqs` entry -/
  once : ∀ r, s.delivered r + (s.pending r).toNat + (s.reqs r).toNat ≤ 1
  /-- a request not yet issued has left no trace -/
  fresh : ∀ r, s.sent r = false → s.delivered r = 0 ∧ s.pending r = false ∧
    s.reqs r = false ∧ s.accepted r = false ∧ cntReq r s.wQ = 0 ∧
    ¬ admitting s r ∧ s.effCancel r = false ∧ s.gaveUp r = false
  /-- a queued admission call is unique, not yet admitted, and either still
  awaited or past its deadline -/
  queued : ∀ r, 0 < cntReq r s.wQ → cntReq r s.wQ = 1 ∧
    (s.pending r = true ∨ s.expired r = true) ∧ ¬ admitting s r ∧
    s.accepted r = false ∧ s.reqs r = false ∧
    (P.callerTimeouts = false → s.pending r = true)
  /-- likewise for the call being admitted -/
  inAdmit : ∀ r, admitting s r → s.reqs r = false ∧ s.accepted r = false ∧
    (s.pending r = true ∨ s.expired r = true) ∧
    (P.callerTimeouts = false → s.pending r = true)
  /-- the reply step only ever answers a waiting caller (needs `Safe`) -/
  checkedPending : ∀ r, s.phase = .checked r → s.pending r = true
  gaveUpOnce : ∀ r, s.gaveUp r = true → 1 ≤ s.delivered r
  acc : ∀ r, s.accepted r = true → s.pending r = false ∧ cntReq r s.wQ = 0 ∧
    ¬ admitting s r
  reqsAcc : ∀ r, s.reqs r = true → s.accepted r = true
  eff : ∀ r, s.effCancel r = true → s.accepted r = true ∧ s.reqs r = false ∧
    s.delivered r = s.snap r
  /-- a cancel only takes effect on an unresolved request -/
  effZero : ∀ r, s.effCancel r = true → s.delivered r = 0
  /-- spans end on terminal outcomes and effective cancels, nowhere else -/
  spanEq : ∀ r, s.spans r = s.delivered r + (s.effCancel r).toNat
  /-- metrics are recorded on terminal outcomes, nowhere else -/
  metricsEq : ∀ r, s.metrics r = s.delivered r
  stop : s.progressStop = false

theorem inv_init (P : Params) : Inv P (init : St R) := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩ <;> simp [init, admitting]

/-- Prove one `∀ x` field after a step touching request `r`: instantiate
every invariant field at `x` and at `r`, split on `x = r`, and simplify. -/
syntax "adm_field" ident : tactic
set_option hygiene false in
macro_rules
  | `(tactic| adm_field $r) => `(tactic| (
      intro x
      have e1 := c1 x; have e2 := c2 x; have e3 := c3 x; have e4 := c4 x
      have e5 := c5 x; have e6 := c6 x; have e7 := c7 x; have e8 := c8 x
      have e9 := c9 x; have e10 := c10 x; have e11 := c11 x; have e12 := c12 x
      have f1 := c1 $r; have f2 := c2 $r; have f3 := c3 $r; have f4 := c4 $r
      have f5 := c5 $r; have f6 := c6 $r; have f7 := c7 $r; have f8 := c8 $r
      have f9 := c9 $r; have f10 := c10 $r; have f11 := c11 $r; have f12 := c12 $r
      clear c1 c2 c3 c4 c5 c6 c7 c8 c9 c10 c11 c12
      by_cases hx : x = $r
      · subst hx
        simp only [upd_same, admitting, replyExpired, resolve, Bool.toNat, cntReq_append, cntReq_req,
          cntReq_cancel, cntReq_resp, cntReq_chunk, cntReq_nil, List.append_nil, if_true] at *
        grind [cntReq_req, cntReq_cancel, cntReq_resp, cntReq_chunk, cntReq_nil]
      · have hx' : ¬ $r = x := fun h => hx h.symm
        simp only [upd_other _ _ _ _ hx, hx, hx', admitting, replyExpired, resolve, Bool.toNat,
          cntReq_append, cntReq_req, cntReq_cancel, cntReq_resp, cntReq_chunk,
          cntReq_nil, if_false] at *
        grind [cntReq_req, cntReq_cancel, cntReq_resp, cntReq_chunk, cntReq_nil]))

/-- Preserve `Inv` across a step touching only request `r` and leaving
`progressStop` alone. -/
syntax "adm_inv" ident : tactic
set_option hygiene false in
macro_rules
  | `(tactic| adm_inv $r) => `(tactic| (
      obtain ⟨c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13⟩ := hI
      refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, c13⟩
      all_goals adm_field $r))

section Steps
variable {P : Params} {s : St R}

theorem inv_sendLive (hI : Inv P s) (r : R) (hs : s.sent r = false) :
    Inv P { s with wQ := s.wQ ++ [.req r], sent := upd s.sent r true,
                   pending := upd s.pending r true } := by
  adm_inv r

theorem inv_sendDead (hI : Inv P s) (r : R) (hs : s.sent r = false) :
    Inv P { resolve s r 1 with sent := upd s.sent r true } := by
  adm_inv r

theorem inv_expire (hI : Inv P s) (r : R) :
    Inv P { s with expired := upd s.expired r true } := by
  adm_inv r

theorem inv_callerTimeout (hI : Inv P s) (hP : Safe P) (r : R)
    (hct : P.callerTimeouts = true) (hp : s.pending r = true) (he : s.expired r = true)
    (hsl : P.slack = true → s.phase ≠ .checked r) :
    Inv P { resolve s r 1 with pending := upd s.pending r false,
                               gaveUp := upd s.gaveUp r true } := by
  have hsl' : s.phase ≠ .checked r := by
    rcases hP with h | h
    · simp [h] at hct
    · exact hsl h.2
  adm_inv r

theorem inv_sendCancel (hI : Inv P s) (r : R) :
    Inv P { s with cancelled := upd s.cancelled r true,
                   wQ := if s.wAlive then s.wQ ++ [.cancel r] else s.wQ } := by
  split <;> adm_inv r

theorem inv_recvReqExpired (hI : Inv P s) (r : R) (pre rest : List (WMsg R))
    (hq : s.wQ = pre ++ .req r :: rest) :
    Inv P { replyExpired s r with wQ := pre ++ rest } := by
  cases s; simp only at hq; subst hq
  adm_inv r

theorem inv_recvReq (hI : Inv P s) (r : R) (pre rest : List (WMsg R))
    (hq : s.wQ = pre ++ .req r :: rest) :
    Inv P { s with wQ := pre ++ rest, phase := .sent r } := by
  cases s; simp only at hq; subst hq
  adm_inv r

theorem inv_checkRefuse (hI : Inv P s) (r : R) (hph : s.phase = .sent r) :
    Inv P { replyExpired s r with phase := .idle } := by
  adm_inv r

theorem inv_checkPass (hI : Inv P s) (hP : Safe P) (r : R) (hph : s.phase = .sent r)
    (hd : (P.deadline && s.expired r) = false) :
    Inv P { s with phase := .checked r } := by
  have hpend : s.pending r = true := by
    have := hI.inAdmit r (Or.inl hph)
    rcases hP with h | ⟨h, -⟩
    · exact this.2.2.2 h
    · simp [h] at hd; simp [hd] at this; exact this.2.2.1
  adm_inv r

theorem inv_admitReply (hI : Inv P s) (r : R) (hph : s.phase = .checked r) :
    Inv P { s with reqs := upd s.reqs r true, pending := upd s.pending r false,
                   accepted := upd s.accepted r (s.accepted r || s.pending r),
                   phase := .idle } := by
  adm_inv r

theorem inv_recvCancel (hI : Inv P s) (r : R) (pre rest : List (WMsg R))
    (hph : s.phase = .idle) (hq : s.wQ = pre ++ .cancel r :: rest) :
    Inv P (if s.reqs r then
          { s with wQ := pre ++ rest, reqs := upd s.reqs r false,
                   effCancel := upd s.effCancel r true,
                   snap := upd s.snap r (s.delivered r),
                   spans := upd s.spans r (s.spans r + 1) }
        else { s with wQ := pre ++ rest }) := by
  cases s; simp only at hq; subst hq
  split <;> adm_inv r

theorem inv_recvResp (hI : Inv P s) (r : R) (pre rest : List (WMsg R))
    (hph : s.phase = .idle) (hq : s.wQ = pre ++ .resp r :: rest) :
    Inv P (if s.reqs r then
          { resolve s r 1 with wQ := pre ++ rest, reqs := upd s.reqs r false }
        else { s with wQ := pre ++ rest }) := by
  cases s; simp only at hq; subst hq
  split <;> adm_inv r

theorem inv_recvChunk (hI : Inv P s) (r : R) (pre rest : List (WMsg R))
    (hq : s.wQ = pre ++ .chunk r :: rest) :
    Inv P { s with wQ := pre ++ rest,
                   progressStop := s.progressStop ||
                     (s.reqs r && (s.effCancel r || decide (0 < s.delivered r))) } := by
  have hstop : (s.reqs r && (s.effCancel r || decide (0 < s.delivered r))) = false := by
    have h1 := hI.once r; have h9 := hI.eff r
    cases hr : s.reqs r
    · simp
    · have he : s.effCancel r = false := by
        cases he : s.effCancel r
        · rfl
        · simp [he, hr] at h9
      simp [hr, he, Bool.toNat] at h1 ⊢; omega
  cases s; simp only at hq; subst hq
  obtain ⟨c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13⟩ := hI
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, by simp only at hstop c13 ⊢; simp [c13, hstop]⟩
  all_goals adm_field r

theorem inv_emitResp (hI : Inv P s) (r : R) :
    Inv P { s with wQ := s.wQ ++ [.resp r] } := by
  adm_inv r

theorem inv_emitChunk (hI : Inv P s) (r : R) :
    Inv P { s with wQ := s.wQ ++ [.chunk r] } := by
  adm_inv r

theorem inv_restart (hI : Inv P s) :
    Inv P { s with wAlive := true, wQ := [] } := by
  obtain ⟨c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13⟩ := hI
  refine ⟨c1, ?_, ?_, c4, c5, c6, ?_, c8, c9, c10, c11, c12, c13⟩
  · intro x hx; have := c2 x hx; simp_all [admitting]
  · intro x hx; simp at hx
  · intro x hx; have := c7 x hx; simp_all [admitting]

theorem inv_crash (hI : Inv P s) : Inv P (crash s) := by
  obtain ⟨c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13⟩ := hI
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, c13⟩
  all_goals intro x
  all_goals have e1 := c1 x; have e2 := c2 x; have e6 := c6 x; have e7 := c7 x
  all_goals have e8 := c8 x; have e9 := c9 x; have e10 := c10 x; have e11 := c11 x
  all_goals have e12 := c12 x
  all_goals clear c1 c2 c3 c4 c5 c6 c7 c8 c9 c10 c11 c12
  all_goals simp_all [crash, admitting, Bool.toNat]
  all_goals (cases hr : s.reqs x <;> cases hp : s.pending x <;> simp_all <;> omega)

theorem inv_kill (hI : Inv P s) : Inv P (kill s) := by
  obtain ⟨c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13⟩ := hI
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, c13⟩
  all_goals intro x
  all_goals have e1 := c1 x; have e2 := c2 x; have e6 := c6 x; have e7 := c7 x
  all_goals have e8 := c8 x; have e9 := c9 x; have e10 := c10 x; have e11 := c11 x
  all_goals have e12 := c12 x
  all_goals clear c1 c2 c3 c4 c5 c6 c7 c8 c9 c10 c11 c12
  all_goals simp_all [kill, admitting, Bool.toNat]
  all_goals (cases hr : s.reqs x <;> cases hp : s.pending x <;> simp_all <;> omega)

end Steps

theorem inv_step {P : Params} (hP : Safe P) {s t : St R} (hI : Inv P s)
    (h : Step P s t) : Inv P t := by
  cases h with
  | sendLive r hs _ => exact inv_sendLive hI r hs
  | sendDead r hs _ => exact inv_sendDead hI r hs
  | expire r => exact inv_expire hI r
  | callerTimeout r hct hp he hsl => exact inv_callerTimeout hI hP r hct hp he hsl
  | sendCancel r => exact inv_sendCancel hI r
  | recvReqExpired r pre rest _ _ hq => exact inv_recvReqExpired hI r pre rest hq
  | recvReq r pre rest _ _ hq => exact inv_recvReq hI r pre rest hq
  | checkRefuse r _ hph => exact inv_checkRefuse hI r hph
  | checkPass r _ hph hd => exact inv_checkPass hI hP r hph hd
  | admitReply r _ hph => exact inv_admitReply hI r hph
  | recvCancel r pre rest _ hph hq => exact inv_recvCancel hI r pre rest hph hq
  | recvResp r pre rest _ hph hq => exact inv_recvResp hI r pre rest hph hq
  | recvChunk r pre rest _ _ hq => exact inv_recvChunk hI r pre rest hq
  | crash => exact inv_crash hI
  | kill => exact inv_kill hI
  | restart => exact inv_restart hI
  | emitResp r => exact inv_emitResp hI r
  | emitChunk r => exact inv_emitChunk hI r

theorem inv_reach {P : Params} (hP : Safe P) {s : St R} (h : Reach P s) : Inv P s := by
  induction h with
  | init => exact inv_init P
  | step _ hs ih => exact inv_step hP ih hs

/-! ## Headline corollaries -/

theorem at_most_once_proof (P : Params) (hP : Safe P) (s : St R) (h : Reach P s) (r : R) :
    s.delivered r ≤ 1 := by
  have := (inv_reach hP h).once r; omega

theorem no_message_after_admission_error_proof (P : Params) (hP : Safe P) (s : St R)
    (h : Reach P s) (r : R) (hg : s.gaveUp r = true) :
    s.delivered r = 1 ∧ s.reqs r = false := by
  have hI := inv_reach hP h
  have h1 := hI.once r; have h6 := hI.gaveUpOnce r hg
  refine ⟨by omega, ?_⟩
  cases hr : s.reqs r
  · rfl
  · simp [hr, Bool.toNat] at h1; omega

theorem no_delivery_after_effective_cancel_proof (P : Params) (hP : Safe P) (s : St R)
    (h : Reach P s) (r : R) (he : s.effCancel r = true) :
    s.delivered r = s.snap r :=
  ((inv_reach hP h).eff r he).2.2

theorem telemetry_at_most_once_proof (P : Params) (hP : Safe P) (s : St R)
    (h : Reach P s) (r : R) : s.spans r ≤ 1 ∧ s.metrics r ≤ 1 := by
  have hI := inv_reach hP h
  have h1 := hI.once r; have h2 := hI.spanEq r; have h3 := hI.metricsEq r
  have h4 := hI.effZero r
  cases he : s.effCancel r <;> simp [he] at h2 h4 <;> omega

theorem no_progress_after_stop_proof (P : Params) (hP : Safe P) (s : St R)
    (h : Reach P s) : s.progressStop = false :=
  (inv_reach hP h).stop

end KatipoProofs.Admission
