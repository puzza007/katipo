import KatipoProofs.Admission.Model

/-!
# Admission: the pre-send deadline check is redundant

`admit_call` checks the deadline twice: before `send_to_port` and after it.
`StepS` is the worker with only the second check: `recvReqAny` always sends,
and `checkRefuse` refuses. Both directions hold for every `P`:

* `reach_reachS`: every state the shipped worker reaches, the simplified
  one reaches too.
* `reachS_reach`: every state the simplified worker reaches is related by
  `Rel` to one the shipped worker reaches. `Rel` changes only `phase` and
  `wQ` (the refused request is still in the mailbox instead of being
  mid-admission), so every observable -- `delivered`, `spans`, `metrics`,
  `reqs`, `gaveUp`, `effCancel`, `snap`, `progressStop` -- is the same.

So every safety theorem about `Step` holds verbatim for `StepS`, and no
caller-visible outcome needs the first check. What it buys is not
semantics: a stale call (the backed-up-mailbox case) never starts a C
transfer that the second check would immediately abort.
-/

namespace KatipoProofs.Admission

variable {R : Type} [DecidableEq R]

/-- The worker's first deadline check, as a transition. -/
def PreRefuse (P : Params) (s t : St R) : Prop :=
  ∃ r pre rest, s.wAlive = true ∧ s.phase = .idle ∧ s.wQ = pre ++ .req r :: rest ∧
    (P.deadline && s.expired r) = true ∧ t = { replyExpired s r with wQ := pre ++ rest }

/-- `admit_call` without the first `past/1`. -/
inductive StepS (P : Params) : St R → St R → Prop
  | recvReqAny (s : St R) (r : R) (pre rest : List (WMsg R)) : s.wAlive = true →
      s.phase = .idle → s.wQ = pre ++ .req r :: rest →
      StepS P s { s with wQ := pre ++ rest, phase := .sent r }
  | step {s t : St R} : Step P s t → ¬ PreRefuse P s t → StepS P s t

inductive ReachS (P : Params) : St R → Prop
  | init : ReachS P init
  | step {s t : St R} : ReachS P s → StepS P s t → ReachS P t

theorem reach_reachS {P : Params} {s : St R} (h : Reach P s) : ReachS P s := by
  induction h with
  | init => exact .init
  | step _ hs ih =>
    rename_i s t _
    by_cases hp : PreRefuse P s t
    · obtain ⟨r, pre, rest, hw, hi, hq, he, rfl⟩ := hp
      have r1 := ReachS.step ih (.recvReqAny s r pre rest hw hi hq)
      have r2 := ReachS.step r1 (.step (.checkRefuse _ r hw rfl he) (by
        rintro ⟨_, _, _, _, h, _⟩; cases h))
      have e : ({ replyExpired s r with wQ := pre ++ rest } : St R) =
          { replyExpired { s with wQ := pre ++ rest, phase := .sent r } r with phase := .idle } := by
        cases s; simp_all [replyExpired, resolve]
      rw [e]; exact r2
    · exact .step ih (.step hs hp)

/-- The simplified worker's state `s` against the shipped worker's `s'`:
equal, or `s` has sent an already-expired request that `s'` still holds in
its mailbox (and will refuse at the first check). -/
def Rel (P : Params) (s s' : St R) : Prop :=
  s' = s ∨ ∃ r pre rest, s.wAlive = true ∧ s.phase = .sent r ∧
    (P.deadline && s.expired r) = true ∧ s.wQ = pre ++ rest ∧
    s' = { s with phase := .idle, wQ := pre ++ .req r :: rest }

omit [DecidableEq R] in
/-- Everything a caller or a property can observe agrees across `Rel`. -/
theorem Rel.obs {P : Params} {s s' : St R} (h : Rel P s s') :
    s'.delivered = s.delivered ∧ s'.spans = s.spans ∧ s'.metrics = s.metrics ∧
    s'.reqs = s.reqs ∧ s'.gaveUp = s.gaveUp ∧ s'.effCancel = s.effCancel ∧
    s'.snap = s.snap ∧ s'.progressStop = s.progressStop ∧ s'.accepted = s.accepted ∧
    s'.pending = s.pending := by
  rcases h with rfl | ⟨_, _, _, _, _, _, _, rfl⟩ <;> simp

theorem reachS_reach {P : Params} {s : St R} (h : ReachS P s) :
    ∃ s', Reach P s' ∧ Rel P s s' := by
  induction h with
  | init => exact ⟨_, .init, .inl rfl⟩
  | step _ hs ih =>
    rename_i s t _
    obtain ⟨s', hr, hrel⟩ := ih
    rcases hrel with rfl | ⟨r, pre, rest, hw, hph, he, hq, rfl⟩
    · cases hs with
      | recvReqAny r pre rest hw hi hq =>
        by_cases he : (P.deadline && s'.expired r) = true
        · exact ⟨s', hr, .inr ⟨r, pre, rest, hw, rfl, he, rfl, by cases s'; simp_all⟩⟩
        · exact ⟨_, .step hr (.recvReq _ r pre rest hw hi hq (by simpa using he)), .inl rfl⟩
      | step hs _ => exact ⟨_, .step hr hs, .inl rfl⟩
    · -- `s` is mid-admission of the expired `r`; `s'` has it queued.
      cases hs with
      | recvReqAny _ _ _ _ hi => simp_all
      | step hs hn =>
        cases hs with
        | sendLive x h1 h2 =>
          refine ⟨_, .step hr (.sendLive _ x h1 h2), .inr ⟨r, pre, rest ++ [.req x], hw, hph,
            he, by simp [hq], ?_⟩⟩
          simp
        | sendDead x h1 h2 => simp_all
        | expire x h1 h2 h3 =>
          refine ⟨_, .step hr (.expire _ x h1 h2 h3), .inr ⟨r, pre, rest, hw, hph, ?_, hq, rfl⟩⟩
          by_cases hx : r = x <;> simp_all [upd]
        | callerTimeout x h1 h2 h3 h4 =>
          refine ⟨_, .step hr (.callerTimeout _ x h1 h2 h3 (by simp)),
            .inr ⟨r, pre, rest, hw, hph, he, hq, ?_⟩⟩
          simp [resolve]
        | sendCancel x h1 h2 =>
          refine ⟨_, .step hr (.sendCancel _ x h1 h2), .inr ⟨r, pre,
            rest ++ [.cancel x], hw, hph, he, by simp [hq, hw], ?_⟩⟩
          simp [hw]
        | recvReqExpired _ _ _ _ hi => simp_all
        | recvReq _ _ _ _ hi => simp_all
        | checkRefuse x _ hx hex =>
          rw [hph] at hx; cases hx
          refine ⟨_, .step hr (.recvReqExpired _ r pre rest hw rfl rfl he), .inl ?_⟩
          simp [replyExpired, resolve, hq]
        | checkPass x _ hx hex => rw [hph] at hx; cases hx; simp_all
        | admitReply x _ hx => simp_all
        | recvCancel _ _ _ _ hi => simp_all
        | recvResp _ _ _ _ hi => simp_all
        | recvChunk _ _ _ _ hi => simp_all
        | crash h1 =>
          exact ⟨_, .step hr (.crash _ h1), .inl (by simp [crash])⟩
        | kill h1 =>
          exact ⟨_, .step hr (.kill _ h1), .inl (by simp [kill])⟩
        | restart h1 => simp_all
        | emitResp x h1 =>
          refine ⟨_, .step hr (.emitResp _ x h1), .inr ⟨r, pre, rest ++ [.resp x], hw, hph,
            he, by simp [hq], ?_⟩⟩
          simp
        | emitChunk x h1 =>
          refine ⟨_, .step hr (.emitChunk _ x h1), .inr ⟨r, pre, rest ++ [.chunk x], hw, hph,
            he, by simp [hq], ?_⟩⟩
          simp

/-! ## The post-send check is not redundant

`StepNoPost` is the worker with only the first check: after `send_to_port`
it always admits (`passAny`), and no step from mid-admission refuses
(`checkRefuse`/`checkPass` are excluded). Under the shipped `P`, a caller
that timed out while `port_command` blocked then also gets a message. -/

/-- `admit_call` without the second `past/1`. -/
inductive StepNoPost (P : Params) : St R → St R → Prop
  | passAny (s : St R) (r : R) : s.wAlive = true → s.phase = .sent r →
      StepNoPost P s { s with phase := .checked r }
  | step {s t : St R} : Step P s t →
      (∀ r, s.phase = .sent r → t.phase = .sent r ∨ t.wAlive = false) → StepNoPost P s t

inductive ReachNoPost (P : Params) : St R → Prop
  | init : ReachNoPost P init
  | step {s t : St R} : ReachNoPost P s → StepNoPost P s t → ReachNoPost P t

/-- The shipped parameters. -/
def pShipped : Params := ⟨true, true, true⟩

theorem no_post_check_double_delivery_proof :
    ∃ s : St Unit, ReachNoPost pShipped s ∧ s.delivered () = 2 := by
  have r1 := ReachNoPost.step (ReachNoPost.init (P := pShipped))
    (.step (Step.sendLive _ () rfl rfl) (by simp [init]))
  have r2 := ReachNoPost.step r1 (.step (Step.recvReq _ () [] [] rfl rfl rfl rfl) (by simp))
  -- port_command blocks past the deadline; the caller gives up
  have r3 := ReachNoPost.step r2
    (.step (Step.expire _ () rfl (by simp [upd]) rfl) (by simp))
  have r4 := ReachNoPost.step r3
    (.step (Step.callerTimeout _ () rfl (by simp [upd]) (by simp [upd]) (by simp))
      (by simp [resolve]))
  have r5 := ReachNoPost.step r4 (.passAny _ () rfl rfl)
  have r6 := ReachNoPost.step r5 (.step (Step.admitReply _ () rfl rfl) (by simp))
  have r7 := ReachNoPost.step r6 (.step (Step.emitResp _ () rfl) (by simp))
  have r8 := ReachNoPost.step r7 (.step (Step.recvResp _ () [] [] rfl rfl rfl) (by simp))
  exact ⟨_, r8, by simp [upd, init, resolve]⟩

end KatipoProofs.Admission
