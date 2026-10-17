import KatipoProofs.Flow.Proofs

/-!
# Flow control: which mechanisms are redundant

## `ConnInfo.paused` mirrors libcurl's own pause state

`flow_conn` resumes the transfer iff `conn->paused`. With the shipped
ordering, `Inv.pausedAgree` already says that flag equals libcurl's pause
state (`curlPaused`) in every reachable state, so it carries nothing libcurl
does not hold: `flow_conn` could call `curl_easy_pause(CONT)` on every
grant and drop the field. That leans on libcurl returning early when the
pause state does not change, and costs a `curl_multi_socket_action` kick
per grant on a running transfer. The pre-fix ordering is exactly where the
two copies diverge (`sLate` in `Counterexamples.lean`); with one copy there
is nothing to fall out of step.

## The worker's `is_map_key` guard on `{flow, Ref, N}`

`StepF` is the worker forwarding every grant to the port, held request or
not (`flowAll`); every other step is unchanged. `RelF s s'` says the two
agree except that `s` has extra grants queued for the port, and only
behind the point where the port has stopped (`ext`). In both directions
every step is matched by at most one step, so the two models reach the
same states up to those extra grants, which the port drops with
`find_conn` returning NULL (`flowDead`): `reachF_reach` and `reach_reachF`.
The guard saves a port write on a late grant; it is not needed for
correctness.
-/

namespace KatipoProofs.Flow

/-- What the guard leans on, besides `Inv`. -/
structure Aux (s : St) : Prop where
  /-- a request the worker let go of has its cancel queued, or the conn is gone -/
  out : s.inReqs = false → 0 ∈ s.pQ ∨ s.live = false ∨ s.pAlive = false
  /-- `curl_easy_pause` only runs on a live conn -/
  unp : s.live = false → s.unpausing = false
  /-- a curl error is the conn's last act -/
  errW : Msg.error ∈ s.toW → s.live = false

theorem aux_reach {P : Params} {s : St} (h : Reach P s) : Aux s := by
  induction h with
  | init => exact ⟨by simp [init], by simp [init], by simp [init]⟩
  | @step s t hr hs ih =>
    have hI := inv_reach hr
    obtain ⟨hout, hunp, herr⟩ := ih
    cases hs with
    | workerFwd m rest hq hin hw =>
      refine ⟨fun h => ?_, hunp, fun h => herr (by simp [hq, h])⟩
      cases m <;> simp at h
      · exact .inr (.inl (hI.doneW (by simp [hq])).2.1)
      · exact .inr (.inl (herr (by simp [hq])))
    | workerExit hw hx hW =>
      refine ⟨fun _ => .inr (.inr ?_), hunp, by simp [hW]⟩
      cases hp : s.pAlive
      · rfl
      · simp [(hI.portLife hp).2] at hx
    | flowDead n rest hu hq hn hl hp =>
      refine ⟨fun h => .inr (.inl hl), fun _ => hu, herr⟩
    | flowRun n rest hu hq hn hl hpz hp =>
      refine ⟨fun h => ?_, fun h => by simp_all, herr⟩
      rcases hout h with h0 | h0 | h0
      · rw [hq] at h0; simp at h0; rcases h0 with h0 | h0
        · omega
        · exact .inl h0
      · simp_all
      · simp_all
    | flowUnpause n rest hu hq hn hl hpz hp =>
      refine ⟨fun h => ?_, fun h => by simp_all, herr⟩
      rcases hout h with h0 | h0 | h0
      · rw [hq] at h0; simp at h0; rcases h0 with h0 | h0
        · omega
        · exact .inl h0
      · simp_all
      · simp_all
    | writeChunk hl hc hr hw =>
      refine ⟨hout, hunp, fun h => ?_⟩
      have : Msg.error ∈ s.toW := by unfold hdrs at h; split at h <;> simp_all
      simp_all
    | complete hl hu hr hc =>
      exact ⟨fun _ => .inr (.inl rfl), fun _ => hu, fun _ => rfl⟩
    | fail _ hl hu =>
      exact ⟨fun _ => .inr (.inl rfl), fun _ => hu, fun _ => rfl⟩
    | portCancel rest hu hq hp =>
      exact ⟨fun _ => .inr (.inl rfl), fun _ => hu, fun _ => rfl⟩
    | workerCancel hc hw =>
      refine ⟨fun _ => ?_, hunp, herr⟩
      cases hin : s.inReqs <;> simp_all
    | workerTimeout _ hin hw => exact ⟨fun _ => .inl (by simp), hunp, herr⟩
    | workerDrop m rest hq hin hw => exact ⟨hout, hunp, fun h => herr (by simp [hq, h])⟩
    | workerFlow n rest hq hw =>
      refine ⟨fun h => ?_, hunp, herr⟩
      rcases hout h with h0 | h0 | h0 <;> simp_all
    | portDies _ hp => exact ⟨fun _ => .inr (.inr rfl), fun _ => rfl, fun _ => rfl⟩
    | unpauseReturn => exact ⟨hout, fun _ => rfl, herr⟩
    | _ => exact ⟨hout, hunp, herr⟩

/-- `s` with `ex` extra grants behind everything else queued for the port. -/
def ext (s : St) (ex : List Nat) : St := { s with pQ := s.pQ ++ ex }

/-- The worker without the guard: every grant goes to the port. -/
inductive StepF (P : Params) : St → St → Prop
  | flowAll (s : St) (n : Nat) (rest : List Nat) : s.flowQ = n :: rest → s.wAlive = true →
      StepF P s { s with flowQ := rest, pQ := s.pQ ++ [n] }
  /-- every step that does not consume a grant is unchanged -/
  | step {s t : St} : Step P s t → s.flowQ.length ≤ t.flowQ.length → StepF P s t

inductive ReachF (P : Params) : St → Prop
  | init : ReachF P (init P)
  | step {s t : St} : ReachF P s → StepF P s t → ReachF P t

/-- `s` (no guard) against `s'` (shipped): equal up to extra grants that
only exist once the worker has let go of the request. -/
def RelF (s s' : St) : Prop :=
  ∃ ex, s = ext s' ex ∧ (∀ n ∈ ex, n ≠ 0) ∧ (ex ≠ [] → s'.inReqs = false)

@[simp] theorem ext_nil (s : St) : ext s [] = s := by cases s; simp [ext]

/-- Close `{ext s' ex with …} = ext {s' with …} ex`. -/
macro "ext_eq" : tactic => `(tactic| (cases ‹St›; simp_all [ext, recv, hdrs, terminal]))

/-- The extra grants never change anything but the port's queue. -/
theorem relF_side {s' t' : St} {ex : List Nat} (hin : ex ≠ [] → s'.inReqs = false)
    (ht : s'.inReqs = false → t'.inReqs = false) : ex ≠ [] → t'.inReqs = false :=
  fun h => ht (hin h)

theorem inReqs_mono {P : Params} {s t : St} (h : Step P s t) :
    s.inReqs = false → t.inReqs = false := by
  intro hf; cases h <;> first | exact hf | simp_all

theorem reachF_reach {P : Params} {s : St} (h : ReachF P s) :
    ∃ s', Reach P s' ∧ RelF s s' := by
  induction h with
  | init => exact ⟨_, .init, [], by simp, by simp, by simp⟩
  | step _ hs ih =>
    obtain ⟨s', hr, ex, rfl, hx, hin⟩ := ih
    have hI := inv_reach hr
    have hA := aux_reach hr
    have exNil : s'.inReqs = true → ex = [] := fun hi => by
      cases ex with
      | nil => rfl
      | cons _ _ => simp [hin (by simp)] at hi
    cases hs with
    | flowAll n rest hq hw =>
      have hq' : s'.flowQ = n :: rest := hq
      have st := Step.workerFlow (P := P) s' n rest hq' hw
      cases hi : s'.inReqs
      · refine ⟨_, .step hr st, ex ++ [n], ?_, ?_, fun _ => by simp [hi]⟩
        · cases s'; simp_all [ext]
        · simp only [List.mem_append, List.mem_singleton]
          rintro k (hk | rfl)
          · exact hx k hk
          · exact hI.flowPos _ (by simp [hq'])
      · have := exNil hi
        subst this
        exact ⟨_, .step hr st, [], by cases s'; simp_all [ext], by simp, by simp⟩
    | @step t hs hlen =>
      -- every case but the port reading its queue maps to the same step
      have same : ∀ u t', Step P s' t' → u = ext t' ex →
          ∃ s'', Reach P s'' ∧ RelF u s'' := fun _ t' st ht =>
        ⟨t', .step hr st, ex, ht, hx, relF_side hin (inReqs_mono st)⟩
      cases hs with
      | writePause h1 h2 h3 h4 => exact same _ _ (.writePause s' h1 h2 h3 h4) (by ext_eq)
      | writeChunk h1 h2 h3 h4 => exact same _ _ (.writeChunk s' h1 h2 h3 h4) (by ext_eq)
      | unpauseReturn h1 => exact same _ _ (.unpauseReturn s' h1) (by ext_eq)
      | complete h1 h2 h3 h4 => exact same _ _ (.complete s' h1 h2 h3 h4) (by ext_eq)
      | fail h1 h2 h3 => exact same _ _ (.fail s' h1 h2 h3) (by ext_eq)
      | workerFwd m rest h1 h2 h3 => exact same _ _ (.workerFwd s' m rest h1 h2 h3) (by ext_eq)
      | workerDrop m rest h1 h2 h3 => exact same _ _ (.workerDrop s' m rest h1 h2 h3) (by ext_eq)
      | workerFlow n rest h1 h2 =>
        rw [h1] at hlen; simp at hlen; omega
      | workerCancel h1 h2 =>
        cases hi : s'.inReqs
        · exact same _ _ (.workerCancel s' h1 h2) (by ext_eq)
        · have := exNil hi
          subst this; exact same _ _ (.workerCancel s' h1 h2) (by ext_eq)
      | workerTimeout h1 h2 h3 =>
        have := exNil h2
        subst this; exact same _ _ (.workerTimeout s' h1 h2 h3) (by ext_eq)
      | portDies h1 h2 => exact same _ _ (.portDies s' h1 h2) (by ext_eq)
      | workerExit h1 h2 h3 => exact same _ _ (.workerExit s' h1 h2 h3) (by ext_eq)
      | consumerRecv m rest h1 => exact same _ _ (.consumerRecv s' m rest h1) (by ext_eq)
      | consumerGrant h1 h2 => exact same _ _ (.consumerGrant s' h1 h2) (by ext_eq)
      | consumerCancel h1 h2 h3 => exact same _ _ (.consumerCancel s' h1 h2 h3) (by ext_eq)
      | flowDead n rest h1 hq h2 h3 h4 =>
        cases hp : s'.pQ with
        | nil =>
          -- the port drops an extra grant: the shipped worker stutters
          simp only [ext, hp, List.nil_append] at hq; subst hq
          refine ⟨s', hr, rest, by cases s'; simp_all [ext], fun k hk => hx k (by simp [hk]),
            fun _ => hin (by simp)⟩
        | cons m rest' =>
          simp only [ext, hp, List.cons_append, List.cons.injEq] at hq
          obtain ⟨rfl, rfl⟩ := hq
          exact same _ _ (.flowDead s' m rest' h1 hp h2 h3 h4) (by ext_eq)
      | flowRun n rest h1 hq h2 h3 h4 h5 =>
        cases hp : s'.pQ with
        | nil =>
          simp only [ext, hp, List.nil_append] at hq
          rcases hA.out (hin (by simp [hq])) with h0 | h0 | h0 <;> simp_all [ext]
        | cons m rest' =>
          simp only [ext, hp, List.cons_append, List.cons.injEq] at hq
          obtain ⟨rfl, rfl⟩ := hq
          exact same _ _ (.flowRun s' m rest' h1 hp h2 h3 h4 h5) (by ext_eq)
      | flowUnpause n rest h1 hq h2 h3 h4 h5 =>
        cases hp : s'.pQ with
        | nil =>
          simp only [ext, hp, List.nil_append] at hq
          rcases hA.out (hin (by simp [hq])) with h0 | h0 | h0 <;> simp_all [ext]
        | cons m rest' =>
          simp only [ext, hp, List.cons_append, List.cons.injEq] at hq
          obtain ⟨rfl, rfl⟩ := hq
          exact same _ _ (.flowUnpause s' m rest' h1 hp h2 h3 h4 h5) (by ext_eq)
      | portCancel rest h1 hq h2 =>
        cases hp : s'.pQ with
        | nil =>
          simp only [ext, hp, List.nil_append] at hq
          exact absurd rfl (hx 0 (by simp [hq]))
        | cons m rest' =>
          simp only [ext, hp, List.cons_append, List.cons.injEq] at hq
          obtain ⟨rfl, rfl⟩ := hq
          exact same _ _ (.portCancel s' rest' h1 hp h2) (by ext_eq)

theorem reach_reachF {P : Params} {s' : St} (h : Reach P s') :
    ∃ s, ReachF P s ∧ RelF s s' := by
  induction h with
  | init => exact ⟨_, .init, [], by simp, by simp, by simp⟩
  | @step s' t' hr hs ih =>
    obtain ⟨_, hf, ex, rfl, hx, hin⟩ := ih
    have hI := inv_reach hr
    have exNil : s'.inReqs = true → ex = [] := fun hi => by
      cases ex with
      | nil => rfl
      | cons _ _ => simp [hin (by simp)] at hi
    -- a step that does not touch the grant queue is the same step on `ext s' ex`
    have same : ∀ t, Step P (ext s' ex) t → (ext s' ex).flowQ.length ≤ t.flowQ.length →
        t = ext t' ex → ∃ u, ReachF P u ∧ RelF u t' := fun t st hl ht =>
      ⟨t, .step hf (.step st hl), ex, ht, hx, relF_side hin (inReqs_mono hs)⟩
    cases hs with
    | workerFlow n rest hq hw =>
      have st := StepF.flowAll (P := P) (ext s' ex) n rest hq hw
      cases hi : s'.inReqs
      · refine ⟨_, .step hf st, ex ++ [n], ?_, ?_, fun _ => by simp⟩
        · cases s'; simp_all [ext]
        · simp only [List.mem_append, List.mem_singleton]
          rintro k (hk | rfl)
          · exact hx k hk
          · exact hI.flowPos _ (by simp [hq])
      · have := exNil hi
        subst this
        exact ⟨_, .step hf st, [], by cases s'; simp_all [ext], by simp, by simp⟩
    | writePause h1 h2 h3 h4 =>
      exact same _ (.writePause _ h1 h2 h3 h4) (by simp [ext]) (by ext_eq)
    | writeChunk h1 h2 h3 h4 =>
      exact same _ (.writeChunk _ h1 h2 h3 h4) (by simp [ext]) (by ext_eq)
    | unpauseReturn h1 => exact same _ (.unpauseReturn _ h1) (by simp [ext]) (by ext_eq)
    | complete h1 h2 h3 h4 =>
      exact same _ (.complete _ h1 h2 h3 h4) (by simp [ext]) (by ext_eq)
    | fail h1 h2 h3 => exact same _ (.fail _ h1 h2 h3) (by simp [ext]) (by ext_eq)
    | workerFwd m rest h1 h2 h3 =>
      exact same _ (.workerFwd _ m rest h1 h2 h3) (by simp [ext]) (by ext_eq)
    | workerDrop m rest h1 h2 h3 =>
      exact same _ (.workerDrop _ m rest h1 h2 h3) (by simp [ext]) (by ext_eq)
    | workerCancel h1 h2 =>
      rcases Bool.eq_false_or_eq_true s'.inReqs with hi | hi
      · have := exNil hi
        subst this; exact same _ (.workerCancel _ h1 h2) (by simp [ext]) (by ext_eq)
      · exact same _ (.workerCancel _ h1 h2) (by simp [ext]) (by ext_eq)
    | workerTimeout h1 h2 h3 =>
      have := exNil h2
      subst this; exact same _ (.workerTimeout _ h1 h2 h3) (by simp [ext]) (by ext_eq)
    | portDies h1 h2 => exact same _ (.portDies _ h1 h2) (by simp [ext]) (by ext_eq)
    | workerExit h1 h2 h3 => exact same _ (.workerExit _ h1 h2 h3) (by simp [ext]) (by ext_eq)
    | consumerRecv m rest h1 =>
      exact same _ (.consumerRecv _ m rest h1) (by simp [ext, recv]) (by ext_eq)
    | consumerGrant h1 h2 =>
      exact same _ (.consumerGrant _ h1 h2) (by simp [ext]) (by ext_eq)
    | consumerCancel h1 h2 h3 =>
      exact same _ (.consumerCancel _ h1 h2 h3) (by simp [ext]) (by ext_eq)
    | flowDead n rest h1 hq h2 h3 h4 =>
      exact same _ (.flowDead _ n (rest ++ ex) h1 (by simp [ext, hq]) h2 h3 h4)
        (by simp [ext]) (by ext_eq)
    | flowRun n rest h1 hq h2 h3 h4 h5 =>
      exact same _ (.flowRun _ n (rest ++ ex) h1 (by simp [ext, hq]) h2 h3 h4 h5)
        (by simp [ext]) (by ext_eq)
    | flowUnpause n rest h1 hq h2 h3 h4 h5 =>
      exact same _ (.flowUnpause _ n (rest ++ ex) h1 (by simp [ext, hq]) h2 h3 h4 h5)
        (by simp [ext]) (by ext_eq)
    | portCancel rest h1 hq h2 =>
      exact same _ (.portCancel _ (rest ++ ex) h1 (by simp [ext, hq]) h2)
        (by simp [ext]) (by ext_eq)

end KatipoProofs.Flow
