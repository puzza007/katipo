import KatipoProofs.Retry.Model

/-!
# Retries: invariants

`Gen` holds for every configuration: outcomes, and transfers sent, against
each request's state. `Fr` holds with fresh port ids: each transfer's id
carries its attempt number, is in at most one place (pipe, port or the
port's output), and is either its request's current attempt or has a
cancel behind it in the pipe.
-/

namespace KatipoProofs.Retry

structure Gen (P : Params) (s : St) : Prop where
  deliv : ∀ r, s.delivered r = if s.rs r = .done then 1 else 0
  sentNew : ∀ r, s.rs r = .new → s.sent r = 0
  sentHeld : ∀ r m c tr, s.rs r = .held m c tr →
    s.sent r = c + 1 ∧ c ≤ P.maxRetries ∧ (m = .backoff → c < P.maxRetries)
  sentLe : ∀ r, s.sent r ≤ P.maxRetries + 1

/-- `Gen` reads only `rs`, `sent` and `delivered`. -/
theorem gen_congr {P : Params} {s t : St} (h1 : t.rs = s.rs) (h2 : t.sent = s.sent)
    (h3 : t.delivered = s.delivered) (hG : Gen P s) : Gen P t := by
  obtain ⟨a, b, c, d⟩ := hG
  exact ⟨by rw [h1, h3]; exact a, by rw [h1, h2]; exact b, by rw [h1, h2]; exact c,
         by rw [h2]; exact d⟩

theorem gen_init (P : Params) : Gen P init :=
  ⟨fun _ => rfl, fun _ _ => rfl, fun _ _ _ _ h => (nomatch h), fun _ => Nat.zero_le _⟩

/-- `retryOrResolve` keeps `Gen` for a request held in an attempt. -/
theorem gen_rr {P : Params} {s : St} (hG : Gen P s) {r c tr : Nat}
    (hr : s.rs r = .held .attempt c tr) (b : Bool) (A : Timer → Bool) (o : List Out)
    (st0 : Bool) (f : Timer → Bool) (q : List Cmd) (sp : Bool) :
    Gen P (retryOrResolve P { s with out := o, stale := st0, fired := f, pipe := q,
                                     spurious := sp } r c b A) := by
  obtain ⟨hs, hc, -⟩ := hG.sentHeld r _ _ _ hr
  unfold retryOrResolve
  split
  · next hb =>
    refine ⟨fun x => ?_, fun x hx => ?_, fun x m c' tr' hx => ?_, hG.sentLe⟩
    · by_cases e : x = r
      · subst e; simp [upd, hG.deliv x, hr]
      · simp [upd, e, hG.deliv x]
    · by_cases e : x = r
      · subst e; simp [upd] at hx
      · simp [upd, e] at hx ⊢; exact hG.sentNew x hx
    · by_cases e : x = r
      · subst e; simp [upd] at hx; obtain ⟨rfl, rfl, -⟩ := hx
        exact ⟨hs, hc, fun _ => hb.2⟩
      · simp [upd, e] at hx ⊢; exact hG.sentHeld x m c' tr' hx
  · refine ⟨fun x => ?_, fun x hx => ?_, fun x m c' tr' hx => ?_, hG.sentLe⟩
    · by_cases e : x = r
      · subst e; simp [upd, hG.deliv x, hr]
      · simp [upd, e, hG.deliv x]
    · by_cases e : x = r
      · subst e; simp [upd] at hx
      · simp [upd, e] at hx ⊢; exact hG.sentNew x hx
    · by_cases e : x = r
      · subst e; simp [upd] at hx
      · simp [upd, e] at hx ⊢; exact hG.sentHeld x m c' tr' hx

theorem gen_step {P : Params} {s t : St} (hG : Gen P s) (h : Step P s t) : Gen P t := by
  cases h with
  | admit r hr =>
    refine ⟨fun x => ?_, fun x hx => ?_, fun x m c tr hx => ?_, fun x => ?_⟩
    · by_cases e : x = r
      · subst e; simp [upd, hG.deliv x, hr]
      · simp [upd, e, hG.deliv x]
    · by_cases e : x = r
      · subst e; simp [upd] at hx
      · simp [upd, e] at hx ⊢; exact hG.sentNew x hx
    · by_cases e : x = r
      · subst e; simp [upd] at hx; obtain ⟨rfl, rfl, -⟩ := hx; simp [upd]
      · simp [upd, e] at hx ⊢; exact hG.sentHeld x m c tr hx
    · by_cases e : x = r
      · subst e; simp [upd]
      · simp [upd, e]; exact hG.sentLe x
  | portReq => exact gen_congr (s := s) rfl rfl rfl hG
  | portCancel => exact gen_congr (s := s) rfl rfl rfl hG
  | portEnd => exact gen_congr (s := s) rfl rfl rfl hG
  | fire => exact gen_congr (s := s) rfl rfl rfl hG
  | workerOutCur l1 l2 m c tr _ hr _ =>
    exact gen_rr hG hr m.retry _ _ _ s.fired s.pipe s.spurious
  | workerOutDrop => exact gen_congr (s := s) rfl rfl rfl hG
  | reqTimeout t c tr _ _ hr _ =>
    exact gen_rr hG hr true _ s.out s.stale _ _ _
  | reqTimeoutDrop => exact gen_congr (s := s) rfl rfl rfl hG
  | retryDrop => exact gen_congr (s := s) rfl rfl rfl hG
  | retry t c tr _ _ hr _ =>
    generalize t.r = r at *
    obtain ⟨hs, hc, hb⟩ := hG.sentHeld _ _ _ _ hr
    have hb := hb rfl
    refine ⟨fun x => ?_, fun x hx => ?_, fun x m c' tr' hx => ?_, fun x => ?_⟩
    · by_cases e : x = r
      · subst e; simp [upd, hG.deliv x, hr]
      · simp [upd, e, hG.deliv x]
    · by_cases e : x = r
      · subst e; simp [upd] at hx
      · simp [upd, e] at hx ⊢; exact hG.sentNew x hx
    · by_cases e : x = r
      · subst e; simp [upd] at hx; obtain ⟨rfl, rfl, -⟩ := hx; simp [upd]; omega
      · simp [upd, e] at hx ⊢; exact hG.sentHeld x m c' tr' hx
    · by_cases e : x = r
      · subst e; simp [upd]; omega
      · simp [upd, e]; exact hG.sentLe x
  | callerCancel => exact gen_congr (s := s) rfl rfl rfl hG
  | workerCancel r m c tr _ hr =>
    refine ⟨fun x => ?_, fun x hx => ?_, fun x m' c' tr' hx => ?_, hG.sentLe⟩
    · by_cases e : x = r
      · subst e; simp [upd, hG.deliv x, hr]
      · simp [upd, e, hG.deliv x]
    · by_cases e : x = r
      · subst e; simp [upd] at hx
      · simp [upd, e] at hx ⊢; exact hG.sentNew x hx
    · by_cases e : x = r
      · subst e; simp [upd] at hx
      · simp [upd, e] at hx ⊢; exact hG.sentHeld x m' c' tr' hx
  | workerCancelDrop => exact gen_congr (s := s) rfl rfl rfl hG

theorem gen_reach {P : Params} {s : St} (h : Reach P s) : Gen P s := by
  induction h with
  | init => exact gen_init P
  | step _ hs ih => exact gen_step ih hs

/-- Matching `Tref`, `spurious` is never set. -/
theorem spur_step {P : Params} (hm : P.matchTref = true) {s t : St}
    (hS : s.spurious = false) (h : Step P s t) : t.spurious = false := by
  cases h with
  | workerOutCur l1 l2 m c tr =>
    unfold retryOrResolve; split <;> exact hS
  | reqTimeout t c tr _ _ _ hmt =>
    have : t.tok = tr := by simpa [tmatch, hm] using hmt
    unfold retryOrResolve; split <;> simp [hS, this]
  | _ => exact hS

theorem spur_reach {P : Params} (hm : P.matchTref = true) {s : St} (h : Reach P s) :
    s.spurious = false := by
  induction h with
  | init => rfl
  | step _ hs ih => exact spur_step hm ih hs


/-! ## Fresh ids -/

def isReq (id : Id) : Cmd → Bool
  | .req i _ => i == id
  | .cancel _ => false

/-- Requests for `id` in a pipe. -/
def reqs (id : Id) (q : List Cmd) : Nat := q.countP (isReq id)

/-- Where transfer `id` is: requested in the pipe, run by the port, or
ended in the port's output. -/
def tokens (s : St) (id : Id) : Nat :=
  reqs id s.pipe + s.running.countP (·.id == id) + s.out.countP (·.id == id)

/-- Each request in the pipe is for its request's current attempt, or has
a cancel for it behind it. -/
def PipeOk (C : Id → Prop) : List Cmd → Prop
  | [] => True
  | .req id _ :: rest => (C id ∨ 0 < cancels id rest) ∧ PipeOk C rest
  | .cancel _ :: rest => PipeOk C rest

structure Fr (s : St) : Prop where
  pipeN : ∀ id n, .req id n ∈ s.pipe → id.n = n
  runN : ∀ x ∈ s.running, x.id.n = x.n
  outN : ∀ m ∈ s.out, m.id.n = m.n
  uniq : ∀ id, tokens s id ≤ 1
  unborn : ∀ id, s.sent id.r ≤ id.n → tokens s id = 0
  pipeOk : PipeOk (isCur s) s.pipe
  runOk : ∀ x ∈ s.running, isCur s x.id ∨ 0 < cancels x.id s.pipe
  noStale : s.stale = false

theorem Id.ext' {a b : Id} (h1 : a.r = b.r) (h2 : a.n = b.n) : a = b := by
  cases a; cases b; simp only at h1 h2; subst h1; subst h2; rfl

theorem pid_fresh {P : Params} (hf : P.fresh = true) (r n : Nat) : pid P r n = ⟨r, n⟩ := by
  simp [pid, hf]

@[simp] theorem cancels_nil (id : Id) : cancels id [] = 0 := rfl

@[simp] theorem cancels_append (id : Id) (p q : List Cmd) :
    cancels id (p ++ q) = cancels id p + cancels id q := by
  simp [cancels, List.countP_append]

@[simp] theorem cancels_req (id i : Id) (n : Nat) (q : List Cmd) :
    cancels id (.req i n :: q) = cancels id q := by
  simp [cancels]

theorem cancels_cancel (id i : Id) (q : List Cmd) :
    cancels id (.cancel i :: q) = cancels id q + if i = id then 1 else 0 := by
  by_cases h : i = id <;> simp [cancels, h]

@[simp] theorem reqs_nil (id : Id) : reqs id [] = 0 := rfl

@[simp] theorem reqs_append (id : Id) (p q : List Cmd) :
    reqs id (p ++ q) = reqs id p + reqs id q := by
  simp [reqs, List.countP_append]

@[simp] theorem reqs_req (id i : Id) (n : Nat) (q : List Cmd) :
    reqs id (.req i n :: q) = reqs id q + if i = id then 1 else 0 := by
  simp [reqs, List.countP_cons, isReq]

@[simp] theorem reqs_cancel (id i : Id) (q : List Cmd) :
    reqs id (.cancel i :: q) = reqs id q := by
  simp [reqs, isReq]

theorem pipeOk_append {C C' : Id → Prop} : ∀ (p q : List Cmd), PipeOk C p → PipeOk C' q →
    (∀ id, 0 < reqs id p → C id → C' id ∨ 0 < cancels id q) → PipeOk C' (p ++ q)
  | [], _, _, hq, _ => hq
  | .req id n :: rest, q, ⟨h1, h2⟩, hq, h => by
    refine ⟨?_, pipeOk_append rest q h2 hq (fun id' hp hc => h id' ?_ hc)⟩
    · rcases h1 with hc | hc
      · rcases h id (by simp) hc with h' | h'
        · exact Or.inl h'
        · exact Or.inr (by simp; omega)
      · exact Or.inr (by simp; omega)
    · simp; omega
  | .cancel id :: rest, q, h1, hq, h => by
    exact pipeOk_append rest q h1 hq (fun id' hp hc => h id' (by simpa using hp) hc)

theorem pipeOk_mono {C C' : Id → Prop} (p : List Cmd) (hp : PipeOk C p)
    (h : ∀ id, 0 < reqs id p → C id → C' id) : PipeOk C' p := by
  have := pipeOk_append p [] hp trivial (fun id hr hc => Or.inl (h id hr hc))
  simpa using this

theorem countP_pos_of_mem {α : Type} {p : α → Bool} {l : List α} {a : α} (h : a ∈ l)
    (hp : p a = true) : 0 < l.countP p :=
  List.countP_pos_iff.mpr ⟨a, h, hp⟩

theorem reqs_pos_of_mem {id : Id} {n : Nat} {q : List Cmd} (h : .req id n ∈ q) :
    0 < reqs id q := countP_pos_of_mem h (by simp [isReq])

/-- `Fr` once the pipe has `q` appended and `rs` changed only at `r`. -/
theorem isCur_upd_ne {s : St} {r : Nat} {v : RS} {id : Id} (h : id.r ≠ r) :
    (∃ tr, upd s.rs r v id.r = .held .attempt id.n tr) ↔ isCur s id := by
  simp [upd, h, isCur]


@[simp] theorem rr_pipe (P : Params) (s : St) (r c : Nat) (b : Bool) (A : Timer → Bool) :
    (retryOrResolve P s r c b A).pipe = s.pipe := by unfold retryOrResolve; split <;> rfl
@[simp] theorem rr_running (P : Params) (s : St) (r c : Nat) (b : Bool) (A : Timer → Bool) :
    (retryOrResolve P s r c b A).running = s.running := by unfold retryOrResolve; split <;> rfl
@[simp] theorem rr_out (P : Params) (s : St) (r c : Nat) (b : Bool) (A : Timer → Bool) :
    (retryOrResolve P s r c b A).out = s.out := by unfold retryOrResolve; split <;> rfl
@[simp] theorem rr_sent (P : Params) (s : St) (r c : Nat) (b : Bool) (A : Timer → Bool) :
    (retryOrResolve P s r c b A).sent = s.sent := by unfold retryOrResolve; split <;> rfl
@[simp] theorem rr_stale (P : Params) (s : St) (r c : Nat) (b : Bool) (A : Timer → Bool) :
    (retryOrResolve P s r c b A).stale = s.stale := by unfold retryOrResolve; split <;> rfl
theorem rr_rs_ne (P : Params) (s : St) (r c : Nat) (b : Bool) (A : Timer → Bool) (x : Nat)
    (h : x ≠ r) : (retryOrResolve P s r c b A).rs x = s.rs x := by
  unfold retryOrResolve; split <;> simp [upd, h]
/-- After `retryOrResolve` the request is not in an attempt. -/
theorem rr_rs_r (P : Params) (s : St) (r c : Nat) (b : Bool) (A : Timer → Bool) (n tr : Nat) :
    (retryOrResolve P s r c b A).rs r ≠ .held .attempt n tr := by
  unfold retryOrResolve; split <;> simp [upd]

/-- `Fr` across a step that appends `q` to the pipe, changes `rs` only at
`r`, only raises `sent`, takes from the port's output and leaves the
port's transfers alone. -/
theorem fr_frame {s t : St} {r : Nat} {q : List Cmd} (hF : Fr s)
    (hrs : ∀ x, x ≠ r → t.rs x = s.rs x)
    (hpipe : t.pipe = s.pipe ++ q) (hrun : t.running = s.running)
    (hout_sub : ∀ m ∈ t.out, m ∈ s.out)
    (hout_cnt : ∀ id, t.out.countP (·.id == id) ≤ s.out.countP (·.id == id))
    (hst : t.stale = false)
    (hmono : ∀ x, s.sent x ≤ t.sent x)
    (hq_n : ∀ id n, Cmd.req id n ∈ q → id.n = n)
    (hq_ok : PipeOk (isCur t) q)
    (hq_tok : ∀ id, 0 < reqs id q → tokens s id = 0 ∧ reqs id q = 1)
    (hq_unborn : ∀ id, t.sent id.r ≤ id.n → reqs id q = 0)
    (hcur : ∀ id, id.r = r → isCur s id →
      0 < reqs id s.pipe + s.running.countP (·.id == id) → isCur t id ∨ 0 < cancels id q) :
    Fr t := by
  have cur_ne : ∀ id, id.r ≠ r → (isCur t id ↔ isCur s id) := by
    intro id h; simp [isCur, hrs _ h]
  have hcur' : ∀ id, isCur s id → 0 < reqs id s.pipe + s.running.countP (·.id == id) →
      isCur t id ∨ 0 < cancels id q := by
    intro id hc hp
    by_cases e : id.r = r
    · exact hcur id e hc hp
    · exact Or.inl ((cur_ne id e).mpr hc)
  have htok : ∀ id, tokens t id ≤ tokens s id + reqs id q := by
    intro id; simp only [tokens, hpipe, hrun, reqs_append]; have := hout_cnt id; omega
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, hst⟩
  · intro id n h
    rw [hpipe, List.mem_append] at h
    rcases h with h | h
    · exact hF.pipeN _ _ h
    · exact hq_n _ _ h
  · rw [hrun]; exact hF.runN
  · exact fun m hm => hF.outN m (hout_sub m hm)
  · intro id
    have := htok id
    by_cases hq : 0 < reqs id q
    · obtain ⟨h0, h1⟩ := hq_tok id hq; omega
    · have := hF.uniq id; omega
  · intro id hle
    have h1 := hq_unborn id hle
    have h2 := hF.unborn id (Nat.le_trans (hmono _) hle)
    have := htok id; omega
  · rw [hpipe]
    exact pipeOk_append _ _ hF.pipeOk hq_ok (fun id hp hc => hcur' id hc (by omega))
  · intro x hx
    rw [hrun] at hx
    rw [hpipe, cancels_append]
    have hx1 : 0 < s.running.countP (·.id == x.id) := countP_pos_of_mem hx (by simp)
    rcases hF.runOk x hx with hc | hc
    · rcases hcur' x.id hc (by omega) with h | h
      · exact Or.inl h
      · exact Or.inr (by omega)
    · exact Or.inr (by omega)

theorem fr_init : Fr init :=
  ⟨fun _ _ h => (nomatch h), fun _ h => (nomatch h), fun _ h => (nomatch h),
   fun _ => Nat.zero_le _, fun _ _ => rfl, trivial, fun _ h => (nomatch h), rfl⟩


/-- `Fr` reads only `rs`, the pipe, the port, its output, `sent` and
`stale`. -/
theorem fr_congr {s t : St} (h1 : t.rs = s.rs) (h2 : t.pipe = s.pipe)
    (h3 : t.running = s.running) (h4 : t.out = s.out) (h5 : t.sent = s.sent)
    (h6 : t.stale = s.stale) (hF : Fr s) : Fr t := by
  have hc : isCur t = isCur s := by funext id; simp [isCur, h1]
  have ht : tokens t = tokens s := by funext id; simp [tokens, h2, h3, h4]
  obtain ⟨a, b, c, d, e, f, g, k⟩ := hF
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩ <;>
    simp only [hc, ht, h2, h3, h4, h5, h6] <;> assumption

theorem reqs_single (id i : Id) (n : Nat) : reqs id [.req i n] = if i = id then 1 else 0 := by
  simp

theorem fr_step {P : Params} (hf : P.fresh = true) {s t : St} (hG : Gen P s) (hF : Fr s)
    (h : Step P s t) : Fr t := by
  cases h with
  | admit r hr =>
    have hs0 := hG.sentNew r hr
    refine fr_frame (r := r) (q := [.req (pid P r 0) 0]) hF (fun x hx => by simp [upd, hx])
      rfl rfl (fun _ h => h) (fun _ => Nat.le_refl _) hF.noStale ?_ ?_ ?_ ?_ ?_ ?_
    · intro x; by_cases e : x = r
      · subst e; simp [upd, hs0]
      · simp [upd, e]
    · intro id n h; simp [pid_fresh hf] at h; obtain ⟨rfl, rfl⟩ := h; rfl
    · exact ⟨Or.inl ⟨s.toks r + 1, by simp [pid_fresh hf, upd]⟩, trivial⟩
    · intro id hq
      rw [reqs_single] at hq ⊢
      split at hq
      · next e => subst e; simp [pid_fresh hf]; exact hF.unborn _ (by simp [hs0])
      · omega
    · intro id hle
      rw [reqs_single]; split
      · next e => subst e; simp [pid_fresh hf, upd] at hle
      · rfl
    · intro id e hc; obtain ⟨tr, h⟩ := hc; rw [e, hr] at h; cases h
  | portReq id n rest hp =>
    have hok := hF.pipeOk; rw [hp] at hok
    refine ⟨?_, ?_, hF.outN, ?_, ?_, hok.2, ?_, hF.noStale⟩
    · intro i m h; exact hF.pipeN i m (by rw [hp]; exact List.mem_cons_of_mem _ h)
    · intro x hx; rw [List.mem_append] at hx
      rcases hx with hx | hx
      · exact hF.runN x hx
      · simp at hx; subst hx; exact hF.pipeN id n (by rw [hp]; simp)
    · intro i; have := hF.uniq i
      by_cases e : id = i <;> simp [tokens, hp, e] at this ⊢ <;> omega
    · intro i hle; have := hF.unborn i hle
      by_cases e : id = i <;> simp [tokens, hp, e] at this ⊢ <;> omega
    · intro x hx; rw [List.mem_append] at hx
      rcases hx with hx | hx
      · rcases hF.runOk x hx with h | h
        · exact Or.inl h
        · rw [hp] at h; exact Or.inr (by simpa using h)
      · simp at hx; subst hx; exact hok.1
  | portCancel id rest hp =>
    have hok := hF.pipeOk; rw [hp] at hok
    have hle : ∀ i, reqs i rest + (s.running.filter (fun x => x.id ≠ id)).countP (·.id == i)
        + s.out.countP (·.id == i) ≤ tokens s i := by
      intro i
      have := (List.filter_sublist (p := fun x : Xfer => decide (x.id ≠ id))
        (l := s.running)).countP_le (p := (·.id == i))
      simp only [tokens, hp, reqs_cancel]; omega
    refine ⟨?_, ?_, hF.outN, ?_, ?_, hok, ?_, hF.noStale⟩
    · intro i m h; exact hF.pipeN i m (by rw [hp]; exact List.mem_cons_of_mem _ h)
    · intro x hx; exact hF.runN x (List.mem_filter.mp hx).1
    · intro i; have := hF.uniq i; have := hle i; simp only [tokens] at *; omega
    · intro i h; have := hF.unborn i h; have := hle i; simp only [tokens] at *; omega
    · intro x hx
      obtain ⟨hx, hne⟩ := List.mem_filter.mp hx
      rcases hF.runOk x hx with h | h
      · exact Or.inl h
      · rw [hp, cancels_cancel] at h
        have : id ≠ x.id := fun e => by simp [e] at hne
        exact Or.inr (by simpa [this] using h)
  | portEnd l1 l2 x retry hr =>
    have hx : x ∈ s.running := by rw [hr]; simp
    have hsub : ∀ y ∈ l1 ++ l2, y ∈ s.running := by
      intro y hy; rw [hr]; simp at hy ⊢; rcases hy with h | h <;> simp [h]
    refine ⟨hF.pipeN, fun y hy => hF.runN y (hsub y hy), ?_, ?_, ?_, hF.pipeOk,
      fun y hy => hF.runOk y (hsub y hy), hF.noStale⟩
    · intro m hm; rw [List.mem_append] at hm
      rcases hm with hm | hm
      · exact hF.outN m hm
      · simp at hm; subst hm; exact hF.runN x hx
    · intro i; have := hF.uniq i
      by_cases e : x.id = i <;> simp [tokens, hr, e] at this ⊢ <;> omega
    · intro i hle; have := hF.unborn i hle
      by_cases e : x.id = i <;> simp [tokens, hr, e] at this ⊢ <;> omega
  | fire => exact fr_congr (s := s) rfl rfl rfl rfl rfl rfl hF
  | reqTimeoutDrop => exact fr_congr (s := s) rfl rfl rfl rfl rfl rfl hF
  | retryDrop => exact fr_congr (s := s) rfl rfl rfl rfl rfl rfl hF
  | callerCancel => exact fr_congr (s := s) rfl rfl rfl rfl rfl rfl hF
  | workerCancelDrop => exact fr_congr (s := s) rfl rfl rfl rfl rfl rfl hF
  | workerOutDrop l1 l2 m ho _ =>
    refine fr_frame (r := 0) (q := []) hF (fun _ _ => rfl) (by simp) rfl ?_ ?_ hF.noStale
      (fun _ => Nat.le_refl _) (fun _ _ h => by simp at h) trivial
      (fun _ h => by simp at h) (fun _ _ => rfl) (fun _ _ hc _ => Or.inl hc)
    · intro m' h; rw [ho]; simp at h ⊢; rcases h with h | h <;> simp [h]
    · intro i; simp [ho, List.countP_append, List.countP_cons] <;> (try split) <;> omega
  | workerOutCur l1 l2 m c tr ho hr hpid =>
    have hm : m ∈ s.out := by rw [ho]; simp
    have hid : m.id = ⟨m.id.r, c⟩ := by rw [← hpid, pid_fresh hf]
    have hmn : m.n = c := by have := hF.outN m hm; rw [hid] at this; exact this.symm
    refine fr_frame (r := m.id.r) (q := []) hF
      (fun x hx => by rw [rr_rs_ne _ _ _ _ _ _ x hx]) (by simp) (by simp) ?_ ?_
      (by simp [hF.noStale, hmn]) (fun _ => by simp) (fun _ _ h => by simp at h) trivial
      (fun _ h => by simp at h) (fun _ _ => rfl) ?_
    · intro m' h; simp at h; rw [ho]; simp; rcases h with h | h <;> simp [h]
    · intro i; simp [ho, List.countP_append, List.countP_cons] <;> (try split) <;> omega
    · intro id e hc hp
      exfalso
      obtain ⟨tr', h'⟩ := hc
      rw [e, hr] at h'; injection h' with _ hn
      have hi : id = m.id := Id.ext' e (by rw [hid]; exact hn.symm)
      have := hF.uniq id
      have hpos : 0 < s.out.countP (·.id == id) := countP_pos_of_mem hm (by simp [hi])
      simp only [tokens] at this; omega
  | reqTimeout tm c tr _ _ hr _ =>
    refine fr_frame (r := tm.r) (q := [.cancel (pid P tm.r c)]) hF
      (fun x hx => by rw [rr_rs_ne _ _ _ _ _ _ x hx]) (by simp) (by simp) (fun _ h => by simpa using h)
      (fun _ => by simp) (by simp [hF.noStale]) (fun _ => by simp) (fun _ _ h => by simp at h)
      trivial (fun _ h => by simp at h) (fun _ _ => by simp) ?_
    · intro id e hc _
      obtain ⟨tr', h'⟩ := hc
      rw [e, hr] at h'; cases h'
      have hi : pid P tm.r id.n = id := by rw [pid_fresh hf]; cases id; simp_all
      right; rw [hi]; simp [cancels]
  | retry tm c tr _ _ hr _ =>
    have hs := (hG.sentHeld _ _ _ _ hr).1
    refine fr_frame (r := tm.r) (q := [.req (pid P tm.r (c + 1)) (c + 1)]) hF
      (fun x hx => by simp [upd, hx]) rfl rfl (fun _ h => h) (fun _ => Nat.le_refl _)
      hF.noStale ?_ ?_ ?_ ?_ ?_ ?_
    · intro x; by_cases e : x = tm.r
      · subst e; simp [upd]
      · simp [upd, e]
    · intro id n h; simp [pid_fresh hf] at h; obtain ⟨rfl, rfl⟩ := h; rfl
    · exact ⟨Or.inl ⟨s.toks tm.r + 1, by simp [pid_fresh hf, upd]⟩, trivial⟩
    · intro id hq
      rw [reqs_single] at hq ⊢
      split at hq
      · next e => subst e; simp [pid_fresh hf]; exact hF.unborn _ (by simp [hs])
      · omega
    · intro id hle
      rw [reqs_single]; split
      · next e => exfalso; subst e; simp [pid_fresh hf, upd, hs] at hle; omega
      · rfl
    · intro id e hc; obtain ⟨tr', h⟩ := hc; rw [e, hr] at h; cases h
  | workerCancel r m c tr _ hr =>
    cases m with
    | attempt =>
      refine fr_frame (r := r) (q := [.cancel (pid P r c)]) hF
        (fun x hx => by simp [upd, hx]) (by simp) rfl (fun _ h => h) (fun _ => Nat.le_refl _)
        hF.noStale (fun _ => Nat.le_refl _) (fun _ _ h => by simp at h) trivial
        (fun _ h => by simp at h) (fun _ _ => by simp) ?_
      intro id e hc _
      obtain ⟨tr', h'⟩ := hc
      rw [e, hr] at h'; cases h'
      have hi : pid P r id.n = id := by rw [pid_fresh hf]; cases id; simp_all
      right; rw [hi]; simp [cancels]
    | backoff =>
      refine fr_frame (r := r) (q := []) hF
        (fun x hx => by simp [upd, hx]) (by simp) rfl (fun _ h => h) (fun _ => Nat.le_refl _)
        hF.noStale (fun _ => Nat.le_refl _) (fun _ _ h => by simp at h) trivial
        (fun _ h => by simp at h) (fun _ _ => rfl) ?_
      intro id e hc; obtain ⟨tr', h⟩ := hc; rw [e, hr] at h; cases h

theorem fr_reach {P : Params} (hf : P.fresh = true) {s : St} (h : Reach P s) : Fr s := by
  induction h with
  | init => exact fr_init
  | step hr hs ih => exact fr_step hf (gen_reach hr) ih hs

end KatipoProofs.Retry
