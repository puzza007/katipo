import KatipoProofs.Upload.Model

/-!
# Streaming request bodies: safety proofs

Each property is an inductive invariant, proved preserved by every `Step`
and lifted to `Reach`. Headline statements are in `Upload/Statements.lean`.
-/

namespace KatipoProofs.Upload

@[simp] theorem cnt_nil {α : Type} [DecidableEq α] (x : α) : cnt x [] = 0 := rfl

@[simp] theorem cnt_cons {α : Type} [DecidableEq α] (x m : α) (ms : List α) :
    cnt x (m :: ms) = (if m = x then 1 else 0) + cnt x ms := rfl

@[simp] theorem cnt_append {α : Type} [DecidableEq α] (x : α) (l m : List α) :
    cnt x (l ++ m) = cnt x l + cnt x m := by
  induction l with
  | nil => simp
  | cons a l ih => simp [ih]; omega

@[simp] theorem cntBody_nil (b : Body) : cntBody b [] = 0 := rfl

@[simp] theorem cntBody_body (b b' : Body) (q : List Cmd) :
    cntBody b (.body b' :: q) = (if b' = b then 1 else 0) + cntBody b q := by
  simp [cntBody]

@[simp] theorem cntBody_flow (b : Body) (n : Nat) (q : List Cmd) :
    cntBody b (.flow n :: q) = cntBody b q := by simp [cntBody]

@[simp] theorem cntBody_cancel (b : Body) (q : List Cmd) :
    cntBody b (.cancel :: q) = cntBody b q := by simp [cntBody]

@[simp] theorem cntBody_append (b : Body) (l m : List Cmd) :
    cntBody b (l ++ m) = cntBody b l + cntBody b m := by simp [cntBody]

@[simp] theorem accept_sentN (P : Params) (s : St) (b : Body) (r : List Cmd) :
    (accept P s b r).sentN = s.sentN := rfl
@[simp] theorem accept_sentEof (P : Params) (s : St) (b : Body) (r : List Cmd) :
    (accept P s b r).sentEof = s.sentEof := rfl
@[simp] theorem accept_bodyQ (P : Params) (s : St) (b : Body) (r : List Cmd) :
    (accept P s b r).bodyQ = s.bodyQ := rfl
@[simp] theorem accept_pQ (P : Params) (s : St) (b : Body) (r : List Cmd) :
    (accept P s b r).pQ = r := rfl
@[simp] theorem accept_live (P : Params) (s : St) (b : Body) (r : List Cmd) :
    (accept P s b r).live = s.live := rfl
@[simp] theorem accept_readN (P : Params) (s : St) (b : Body) (r : List Cmd) :
    (accept P s b r).readN = s.readN := rfl
@[simp] theorem accept_uploadDone (P : Params) (s : St) (b : Body) (r : List Cmd) :
    (accept P s b r).uploadDone = s.uploadDone := rfl
@[simp] theorem accept_eofIn (P : Params) (s : St) (b : Body) (r : List Cmd) :
    (accept P s b r).eofIn = (s.eofIn || b == .eof) := rfl

/-- A body of the right length is buffered as before the length check. -/
theorem accept_eq {P : Params} {s : St} {b : Body} (r : List Cmd) (hw : wrong P s b = false) :
    accept P s b r = { s with pQ := r, buf := if b = .data then s.buf + 1 else s.buf,
                              eofIn := s.eofIn || b == .eof, upFailed := false,
                              demanded := false } := by
  cases b <;> simp_all [accept]

/-! ## Body conservation -/

/-- `BodyConserved`. -/
def Cons (s : St) : Prop :=
  s.inReqs = true → s.live = true → s.readN + inFlight s = s.sentN

/-! ## Pause flags (masked resume) -/

/-- `SendPausedAgrees` and `RecvPausedAgrees`, strengthened to hold inside
`curl_easy_pause` too. -/
def Agree (s : St) : Prop := s.upPaused = s.curlSendPaused ∧ s.paused = s.curlRecvPaused

theorem agree_step {P : Params} (hm : P.masked = true) {s t : St} (hI : Agree s)
    (h : Step P s t) : Agree t := by
  obtain ⟨h1, h2⟩ := hI
  cases h <;> simp_all [Agree, accept, recv]

theorem agree_reach {P : Params} (hm : P.masked = true) {s : St} (h : Reach P s) :
    Agree s := by
  induction h with
  | init => simp [Agree, init]
  | step _ hs ih => exact agree_step hm ih hs

/-! ## Protocol order -/

/-- A `done` or `error` in the worker -> caller queue is its last message. -/
def termLast : List Msg → Prop
  | [] => True
  | m :: ms => ((m = .done ∨ m = .error) → ms = []) ∧ termLast ms

theorem termLast_append (l : List Msg) (m : Msg) (hl : termLast l)
    (hd : cnt .done l = 0) (he : cnt .error l = 0) : termLast (l ++ [m]) := by
  induction l with
  | nil => simp [termLast]
  | cons a l ih =>
    simp only [cnt_cons] at hd he
    have ha : a ≠ .done ∧ a ≠ .error := by
      constructor <;> intro hx <;> simp_all
    simp only [termLast] at hl ⊢
    exact ⟨fun hx => by cases hx <;> simp_all, ih hl.2 (by omega) (by omega)⟩

/-- Why `ProtocolOrder` holds: a terminal message, queued or seen, means the
worker has let go of the request, so nothing more is queued behind it. -/
structure Ord (s : St) : Prop where
  noBad : s.orderBad = false
  seenEmpty : terminal s = true → s.toC = []
  letGo : (0 < cnt .done s.toC + cnt .error s.toC ∨ terminal s = true) → s.inReqs = false
  last : termLast s.toC

theorem ord_init (P : Params) : Ord (init P) :=
  ⟨rfl, by simp [terminal, init], by simp [terminal, init], by simp [termLast, init]⟩

theorem ord_step {P : Params} {s t : St} (hI : Ord s) (h : Step P s t) : Ord t := by
  obtain ⟨o1, o2, o3, o4⟩ := hI
  cases h with
  | workerFwd m rest h1 h2 =>
    have hd : cnt .done s.toC = 0 := by
      cases hx : cnt .done s.toC with
      | zero => rfl
      | succ k => have := o3 (Or.inl (by omega)); simp_all
    have he : cnt .error s.toC = 0 := by
      cases hx : cnt .error s.toC with
      | zero => rfl
      | succ k => have := o3 (Or.inl (by omega)); simp_all
    have ht : terminal s = false := by
      cases hx : terminal s with
      | false => rfl
      | true => have := o3 (Or.inr hx); simp_all
    refine ⟨o1, ?_, ?_, termLast_append _ _ o4 hd he⟩
    · intro hx; simp_all [terminal]
    · intro _; cases m <;> simp_all [terminal]
  | workerTimeout h1 h2 =>
    have hd : cnt .done s.toC = 0 := by
      cases hx : cnt .done s.toC with
      | zero => rfl
      | succ k => have := o3 (Or.inl (by omega)); simp_all
    have he : cnt .error s.toC = 0 := by
      cases hx : cnt .error s.toC with
      | zero => rfl
      | succ k => have := o3 (Or.inl (by omega)); simp_all
    have ht : terminal s = false := by
      cases hx : terminal s with
      | false => rfl
      | true => have := o3 (Or.inr hx); simp_all
    refine ⟨o1, ?_, fun _ => rfl, termLast_append _ _ o4 hd he⟩
    intro hx; simp_all [terminal]
  | callerRecv m rest h1 =>
    have ht : terminal s = false := by
      cases hx : terminal s with
      | false => rfl
      | true => have := o2 hx; simp_all
    rw [h1] at o3 o4
    simp only [termLast] at o4
    refine ⟨by simp [recv, o1, ht], ?_, ?_, o4.2⟩
    · intro hx
      simp only [recv, terminal] at hx ⊢
      simp only [terminal] at ht
      cases m <;> simp_all
    · intro hx
      simp only [recv, terminal] at hx ⊢
      simp only [terminal] at ht
      apply o3
      cases m <;> simp_all <;> omega
  | workerCancel h1 =>
    exact ⟨o1, o2, fun _ => rfl, o4⟩
  | _ => exact ⟨o1, o2, o3, o4⟩

theorem ord_reach {P : Params} {s : St} (h : Reach P s) : Ord s := by
  induction h with
  | init => exact ord_init P
  | step _ hs ih => exact ord_step ih hs

/-! ## The body completes in full -/

/-- In the caller -> worker queue, an eof is the last message. -/
def eofLastB : List Body → Prop
  | [] => True
  | b :: bs => (b = .eof → bs = []) ∧ eofLastB bs

/-- In the worker -> port queue, no body message follows an eof. -/
def eofLastP : List Cmd → Prop
  | [] => True
  | c :: cs => (c = .body .eof → cntBody .data cs = 0 ∧ cntBody .eof cs = 0) ∧ eofLastP cs

theorem eofLastB_append (l : List Body) (b : Body) (hl : eofLastB l)
    (he : cnt .eof l = 0) : eofLastB (l ++ [b]) := by
  induction l with
  | nil => simp [eofLastB]
  | cons a l ih =>
    simp only [cnt_cons] at he
    simp only [eofLastB] at hl ⊢
    exact ⟨fun hx => by simp_all, ih hl.2 (by omega)⟩

theorem eofLastP_append (l : List Cmd) (c : Cmd) (hl : eofLastP l)
    (h : cntBody .eof l = 0 ∨ (c ≠ .body .data ∧ c ≠ .body .eof)) :
    eofLastP (l ++ [c]) := by
  induction l with
  | nil => simp [eofLastP, cntBody]
  | cons a l ih =>
    simp only [List.cons_append, eofLastP] at hl ⊢
    refine ⟨fun hx => ?_, ih hl.2 ?_⟩
    · subst hx
      rcases h with h | ⟨h1, h2⟩
      · simp [cntBody] at h
      · obtain ⟨hd, he⟩ := hl.1 rfl
        simp only [cntBody, cnt_append, cnt_cons, cnt_nil] at hd he ⊢
        simp [h1, h2, hd, he]
    · rcases h with h | h
      · left; simp only [cntBody, cnt_cons] at h ⊢; omega
      · right; exact h

theorem eofLastP_tail (c : Cmd) (l : List Cmd) (h : eofLastP (c :: l)) : eofLastP l := h.2

/-- Why `CompleteBody` holds: the caller's eof follows its last chunk down
FIFO queues, so by the time it reaches the port every chunk is buffered
or read. -/
structure Eof (P : Params) (s : St) : Prop where
  sentLe : s.sentN ≤ P.total
  sentAll : s.sentEof = true → s.sentN = P.total
  noEofYet : s.sentEof = false →
    cnt .eof s.bodyQ = 0 ∧ cntBody .eof s.pQ = 0 ∧ s.eofIn = false
  lastB : eofLastB s.bodyQ
  lastP : eofLastP s.pQ
  eofP : 0 < cntBody .eof s.pQ → cnt .data s.bodyQ = 0 ∧ cnt .eof s.bodyQ = 0
  eofIn : s.eofIn = true → cnt .data s.bodyQ = 0 ∧ cnt .eof s.bodyQ = 0 ∧
    cntBody .data s.pQ = 0 ∧ cntBody .eof s.pQ = 0
  sum : s.live = true → (0 < cntBody .eof s.pQ ∨ s.eofIn = true) →
    s.readN + cntBody .data s.pQ + s.buf = P.total
  done : s.uploadDone = true → s.readN = P.total ∧ (P.length = true ∨ s.sentEof = true)

/-- What an honest caller's body keeps true beyond `Eof`: nothing after eof,
nothing taken that was not sent, no failed upload, and with a declared
length the upload completes on its last chunk. -/
structure Hon (P : Params) (s : St) : Prop where
  noLate : s.lateN = 0
  le : s.readN + s.buf + cntBody .data s.pQ + cnt .data s.bodyQ ≤ s.sentN
  noFail : s.upFailed = false
  lenDone : P.length = true → s.readN = P.total → s.uploadDone = true

/-- An honest caller's body is never the wrong length: a chunk arrives
before the length is all in, and eof only once it is. -/
theorem wrong_false {P : Params} {s : St} {b : Body} {rest : List Cmd} (hE : Eof P s)
    (hH : Hon P s) (hl : s.live = true) (hq : s.pQ = .body b :: rest) : wrong P s b = false := by
  cases b with
  | data =>
    have h1 := hH.le; have h2 := hE.sentLe
    rw [hq] at h1; simp at h1
    cases hlen : P.length <;> simp [wrong, hlen] <;> omega
  | eof =>
    have h3 := hE.sum hl (Or.inl (by rw [hq]; simp; omega))
    have h4 := hE.lastP; rw [hq] at h4 h3
    have h5 : cntBody .data rest = 0 := (h4.1 rfl).1
    simp at h3
    cases hlen : P.length <;> simp [wrong, hlen] <;> omega

theorem eof_init (P : Params) : Eof P (init P) := by
  constructor <;> simp_all [init, cntBody, eofLastB, eofLastP]

theorem eof_step {P : Params} (hlr : P.liar = false) {s t : St} (hC : Cons s) (hH : Hon P s)
    (hI : Eof P s) (h : Step P s t) : Eof P t := by
  obtain ⟨e1, e2, e3, e4, e5, e6, e7, e8, e9⟩ := hI
  have sentOfEofIn : s.eofIn = true → s.sentEof = true := fun hx => by
    cases hs : s.sentEof
    · have := (e3 hs).2.2; simp_all
    · rfl
  have sentOfEofP : 0 < cntBody .eof s.pQ → s.sentEof = true := fun hx => by
    cases hs : s.sentEof
    · have := (e3 hs).2.1; omega
    · rfl
  cases h with
  | readData h1 h2 h3 h4 h5 =>
    exact ⟨e1, e2, e3, e4, e5, e6, e7, fun hl hx => by dsimp only at hx ⊢; have := e8 h1 hx; omega,
      fun hx => by simp at hx ⊢; exact ⟨by omega, Or.inl hx.1⟩⟩
  | readEof h1 h2 h3 h4 h5 h6 =>
    refine ⟨e1, e2, e3, e4, e5, e6, e7, e8, fun _ => ⟨?_, Or.inr (sentOfEofIn h6)⟩⟩
    have := e8 h1 (Or.inr h6); have := (e7 h6).2.2.1; dsimp only; omega
  | bodyIgnored b rest h1 h2 h3 h4 =>
    have hi : s.eofIn = true := by simpa [hH.noFail] using h4
    have := e7 hi; rw [h2] at this
    cases b <;> simp at this
  | lieExtra h1 | lieShort h1 | lieLate h1 => simp_all
  | bodyRun b rest h1 h2 h3 h4 h5 h6 | bodyResume b rest h1 h2 h3 h4 h5 h6 =>
    rw [accept_eq rest (wrong_false ⟨e1, e2, e3, e4, e5, e6, e7, e8, e9⟩ hH h3 h2)]
    have l5 := e5; rw [h2] at l5; simp only [eofLastP] at l5
    cases b with
    | data =>
      have hE : cntBody .eof s.pQ = cntBody .eof rest := by simp [h2]
      have hD : cntBody .data s.pQ = cntBody .data rest + 1 := by simp [h2]; omega
      have ne : s.eofIn = false := by
        cases hx : s.eofIn with
        | false => rfl
        | true => have := (e7 hx).2.2.1; omega
      refine ⟨e1, e2, fun hs => ?_, e4, l5.2, fun hx => ?_, fun hx => ?_,
        fun hl hx => ?_, e9⟩
      · dsimp only at hs ⊢; have := e3 hs; rw [hE] at this; simp [this.1, this.2.1, ne]
      · dsimp only at hx ⊢; rw [← hE] at hx; exact e6 hx
      · dsimp only at hx; simp [ne] at hx
      · dsimp only at hx hl ⊢; simp [ne] at hx hl
        have := e8 hl (Or.inl (by rw [hE]; exact hx)); rw [ite_eq_left rfl]; omega
    | eof =>
      have hE : cntBody .eof s.pQ = cntBody .eof rest + 1 := by simp [h2]; omega
      have hD : cntBody .data s.pQ = cntBody .data rest := by simp [h2]
      have hr := l5.1 rfl
      have hs := sentOfEofP (by omega)
      have h6 := e6 (by omega)
      have hr2 := hr.2
      refine ⟨e1, e2, fun hx => by dsimp only at hx; simp_all, e4, l5.2,
        fun hx => by dsimp only at hx; omega, fun _ => ?_, fun hl _ => ?_, e9⟩
      · exact ⟨h6.1, h6.2, hr.1, hr.2⟩
      · dsimp only; have := e8 h3 (Or.inl (by omega)); simp; omega
  | workerBody b rest h1 =>
    rw [h1] at e3 e4 e6 e7
    simp only [eofLastB, cnt_cons] at e3 e4 e6 e7
    cases hi : s.inReqs with
    | false =>
      refine ⟨e1, e2, ?_, e4.2, e5, ?_, ?_, e8, e9⟩
      · intro hs; have := e3 hs; simp_all <;> omega
      · intro hx; have := e6 hx; simp_all <;> omega
      · intro hx; have := e7 hx; simp_all <;> omega
    | true =>
      simp only [↓reduceIte]
      cases b with
      | data =>
        have np : cntBody .eof s.pQ = 0 := by
          cases hx : cntBody .eof s.pQ with
          | zero => rfl
          | succ k => have := e6 (by omega); simp at this
        have ni : s.eofIn = false := by
          cases hx : s.eofIn with
          | false => rfl
          | true => have := e7 hx; simp at this
        refine ⟨e1, e2, ?_, e4.2, eofLastP_append _ _ e5 (Or.inl np), ?_, ?_, ?_, e9⟩
        · intro hs; have := e3 hs; simp_all [cntBody]
        · intro hx; simp_all [cntBody]
        · intro hx; simp_all
        · intro hl hx; simp_all [cntBody]
      | eof =>
        have rest0 : rest = [] := e4.1 rfl
        subst rest0
        have hs : s.sentEof = true := by
          cases hx : s.sentEof
          · have := (e3 hx).1; simp at this
          · rfl
        have np : cntBody .eof s.pQ = 0 := by
          cases hx : cntBody .eof s.pQ with
          | zero => rfl
          | succ k => have := e6 (by omega); simp at this
        refine ⟨e1, e2, by simp_all, by simp [eofLastB], eofLastP_append _ _ e5 (Or.inl np),
          by simp, ?_, ?_, e9⟩
        · intro hx; have := e7 hx; simp at this
        · intro hl _
          have hc := hC hi hl
          simp only [inFlight, h1, cnt_cons, cntBody] at hc
          have := e2 hs
          dsimp only; simp [cntBody] at hc ⊢; omega
  | callerData h1 h2 h3 h4 =>
    have := e3 h1
    refine ⟨by simp; omega, by simp_all, ?_, eofLastB_append _ _ e4 this.1, e5, ?_, ?_, ?_, ?_⟩
    · intro _; simp_all
    · intro hx; simp_all [cntBody]
    · intro hx; simp_all
    · intro hl hx; simp_all [cntBody]
    · intro hx; have := e9 hx; simp_all
  | callerEof h1 h2 h3 h4 =>
    have := e3 h1
    refine ⟨e1, fun _ => by simp; omega, by simp, eofLastB_append _ _ e4 this.1, e5, ?_, ?_,
      e8, fun hx => by have := e9 hx; simp_all⟩
    · intro hx; simp_all [cntBody]
    · intro hx; simp_all
  | workerFlow n rest h1 =>
    have hp : ∀ q : List Cmd, cntBody .data (q ++ [.flow n]) = cntBody .data q ∧
        cntBody .eof (q ++ [.flow n]) = cntBody .eof q := by intro q; simp [cntBody]
    cases hi : s.inReqs <;>
      simp only [ite_true, ite_false, Bool.false_eq_true] <;>
      first
      | exact ⟨e1, e2, e3, e4, e5, e6, e7, e8, e9⟩
      | exact ⟨e1, e2, by simpa [hp] using e3, e4,
          eofLastP_append _ _ e5 (Or.inr ⟨by simp, by simp⟩), by simpa [hp] using e6,
          by simpa [hp] using e7, by simpa [hp] using e8, e9⟩
  | workerCancel h1 =>
    have hp : ∀ q : List Cmd, cntBody .data (q ++ [.cancel]) = cntBody .data q ∧
        cntBody .eof (q ++ [.cancel]) = cntBody .eof q := by intro q; simp [cntBody]
    cases hi : s.inReqs <;>
      simp only [ite_true, ite_false, Bool.false_eq_true] <;>
      first
      | exact ⟨e1, e2, e3, e4, e5, e6, e7, e8, e9⟩
      | exact ⟨e1, e2, by simpa [hp] using e3, e4,
          eofLastP_append _ _ e5 (Or.inr ⟨by simp, by simp⟩), by simpa [hp] using e6,
          by simpa [hp] using e7, by simpa [hp] using e8, e9⟩
  | workerTimeout h1 h2 =>
    have hp : ∀ q : List Cmd, cntBody .data (q ++ [.cancel]) = cntBody .data q ∧
        cntBody .eof (q ++ [.cancel]) = cntBody .eof q := by intro q; simp [cntBody]
    exact ⟨e1, e2, by simpa [hp] using e3, e4,
      eofLastP_append _ _ e5 (Or.inr ⟨by simp, by simp⟩), by simpa [hp] using e6,
      by simpa [hp] using e7, by simpa [hp] using e8, e9⟩
  | bodyDead b rest h1 h2 h3 =>
    have l5 := e5; rw [h2] at l5
    have hd : cntBody .data rest ≤ cntBody .data s.pQ := by
      rw [h2]; simp only [cntBody, cnt_cons]; omega
    have he : cntBody .eof rest ≤ cntBody .eof s.pQ := by
      rw [h2]; simp only [cntBody, cnt_cons]; omega
    refine ⟨e1, e2, fun hs => ?_, e4, l5.2, fun hx => e6 (by dsimp only at hx; omega),
      fun hx => ?_, fun hl => by simp_all, e9⟩
    · dsimp only at hs ⊢; have := e3 hs; exact ⟨this.1, by omega, this.2.2⟩
    · dsimp only at hx ⊢; have := e7 hx; exact ⟨this.1, this.2.1, by omega, by omega⟩
  | flowDead n rest h1 h2 h3 | flowRun n rest h1 h2 h3 _ | flowResume n rest h1 h2 h3 _ =>
    have l5 := e5; rw [h2] at l5
    have hc : ∀ x, cntBody x rest = cntBody x s.pQ := by
      intro x; rw [h2]; simp [cntBody]
    exact ⟨e1, e2, by simpa [hc] using e3, e4, l5.2, by simpa [hc] using e6,
      by simpa [hc] using e7, by simpa [hc] using e8, e9⟩
  | portCancel rest h1 h2 =>
    have l5 := e5; rw [h2] at l5
    have hc : ∀ x, cntBody x rest = cntBody x s.pQ := by
      intro x; rw [h2]; simp [cntBody]
    exact ⟨e1, e2, by simpa [hc] using e3, e4, l5.2, by simpa [hc] using e6,
      by simpa [hc] using e7, fun hl => by simp at hl, e9⟩
  | _ => constructor <;> simp_all [recv]


/-! ## An honest caller -/

theorem hon_init (P : Params) : Hon P (init P) :=
  ⟨rfl, by simp [init, cntBody], rfl, fun hl h0 => by simp_all [init]⟩

theorem hon_step {P : Params} (hlr : P.liar = false) {s t : St} (hE : Eof P s) (hI : Hon P s)
    (h : Step P s t) : Hon P t := by
  obtain ⟨n1, n2, n3, n4⟩ := hI
  cases h with
  | readData h1 h2 h3 h4 h5 =>
    refine ⟨n1, by dsimp only; omega, n3, fun hl hx => ?_⟩
    simp only at hx ⊢; simp [hl, hx]
  | bodyRun b rest h1 h2 h3 h4 h5 h6 | bodyResume b rest h1 h2 h3 h4 h5 h6 =>
    have hw := wrong_false hE ⟨n1, n2, n3, n4⟩ h3 h2
    rw [accept_eq rest hw]
    rw [h2] at n2
    refine ⟨n1, ?_, rfl, n4⟩
    cases b <;> simp at n2 ⊢ <;> omega
  | bodyIgnored b rest h1 h2 h3 h4 =>
    rw [h2] at n2
    refine ⟨n1, ?_, n3, n4⟩
    cases b <;> simp at n2 ⊢ <;> omega
  | bodyDead b rest h1 h2 h3 =>
    rw [h2] at n2
    refine ⟨n1, ?_, n3, n4⟩
    cases b <;> simp at n2 ⊢ <;> omega
  | workerBody b rest h1 =>
    rw [h1] at n2
    refine ⟨n1, ?_, n3, n4⟩
    cases hi : s.inReqs <;> cases b <;> simp at n2 ⊢ <;> omega
  | callerData => exact ⟨n1, by simp; omega, n3, n4⟩
  | lieExtra h1 | lieShort h1 | lieLate h1 => simp_all
  | flowDead n rest h1 h2 | flowRun n rest h1 h2 | flowResume n rest h1 h2 | portCancel rest h1 h2 =>
    rw [h2] at n2; exact ⟨n1, by simpa using n2, n3, n4⟩
  | workerFlow | workerCancel | workerTimeout =>
    refine ⟨n1, ?_, n3, n4⟩
    first | (cases hi : s.inReqs <;> simp <;> omega) | (simp; omega)
  | _ => refine ⟨?_, ?_, ?_, ?_⟩ <;> first | simp_all [recv] | (simp_all [recv]; omega)

theorem cons_step {P : Params} (hlr : P.liar = false) {s t : St} (hI : Cons s) (hE : Eof P s)
    (hH : Hon P s) (h : Step P s t) : Cons t := by
  unfold Cons inFlight cntBody at hI ⊢
  cases h with
  | readData h1 h2 h3 h4 h5 =>
    intro hr hl; dsimp only at hr hl ⊢; have := hI hr hl; omega
  | bodyRun b rest h1 h2 h3 h4 h5 h6 =>
    rw [accept_eq rest (wrong_false hE hH h3 h2)]
    intro hr hl; dsimp only at hr hl ⊢; have := hI hr hl
    rw [h2] at this; cases b <;> simp at this ⊢ <;> omega
  | bodyResume b rest h1 h2 h3 h4 h5 h6 =>
    rw [accept_eq rest (wrong_false hE hH h3 h2)]
    intro hr hl; dsimp only at hr hl ⊢; have := hI hr hl
    rw [h2] at this; cases b <;> simp at this ⊢ <;> omega
  | bodyIgnored b rest h1 h2 h3 h4 =>
    have hi : s.eofIn = true := by simpa [hH.noFail] using h4
    have := hE.eofIn hi; rw [h2] at this
    cases b <;> simp at this
  | workerBody b rest h1 =>
    intro hr hl; dsimp only at hr hl ⊢; have := hI hr hl
    rw [h1] at this; simp only [hr, ite_true]; cases b <;> simp at this ⊢ <;> omega
  | callerData =>
    intro hr hl; dsimp only at hr hl ⊢; have := hI hr hl; simp; omega
  | callerEof =>
    intro hr hl; dsimp only at hr hl ⊢; have := hI hr hl; simpa using this
  | workerFwd m rest h1 h2 =>
    intro hr hl; dsimp only at hr hl ⊢; exact hI h2 hl
  | lieExtra h1 | lieShort h1 | lieLate h1 => simp_all
  | _ => intro hr hl; dsimp only [recv] at hr hl ⊢; first | exact hI hr hl | simp_all

/-- The honest caller's invariants hold together: each step of one leans on
the others before it. -/
theorem honest_reach {P : Params} (hlr : P.liar = false) {s : St} (h : Reach P s) :
    Cons s ∧ Eof P s ∧ Hon P s := by
  induction h with
  | init => exact ⟨by simp [Cons, init, inFlight, cntBody], eof_init P, hon_init P⟩
  | step _ hs ih =>
    obtain ⟨hC, hE, hH⟩ := ih
    exact ⟨cons_step hlr hC hE hH hs, eof_step hlr hC hH hE hs, hon_step hlr hE hH hs⟩

/-! ## One chunk and one demand in flight -/

/-- Demands the caller could still answer: received and unanswered, on
their way to it, or (while the worker holds the request) on their way to
the worker. -/
def answerable (s : St) : Nat :=
  s.pending + cnt .demand s.toC + (if s.inReqs then cnt .demand s.toW else 0)

/-- What answers the port's demand: an answerable demand, or the chunk or
eof sent in answer, on its way to the port. -/
def tokens (s : St) : Nat :=
  answerable s + cnt .data s.bodyQ + cnt .eof s.bodyQ + cntBody .data s.pQ + cntBody .eof s.pQ

/-- Why one demand and one chunk: a demand is answered by exactly one
message, which is buffered (and read) before the next demand goes out.
Either the guard or the masked resume keeps a second from going out:
with the mask the upload stays paused until the answer comes. -/
structure Dem (P : Params) (s : St) : Prop where
  one : tokens s + s.buf ≤ 1
  idle : s.inReqs = true → s.live = true → s.demanded = false → tokens s = 0
  pausedWhileDemanded : P.masked = true → s.live = true → s.demanded = true →
    s.curlSendPaused = true

theorem dem_init (P : Params) : Dem P (init P) :=
  ⟨by simp [tokens, answerable, init], by simp [tokens, answerable, init],
   by simp [init]⟩

attribute [grind =] cnt_append cnt_cons cnt_nil cntBody_append cntBody_body
  cntBody_flow cntBody_cancel cntBody_nil

/-- Each field of `Dem` after a step: unfold the counts, then `grind`. -/
local macro "dem_tac" : tactic =>
  `(tactic| (refine ⟨?_, ?_, ?_⟩ <;>
    (try simp [tokens, answerable, accept, recv, demandOk] at *) <;> grind))

theorem dem_step {P : Params} (he : P.eager = false) (hlr : P.liar = false)
    (hg : P.guard = true ∨ P.masked = true) {s t : St} (hI : Dem P s) (h : Step P s t) :
    Dem P t := by
  obtain ⟨k1, k2, k3⟩ := hI
  cases h with
  | bodyRun b => cases b <;> dem_tac
  | bodyResume b => cases b <;> dem_tac
  | lieExtra h1 | lieShort h1 | lieLate h1 => simp_all
  | _ => dem_tac

theorem dem_reach {P : Params} (he : P.eager = false) (hlr : P.liar = false)
    (hg : P.guard = true ∨ P.masked = true) {s : St} (h : Reach P s) : Dem P s := by
  induction h with
  | init => exact dem_init P
  | step _ hs ih => exact dem_step he hlr hg ih hs

/-! ## Any caller: the declared length -/

/-- Why curl never gets more than the declared length, nor finishes the
upload with less, whatever the caller sends: the port takes a chunk only
while the length is not all in, and an eof short of it fails the upload. -/
structure Len (P : Params) (s : St) : Prop where
  gotLe : P.length = true → s.readN + s.buf ≤ P.total
  eofGot : P.length = true → s.eofIn = true → s.upFailed = false →
    s.readN + s.buf = P.total
  done : P.length = true → s.uploadDone = true → s.readN = P.total

theorem len_init (P : Params) : Len P (init P) :=
  ⟨by simp [init], by simp [init], fun _ hd => by simp_all [init]⟩

theorem len_step {P : Params} {s t : St} (hI : Len P s) (h : Step P s t) : Len P t := by
  obtain ⟨l1, l2, l3⟩ := hI
  cases h with
  | readData h1 h2 h3 h4 h5 =>
    refine ⟨fun hl => by have := l1 hl; dsimp only; omega,
      fun hl hi hf => by have := l2 hl hi hf; dsimp only at hi hf ⊢; omega,
      fun hl hd => by simp at hd; dsimp only; omega⟩
  | readEof h1 h2 h3 h4 h5 h6 =>
    exact ⟨l1, l2, fun hl _ => by have := l2 hl h6 h4; dsimp only; omega⟩
  | bodyRun b rest h1 h2 h3 h4 h5 h6 | bodyResume b rest h1 h2 h3 h4 h5 h6 =>
    refine ⟨fun hl => ?_, fun hl hi hf => ?_, fun hl hd => l3 hl (by simpa [accept] using hd)⟩ <;>
      have := l1 hl <;> cases b <;> simp_all [accept, wrong] <;> (try split) <;> omega
  | _ => refine ⟨?_, ?_, ?_⟩ <;> simp_all [recv]

theorem len_reach {P : Params} {s : St} (h : Reach P s) : Len P s := by
  induction h with
  | init => exact len_init P
  | step _ hs ih => exact len_step ih hs

end KatipoProofs.Upload
