import KatipoProofs.Admission.Proofs

/-!
# Trace validation: replaying recorded runs of the real code

`test/katipo_trace.erl` records what the caller (`katipo:attempt/3`,
`cancel/2`) and each pool worker (`katipo_worker`) actually did during a
test run. `check` replays one worker slot's events against the admission
model: each event becomes the `Step`s it corresponds to, and every branch
the code took must be the branch the model takes in that state -- a
delivery only for a request in `Reqs`, a refusal only past the deadline,
a `worker_died` notification for exactly the `Reqs` entries, each caller
outcome the one the model resolved.

`check` is correct by construction: it can only return a state together
with a proof that the state is `Reach`able. So an accepted trace is a run
of the model, and the headline theorems hold along it (`accepted_safe`).
A rejected trace is a disagreement between the code and the model.

## Environment steps the replay inserts
* `expire`: when the clock read at a deadline check says the deadline has
  passed, and otherwise just before a step that needs it (a refusal, or
  the caller's timeout).
* `emitResp`/`emitChunk`: just before the worker handles that message.
* `kill`: when a worker restarts, or a waiting caller sees `worker_died`,
  while the model's worker is still alive -- the worker died without
  running `terminate/2`.
* `sendLive` for a request sent while the model's worker was dead but
  handled by its next incarnation (the caller resolved the name after the
  restart): deferred to the restart.

Events with no model counterpart: a duplicate `cancel` from the caller is
ignored, and a worker's no-op cancel for a request not in `Reqs` is a
stutter.
-/

namespace KatipoProofs.Admission.Trace
open KatipoProofs.Admission

/-- The raw outcome of one admission call, before `katipo:attempt/3` folds
`expired` and a call timeout into `admission_timeout`. -/
inductive Res | ok | expired | timeout | died
  deriving DecidableEq, Repr

/-- One recorded event; `a` is the attempt (request) id. On the four
admission events, `late` is the wall clock read just before that deadline
check: whether the deadline had already passed. -/
inductive Ev
  | start
  | send (a : Nat)
  | result (a : Nat) (r : Res)
  | cancel (a : Nat)
  | pre (a : Nat) (late : Bool)
  | recv (a : Nat) (late : Bool)
  | post (a : Nat) (late : Bool)
  | admit (a : Nat) (late : Bool)
  | resp (a : Nat) (hit : Bool)
  | chunk (a : Nat) (hit : Bool)
  | wcancel (a : Nat) (hit : Bool)
  | crash (told : List Nat)
  deriving Repr

/-- The shipped protocol. -/
def P0 : Params := ⟨true, true, true⟩

theorem safe_P0 : Safe P0 := Or.inr ⟨rfl, rfl⟩

inductive Steps (P : Params) : St Nat → St Nat → Prop
  | refl (s : St Nat) : Steps P s s
  | tail {s t u : St Nat} : Steps P s t → Step P t u → Steps P s u

theorem Steps.trans {P : Params} {s t u : St Nat} (h1 : Steps P s t) (h2 : Steps P t u) :
    Steps P s u := by
  induction h2 with
  | refl => exact h1
  | tail _ h ih => exact .tail ih h

theorem Steps.single {P : Params} {s t : St Nat} (h : Step P s t) : Steps P s t :=
  .tail (.refl s) h

theorem Steps.reach {P : Params} {s t : St Nat} (h : Steps P s t) (hs : Reach P s) :
    Reach P t := by
  induction h with
  | refl => exact hs
  | tail _ h ih => exact .step ih h

/-- First occurrence of `m`, splitting the list around it. -/
def splitAt? {α : Type} [DecidableEq α] (m : α) : List α → Option (List α × List α)
  | [] => none
  | x :: xs => if x = m then some ([], xs) else (splitAt? m xs).map fun p => (x :: p.1, p.2)

theorem splitAt?_eq {α : Type} [DecidableEq α] {m : α} :
    ∀ {l pre rest : List α}, splitAt? m l = some (pre, rest) → l = pre ++ m :: rest
  | [], _, _, h => by simp [splitAt?] at h
  | x :: xs, pre, rest, h => by
    unfold splitAt? at h
    split at h
    · simp at h; obtain ⟨rfl, rfl⟩ := h; simp_all
    · match hs : splitAt? m xs, h with
      | some (p, r), h =>
        simp at h; obtain ⟨rfl, rfl⟩ := h; simp [splitAt?_eq hs]
      | none, h => simp at h

/-- Checker state: the model state plus bookkeeping that no step reads. -/
structure C where
  st : St Nat
  /-- the caller outcome the model resolved for `a` and the caller has not
  reported yet -/
  owed : Nat → Option Res
  /-- sent while the model's worker was dead, handled after its restart -/
  deferred : List Nat
  /-- every attempt this slot has mentioned -/
  ids : List Nat

/-- A replay segment from `c`: an error, or a new checker state whose model
state is reachable from `c.st`. -/
abbrev Out (c : C) := Except String { c' : C // Steps P0 c.st c'.st }

def stay (c : C) : Out c := .ok ⟨c, .refl _⟩

def andThen {c : C} (x : Out c) (f : (c' : C) → Out c') : Out c :=
  match x with
  | .error e => .error e
  | .ok ⟨c', h⟩ => match f c' with
    | .error e => .error e
    | .ok ⟨c'', h'⟩ => .ok ⟨c'', h.trans h'⟩

def setOwed (o : Nat → Option Res) (a : Nat) (r : Option Res) : Nat → Option Res :=
  fun x => if x = a then r else o x

/-- Callers waiting when the worker died: their call monitors fire. -/
def owedDied (c : C) : Nat → Option Res :=
  fun x => if c.ids.contains x && c.st.pending x then some .died else c.owed x

def ensureExpired (c : C) (a : Nat) : Out c :=
  if he : c.st.expired a = true then stay c
  else if hp : c.st.pending a = true then
    .ok ⟨{ c with st := { c.st with expired := upd c.st.expired a true } },
      .single (Step.expire _ a rfl hp (by simpa using he))⟩
  else .error s!"attempt {a}: past its deadline but the caller is no longer waiting"

def doKill (c : C) : Out c :=
  if h : c.st.wAlive = true then
    .ok ⟨{ c with st := kill c.st, owed := owedDied c }, .single (Step.kill _ h)⟩
  else stay c

def sendLive1 (c : C) (a : Nat) : Out c :=
  if hs : c.st.sent a = false then
    if hw : c.st.wAlive = true then
      .ok ⟨{ c with st := { c.st with wQ := c.st.wQ ++ [.req a], sent := upd c.st.sent a true,
                                      pending := upd c.st.pending a true } },
        .single (Step.sendLive _ a hs hw)⟩
    else .error s!"attempt {a}: sent to a dead worker"
  else .error s!"attempt {a}: sent twice"

def sendAll : (c : C) → List Nat → Out c
  | c, [] => stay c
  | c, a :: as => andThen (sendLive1 c a) fun c' => sendAll c' as

def onStart (c : C) : Out c :=
  andThen (doKill c) fun c1 =>
    if h : c1.st.wAlive = false then
      andThen (.ok ⟨{ c1 with st := { c1.st with wAlive := true, wQ := [] }, deferred := [] },
          .single (Step.restart _ h)⟩)
        fun c2 => sendAll c2 c1.deferred
    else .error "unreachable: worker alive after kill"

def onSend (seen : Nat → Bool) (c : C) (a : Nat) : Out c :=
  if c.st.wAlive then sendLive1 c a
  else if hs : c.st.sent a = false then
    if seen a then stay { c with deferred := c.deferred ++ [a] }
    else if hw : c.st.wAlive = false then
      .ok ⟨{ c with st := { resolve c.st a 1 with sent := upd c.st.sent a true },
                    owed := setOwed c.owed a (some .died) },
        .single (Step.sendDead _ a hs hw)⟩
    else .error "unreachable"
  else .error s!"attempt {a}: sent twice"

def checkOwed (c : C) (a : Nat) (r : Res) : Out c :=
  if c.owed a = some r then stay { c with owed := setOwed c.owed a none }
  else .error s!"attempt {a}: caller saw {repr r}, model owes {repr (c.owed a)}"

def onResult (c : C) (a : Nat) (r : Res) : Out c :=
  match r with
  | .timeout =>
    andThen (ensureExpired c a) fun c1 =>
      if hp : c1.st.pending a = true then
        if he : c1.st.expired a = true then
          if hph : c1.st.phase ≠ .checked a then
            .ok ⟨{ c1 with st := { resolve c1.st a 1 with pending := upd c1.st.pending a false,
                                                          gaveUp := upd c1.st.gaveUp a true } },
              .single (Step.callerTimeout _ a rfl hp he (fun _ => hph))⟩
          else .error s!"attempt {a}: caller timed out inside admit_call"
        else .error "unreachable"
      else .error s!"attempt {a}: caller saw admission_timeout, model already resolved it"
  | .died =>
    if c.owed a ≠ some .died && c.st.wAlive && c.st.pending a then
      andThen (doKill c) fun c1 => checkOwed c1 a .died
    else checkOwed c a .died
  | r => checkOwed c a r

def onCancel (c : C) (a : Nat) : Out c :=
  if h : c.st.accepted a = true ∧ c.st.cancelled a = false then
    .ok ⟨{ c with st := { c.st with cancelled := upd c.st.cancelled a true,
                                     wQ := if c.st.wAlive then c.st.wQ ++ [.cancel a]
                                           else c.st.wQ } },
      .single (Step.sendCancel _ a h.1 h.2)⟩
  else stay c

/-- Preconditions shared by every worker event outside `admit_call`. -/
def idle (c : C) (k : c.st.wAlive = true → c.st.phase = .idle → Out c) : Out c :=
  if hw : c.st.wAlive = true then
    if hi : c.st.phase = .idle then k hw hi
    else .error "worker event inside admit_call"
  else .error "worker event while the model's worker is dead"

def onPre (c : C) (a : Nat) : Out c :=
  andThen (ensureExpired c a) fun c1 => idle c1 fun hw hi =>
    match hq : splitAt? (.req a) c1.st.wQ with
    | some (pre, rest) =>
      if hd : (P0.deadline && c1.st.expired a) = true then
        .ok ⟨{ c1 with st := { replyExpired c1.st a with wQ := pre ++ rest },
                       owed := if c1.st.pending a then setOwed c1.owed a (some .expired)
                               else c1.owed },
          .single (Step.recvReqExpired _ a pre rest hw hi (splitAt?_eq hq) hd)⟩
      else .error "unreachable: expired after ensureExpired"
    | none => .error s!"attempt {a}: refused but never sent"

def onRecv (c : C) (a : Nat) : Out c :=
  idle c fun hw hi =>
    match hq : splitAt? (.req a) c.st.wQ with
    | some (pre, rest) =>
      if hd : (P0.deadline && c.st.expired a) = false then
        .ok ⟨{ c with st := { c.st with wQ := pre ++ rest, phase := .sent a } },
          .single (Step.recvReq _ a pre rest hw hi (splitAt?_eq hq) hd)⟩
      else .error s!"attempt {a}: pre-check passed after the caller's deadline"
    | none => .error s!"attempt {a}: received but never sent"

def onPost (c : C) (a : Nat) : Out c :=
  andThen (ensureExpired c a) fun c1 =>
    if h : c1.st.wAlive = true ∧ c1.st.phase = .sent a then
      if hd : (P0.deadline && c1.st.expired a) = true then
        .ok ⟨{ c1 with st := { replyExpired c1.st a with phase := .idle },
                       owed := if c1.st.pending a then setOwed c1.owed a (some .expired)
                               else c1.owed },
          .single (Step.checkRefuse _ a h.1 h.2 hd)⟩
      else .error "unreachable: expired after ensureExpired"
    else .error s!"attempt {a}: post-check outside its admit_call"

def onAdmit (c : C) (a : Nat) : Out c :=
  if hw : c.st.wAlive = true then
    if hph : c.st.phase = .sent a then
      if hd : (P0.deadline && c.st.expired a) = false then
        let s1 := { c.st with phase := .checked a }
        .ok ⟨{ c with
                st := { s1 with reqs := upd s1.reqs a true, pending := upd s1.pending a false,
                                accepted := upd s1.accepted a (s1.accepted a || s1.pending a),
                                phase := .idle },
                owed := if c.st.pending a then setOwed c.owed a (some .ok) else c.owed },
          .tail (.single (Step.checkPass _ a hw hph hd)) (Step.admitReply s1 a hw rfl)⟩
      else .error s!"attempt {a}: admitted after the caller's deadline"
    else .error s!"attempt {a}: admitted outside its admit_call"
  else .error "worker event while the model's worker is dead"

def onResp (c : C) (a : Nat) (hit : Bool) : Out c :=
  idle c fun hw hi =>
    let s1 := { c.st with wQ := c.st.wQ ++ [.resp a] }
    match hq : splitAt? (.resp a) s1.wQ with
    | some (pre, rest) =>
      if c.st.reqs a == hit then
        .ok ⟨{ c with st := if s1.reqs a then
                  { resolve s1 a 1 with wQ := pre ++ rest, reqs := upd s1.reqs a false }
                else { s1 with wQ := pre ++ rest } },
          .tail (.single (Step.emitResp _ a hw)) (Step.recvResp s1 a pre rest hw hi (splitAt?_eq hq))⟩
      else .error s!"attempt {a}: terminal message {if hit then "delivered" else "dropped"}, model says otherwise"
    | none => .error "unreachable"

def onChunk (c : C) (a : Nat) (hit : Bool) : Out c :=
  idle c fun hw hi =>
    let s1 := { c.st with wQ := c.st.wQ ++ [.chunk a] }
    match hq : splitAt? (.chunk a) s1.wQ with
    | some (pre, rest) =>
      if c.st.reqs a == hit then
        let stop := s1.progressStop ||
          (s1.reqs a && (s1.effCancel a || decide (0 < s1.delivered a)))
        .ok ⟨{ c with st := { s1 with wQ := pre ++ rest, progressStop := stop } },
          .tail (.single (Step.emitChunk _ a hw)) (Step.recvChunk s1 a pre rest hw hi (splitAt?_eq hq))⟩
      else .error s!"attempt {a}: chunk {if hit then "forwarded" else "dropped"}, model says otherwise"
    | none => .error "unreachable"

def onWCancel (c : C) (a : Nat) (hit : Bool) : Out c :=
  idle c fun hw hi =>
    match hq : splitAt? (.cancel a) c.st.wQ with
    | some (pre, rest) =>
      if c.st.reqs a == hit then
        .ok ⟨{ c with st := if c.st.reqs a then
                  { c.st with wQ := pre ++ rest, reqs := upd c.st.reqs a false,
                              effCancel := upd c.st.effCancel a true,
                              snap := upd c.st.snap a (c.st.delivered a),
                              spans := upd c.st.spans a (c.st.spans a + 1) }
                else { c.st with wQ := pre ++ rest } },
          .single (Step.recvCancel _ a pre rest hw hi (splitAt?_eq hq))⟩
      else .error s!"attempt {a}: cancel {if hit then "took effect" else "was a no-op"}, model says otherwise"
    | none =>
      if !hit && !c.st.reqs a then stay c
      else .error s!"attempt {a}: effective cancel never sent"

def onCrash (c : C) (told : List Nat) : Out c :=
  if hw : c.st.wAlive = true then
    if told.all c.st.reqs && c.ids.all (fun x => !c.st.reqs x || told.contains x) then
      .ok ⟨{ c with st := crash c.st, owed := owedDied c }, .single (Step.crash _ hw)⟩
    else .error s!"terminate told {told}, model's Reqs is {c.ids.filter c.st.reqs}"
  else .error "terminate while the model's worker is dead"

/-- A late clock reading is the environment's `expire`: take it first. -/
def clocked (c : C) (a : Nat) (late : Bool) (k : (c : C) → Nat → Out c) : Out c :=
  if late then andThen (ensureExpired c a) fun c1 => k c1 a else k c a

def Ev.ids : Ev → List Nat
  | .start => []
  | .send a | .result a _ | .cancel a => [a]
  | .pre a _ | .recv a _ | .post a _ | .admit a _ => [a]
  | .resp a _ | .chunk a _ | .wcancel a _ => [a]
  | .crash told => told

def onEv (seen : Nat → Bool) (c0 : C) (e : Ev) : Out c0 :=
  -- `ids` is bookkeeping: extending it leaves the model state alone.
  let c := { c0 with ids := e.ids.foldl (fun l a => if l.contains a then l else a :: l) c0.ids }
  match e with
  | .start => onStart c
  | .send a => onSend seen c a
  | .result a r => onResult c a r
  | .cancel a => onCancel c a
  | .pre a late => clocked c a late onPre
  | .recv a late => clocked c a late onRecv
  | .post a late => clocked c a late onPost
  | .admit a late => clocked c a late onAdmit
  | .resp a hit => onResp c a hit
  | .chunk a hit => onChunk c a hit
  | .wcancel a hit => onWCancel c a hit
  | .crash told => onCrash c told

def init0 : C := ⟨init, fun _ => none, [], []⟩

/-- Replay one slot's events in order; on failure, the index of the
offending event and why. -/
def check (evs : List Ev) : Except (Nat × String) { c : C // Reach P0 c.st } :=
  let seen : Nat → Bool := fun a =>
    evs.any fun e => match e with
      | .pre x _ | .recv x _ => x == a
      | _ => false
  let rec go : Nat → (c : C) → Reach P0 c.st → List Ev →
      Except (Nat × String) { c : C // Reach P0 c.st }
    | _, c, h, [] => .ok ⟨c, h⟩
    | i, c, h, e :: es => match onEv seen c e with
      | .error msg => .error (i, msg)
      | .ok ⟨c', h'⟩ => go (i + 1) c' (h'.reach h) es
  go 0 init0 Reach.init evs

/-- What `check` returns on an accepted trace is a reachable state of the
shipped protocol, so every safety theorem holds along it: one terminal outcome per request, none after an
admission error or an effective cancel, no chunk after a stop, telemetry
at most once. -/
theorem accepted_safe (c : { c : C // Reach P0 c.st }) (r : Nat) :
    c.1.st.delivered r ≤ 1 ∧ c.1.st.spans r ≤ 1 ∧ c.1.st.metrics r ≤ 1 ∧
      (c.1.st.gaveUp r = true → c.1.st.reqs r = false) ∧
      c.1.st.progressStop = false :=
  ⟨at_most_once_proof P0 safe_P0 _ c.2 r,
   (telemetry_at_most_once_proof P0 safe_P0 _ c.2 r).1,
   (telemetry_at_most_once_proof P0 safe_P0 _ c.2 r).2,
   fun hg => (no_message_after_admission_error_proof P0 safe_P0 _ c.2 r hg).2,
   no_progress_after_stop_proof P0 safe_P0 _ c.2⟩

end KatipoProofs.Admission.Trace
