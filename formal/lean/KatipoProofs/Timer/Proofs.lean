import KatipoProofs.Timer.Model

/-!
# libcurl's timer: proofs

The invariant `Inv` has four fields; `armed` and `timely` hold only under
`Safe P`, the other two for every configuration:
* `lastOk`: libcurl's last reported deadline is its current earliest one.
  Every callback ends with `Curl_update_timer`, which either reports the new
  earliest deadline or finds it equal to the last one.
* `armed`: while libcurl has a deadline `m`, a timer is pending at or before
  it, or at a time already past. Set late in a callback from the cached
  start time, the timer lands at `start + (m - t) ≤ m`; set from the
  refreshed time, at `max m t`.
* `noEarly` (with the refresh): the pending timer is never before `m`.
* `timely`: no deadline is overdue by more than one callback.

The one hard case is a timer that fires before anything is due and finds
libcurl's deadline unchanged, so `Curl_update_timer` sets nothing. libcurl's
reset rules it out (the deadline was forgotten, so it is "changed"), the
re-arm sets the timer itself, and with the refresh on one clock it cannot
happen: the timer is never before the deadline, so firing means the deadline
was due. With `lag > 0` the refresh alone does not rule it out.
-/

namespace KatipoProofs.Timer

theorem minD_eq_none {l : List Nat} : minD l = none ↔ l = [] := by
  cases l with
  | nil => simp [minD]
  | cons x xs => simp only [minD]; split <;> simp

theorem minD_mem {l : List Nat} {m : Nat} (h : minD l = some m) : m ∈ l := by
  induction l generalizing m with
  | nil => simp [minD] at h
  | cons x xs ih =>
    simp only [minD] at h
    split at h
    · cases h; simp
    · rename_i y hy
      cases h
      have := ih hy
      rcases Nat.le_total x y with hxy | hxy
      · simp [Nat.min_eq_left hxy]
      · simp [Nat.min_eq_right hxy, this]

theorem minD_le {l : List Nat} {m y : Nat} (h : minD l = some m) (hy : y ∈ l) : m ≤ y := by
  induction l generalizing m with
  | nil => simp at hy
  | cons x xs ih =>
    simp only [minD] at h
    split at h
    · rename_i hn
      cases h
      rcases List.mem_cons.mp hy with rfl | hy'
      · exact Nat.le_refl _
      · rw [minD_eq_none] at hn; subst hn; simp at hy'
    · rename_i z hz
      cases h
      rcases List.mem_cons.mp hy with rfl | hy'
      · exact Nat.min_le_left _ _
      · exact Nat.le_trans (Nat.min_le_right _ _) (ih hz hy')

theorem repOf_inj {a b : Option Nat} (h : repOf a = repOf b) : a = b := by
  cases a <;> cases b <;> simp_all [repOf]

theorem repOf_some_ne_none (m : Nat) : repOf (some m) ≠ .none := by
  simp [repOf]

theorem update_snd (P : Params) (D : List Nat) (L : Rep) (pend : Option Nat) (t c : Nat) :
    (update P D L pend t c).2 = repOf (minD D) := by
  unfold update; split <;> simp_all

/-- A timer set for deadline `m` at time `t`, from a base no later than `t`,
is at or before `m`, or already past. -/
theorem timerFor_armed (P : Params) {m t c x : Nat} (hc : c ≤ t)
    (h : timerFor P (some m) t c = some x) : x ≤ m ∨ x ≤ t := by
  simp only [timerFor] at h
  cases h
  cases P.refresh <;> simp <;> omega

theorem timerFor_refresh (P : Params) (hr : P.refresh = true) {m t c x : Nat}
    (h : timerFor P (some m) t c = some x) : m ≤ x := by
  simp only [timerFor, hr] at h
  cases h
  simp; omega

theorem timerFor_isSome (P : Params) (m t c : Nat) : (timerFor P (some m) t c).isSome := by
  simp [timerFor]

structure Inv (P : Params) (s : St) : Prop where
  lastOk : s.last = repOf (minD s.ds)
  armed : Safe P → ∀ m, minD s.ds = some m → ∃ x, s.timer = some x ∧ (x ≤ m ∨ x ≤ s.now)
  noEarly : P.refresh = true → ∀ m x, minD s.ds = some m → s.timer = some x → m ≤ x
  timely : Safe P → ∀ m, minD s.ds = some m → s.now ≤ m + P.skew

theorem inv_init (P : Params) : Inv P init where
  lastOk := rfl
  armed := by simp [init, minD]
  noEarly := by simp [init, minD]
  timely := by simp [init, minD]

/-- Every deadline left after a callback is past its start, or the one it
added. -/
theorem mem_remaining {s : St} {extra drop : Option Nat} {y : Nat}
    (hy : y ∈ remaining s extra drop) : s.now < y ∨ extra = some y := by
  simp only [remaining, List.mem_append, List.mem_filter, Bool.and_eq_true,
    decide_eq_true_eq] at hy
  rcases hy with ⟨_, h, _⟩ | h
  · exact Or.inl h
  · cases extra <;> simp_all

theorem remaining_ne {s : St} {extra drop : Option Nat} {m : Nat}
    (hm : minD (remaining s extra drop) = some m) :
    (remaining s extra drop).isEmpty = false := by
  cases h : remaining s extra drop with
  | nil => rw [h] at hm; simp [minD] at hm
  | cons _ _ => rfl

/-- The timer a callback leaves pending, when libcurl still has a deadline
`m` afterwards: unchanged deadline keeps what was pending (nothing, after a
timer fire, unless `timer_cb` re-arms), a changed one is re-reported. -/
theorem post_timer (P : Params) (s : St) (isTimer : Bool) (extra drop : Option Nat)
    (k m : Nat) (hm : minD (remaining s extra drop) = some m) :
    (callback P s isTimer extra drop k).timer =
      if repOf (some m) = (if isTimer && P.resets then Rep.none else s.last) then
        (if isTimer && P.rearm then timerFor P (some m) (s.now + k) s.now
         else if isTimer then none else s.timer)
      else timerFor P (some m) (s.now + k) s.now := by
  have hne := remaining_ne hm
  obtain ⟨y, hy⟩ := Option.isSome_iff_exists.mp (timerFor_isSome P m (s.now + k) s.now)
  unfold callback update
  simp only [hm, hne]
  by_cases h : repOf (some m) = (if isTimer && P.resets then Rep.none else s.last)
  · rw [if_pos h, if_pos h]
    cases isTimer <;> cases P.rearm <;> simp
  · rw [if_neg h, if_neg h, hy]
    cases isTimer <;> cases P.rearm <;> simp

theorem callback_inv (P : Params) (s : St) (hI : Inv P s)
    (isTimer : Bool) (extra drop : Option Nat) (k : Nat) (hk : k ≤ P.skew)
    (hex : ∀ e, extra = some e → s.now ≤ e)
    (hfire : isTimer = true → extra = none ∧ ∃ x, s.timer = some x ∧ x ≤ s.now + P.lag) :
    Inv P (callback P s isTimer extra drop k) := by
  have hds : (callback P s isTimer extra drop k).ds = remaining s extra drop := rfl
  have hnow : (callback P s isTimer extra drop k).now = s.now + k := rfl
  -- Every remaining deadline is at or after the callback's start.
  have hge : ∀ y, y ∈ remaining s extra drop → s.now ≤ y := by
    intro y hy
    rcases mem_remaining hy with h | h
    · exact Nat.le_of_lt h
    · exact hex y h
  -- A timer fire that finds libcurl's deadline unchanged, with no reset:
  -- the old deadline is still the earliest one.
  have hsame : ∀ m, minD (remaining s extra drop) = some m →
      repOf (some m) = (if isTimer && P.resets then Rep.none else s.last) →
      (isTimer && P.resets) = false ∧ minD s.ds = some m := by
    intro m _ hL
    cases hb : (isTimer && P.resets)
    · rw [hb, if_neg (by simp), hI.lastOk] at hL
      exact ⟨rfl, (repOf_inj hL).symm⟩
    · rw [hb, if_pos rfl] at hL
      exact absurd hL (repOf_some_ne_none _)
  -- With the refresh on one clock and no re-arm, that fire cannot happen:
  -- the timer was not before the deadline, so the deadline was due and has
  -- run.
  have hnofire : ∀ m, minD (remaining s extra drop) = some m → minD s.ds = some m →
      isTimer = true → P.refresh = true → P.lag = 0 → False := by
    intro m hm hold hT hrf hlag
    obtain ⟨hnone, x, hx, hxn⟩ := hfire hT
    rw [hlag] at hxn
    have hmx := hI.noEarly hrf m x hold hx
    rcases mem_remaining (minD_mem hm) with h | h
    · omega
    · rw [hnone] at h; cases h
  refine ⟨?_, ?_, ?_, ?_⟩
  · exact update_snd ..
  · intro hP m hm
    rw [hds] at hm
    rw [post_timer P s isTimer extra drop k m hm, hnow]
    by_cases hL : repOf (some m) = (if isTimer && P.resets then Rep.none else s.last)
    · rw [if_pos hL]
      obtain ⟨hb, hold⟩ := hsame m hm hL
      cases hT : isTimer
      · obtain ⟨x, hx, h⟩ := hI.armed hP m hold
        exact ⟨x, by simp [hx], by omega⟩
      · cases hA : P.rearm
        · exfalso
          have hR : P.resets = false := by simpa [hT] using hb
          rcases hP with ⟨hrf, hlag⟩ | h | h
          · exact hnofire m hm hold hT hrf hlag
          · rw [hA] at h; cases h
          · rw [hR] at h; cases h
        · obtain ⟨x, hx⟩ := Option.isSome_iff_exists.mp
            (timerFor_isSome P m (s.now + k) s.now)
          exact ⟨x, by simp [hx], timerFor_armed P (by omega) hx⟩
    · rw [if_neg hL]
      obtain ⟨x, hx⟩ := Option.isSome_iff_exists.mp (timerFor_isSome P m (s.now + k) s.now)
      exact ⟨x, hx, timerFor_armed P (by omega) hx⟩
  · intro hrf m x hm hx
    rw [hds] at hm
    rw [post_timer P s isTimer extra drop k m hm] at hx
    by_cases hL : repOf (some m) = (if isTimer && P.resets then Rep.none else s.last)
    · rw [if_pos hL] at hx
      obtain ⟨_, hold⟩ := hsame m hm hL
      cases hT : isTimer
      · simp only [hT, Bool.false_and, Bool.false_eq_true, if_false] at hx
        exact hI.noEarly hrf m x hold hx
      · -- A fire that left the deadline unchanged: the re-arm sets the timer
        -- from the refreshed time, and without it none is pending.
        cases hA : P.rearm
        · simp [hT, hA] at hx
        · simp only [hT, hA, Bool.and_self, if_true] at hx
          exact timerFor_refresh P hrf hx
    · rw [if_neg hL] at hx
      exact timerFor_refresh P hrf hx
  · intro _ m hm
    rw [hds] at hm
    rw [hnow]
    have := hge m (minD_mem hm)
    omega

theorem tick_inv (P : Params) (s : St) (hI : Inv P s)
    (hg : ∀ x, s.timer = some x → s.now < x) : Inv P { s with now := s.now + 1 } where
  lastOk := hI.lastOk
  armed := by
    intro hP m hm
    obtain ⟨x, hx, h⟩ := hI.armed hP m hm
    refine ⟨x, hx, ?_⟩
    show x ≤ m ∨ x ≤ s.now + 1
    omega
  noEarly := hI.noEarly
  timely := by
    intro hP m hm
    obtain ⟨x, hx, h⟩ := hI.armed hP m hm
    have := hg x hx
    show s.now + 1 ≤ m + P.skew
    omega

theorem inv_reach (P : Params) (s : St) (h : Reach P s) : Inv P s := by
  induction h with
  | init => exact inv_init P
  | step s t _ hst ih =>
    cases hst with
    | timerFire x k hx hxn hk =>
      exact callback_inv P s ih true none none k hk (by simp) (fun _ => ⟨rfl, x, hx, hxn⟩)
    | add k d hk =>
      exact callback_inv P s ih false _ none k hk (by intro e he; cases he; omega)
        (by simp)
    | socket k drop hk =>
      exact callback_inv P s ih false none drop k hk (by simp) (by simp)
    | tick hg => exact tick_inv P s ih hg

theorem timer_armed_proof (P : Params) (hP : Safe P) (s : St) (h : Reach P s)
    (hd : s.ds ≠ []) : s.timer ≠ none := by
  obtain ⟨m, hm⟩ : ∃ m, minD s.ds = some m := by
    cases h' : minD s.ds with
    | none => exact absurd (minD_eq_none.mp h') hd
    | some m => exact ⟨m, rfl⟩
  obtain ⟨x, hx, _⟩ := (inv_reach P s h).armed hP m hm
  simp [hx]

theorem timely_proof (P : Params) (hP : Safe P) (s : St) (h : Reach P s) (m : Nat)
    (hm : minD s.ds = some m) : s.now ≤ m + P.skew :=
  (inv_reach P s h).timely hP m hm

theorem not_early_proof (P : Params) (hr : P.refresh = true) (s : St) (h : Reach P s)
    (m x : Nat) (hm : minD s.ds = some m) (hx : s.timer = some x) : m ≤ x :=
  (inv_reach P s h).noEarly hr m x hm hx

/-! ## The old port with libcurl 8.10.0-8.11.0 -/

/-- Before the fix, with libcurl 8.10.0-8.11.0: nothing re-arms the timer. -/
def oldPort : Params :=
  { resets := false, refresh := false, rearm := false, deleteOnNone := false,
    idleDelete := true, skew := 1, lag := 0 }

/-- A request arrives at 0 and its callback runs one tick: libcurl asks for a
one-tick timer to deadline 2, which libevent counts from the cached 0. -/
def s1 : St := callback oldPort init false (some 2) none 1

/-- The timer fires at 1, before the deadline: nothing is due, libcurl's
deadline is unchanged, so no timer is asked for. -/
def s2 : St := callback oldPort s1 true none none 0

theorem s1_eq : s1 = { now := 1, timer := some 1, ds := [2], last := .at 2 } := by decide
theorem s2_eq : s2 = { now := 1, timer := none, ds := [2], last := .at 2 } := by decide

theorem reach_s2 : Reach oldPort s2 := by
  have h1 : Reach oldPort s1 := Reach.step _ _ Reach.init (Step.add init 1 1 (by decide))
  exact Reach.step _ _ h1 (Step.timerFire s1 1 0 (by rw [s1_eq]) (by rw [s1_eq]; decide)
    (by decide))

/-- With no timer pending, only time passes: the deadline waits forever. -/
theorem reach_late (n : Nat) :
    Reach oldPort { now := 1 + n, timer := none, ds := [2], last := .at 2 } := by
  induction n with
  | zero => have := reach_s2; rw [s2_eq] at this; exact this
  | succ n ih =>
    exact Reach.step _ _ ih (Step.tick _ (by simp))

theorem old_811_late_proof (n : Nat) :
    ∃ s : St, Reach oldPort s ∧ s.timer = none ∧ minD s.ds = some 2 ∧ 2 + n ≤ s.now :=
  ⟨_, reach_late (n + 1), rfl, rfl, by simp; omega⟩

/-! ## The refresh alone, with libevent's clock ahead of libcurl's -/

/-- Only the cached-time refresh, libcurl 8.10.0-8.11.0, and libevent's
clock one tick coarser than libcurl's. -/
def refreshOnly : Params :=
  { resets := false, refresh := true, rearm := false, deleteOnNone := false,
    idleDelete := true, skew := 0, lag := 1 }

/-- A request arrives at 0 with a one-tick deadline; the timer is set
exactly for it. -/
def r1 : St := callback refreshOnly init false (some 1) none 0

/-- libevent's clock lets the timer fire at 0: nothing is due, libcurl's
deadline is unchanged, and no timer is asked for. -/
def r2 : St := callback refreshOnly r1 true none none 0

theorem r1_eq : r1 = { now := 0, timer := some 1, ds := [1], last := .at 1 } := by decide
theorem r2_eq : r2 = { now := 0, timer := none, ds := [1], last := .at 1 } := by decide

theorem reach_r2 : Reach refreshOnly r2 := by
  have h1 : Reach refreshOnly r1 := Reach.step _ _ Reach.init (Step.add init 0 1 (by decide))
  exact Reach.step _ _ h1 (Step.timerFire r1 1 0 (by rw [r1_eq]) (by rw [r1_eq]; decide)
    (by decide))

theorem reach_refresh_late (n : Nat) :
    Reach refreshOnly { now := n, timer := none, ds := [1], last := .at 1 } := by
  induction n with
  | zero => have := reach_r2; rw [r2_eq] at this; exact this
  | succ n ih =>
    exact Reach.step _ _ ih (Step.tick _ (by simp))

theorem refresh_only_late_proof (n : Nat) :
    ∃ s : St, Reach refreshOnly s ∧ s.timer = none ∧ minD s.ds = some 1 ∧ 1 + n ≤ s.now :=
  ⟨_, reach_refresh_late (n + 1), rfl, rfl, by simp; omega⟩

end KatipoProofs.Timer
