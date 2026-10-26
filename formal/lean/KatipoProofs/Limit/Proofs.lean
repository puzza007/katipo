import KatipoProofs.Limit.Model

/-! # `max_body_size`: proofs -/

namespace KatipoProofs.Limit

@[simp] theorem total_nil : total [] = 0 := rfl
@[simp] theorem total_cons (c : Nat) (cs : List Nat) : total (c :: cs) = c + total cs := rfl

/-- The up-front check, which only the first chunk can trip. -/
def upfront (limit : Nat) (cl : Option Nat) (n : Nat) : Bool := n == 0 && cl.any (limit < ·)

theorem tooLarge_fst (limit : Nat) (cl : Option Nat) (n c : Nat) :
    (tooLarge limit cl n c).1 = (upfront limit cl n || decide (limit < n + c)) := by
  unfold tooLarge upfront; split <;> simp_all

theorem tooLarge_snd (limit : Nat) (cl : Option Nat) (n c : Nat)
    (h : (tooLarge limit cl n c).1 = false) : (tooLarge limit cl n c).2 = n + c := by
  unfold tooLarge at *; split <;> simp_all

theorem run_cons (limit : Nat) (cl : Option Nat) (n c : Nat) (cs : List Nat) :
    run limit cl n (c :: cs) =
      if upfront limit cl n || decide (limit < n + c) then ([], true)
      else ((c :: (run limit cl (n + c) cs).1), (run limit cl (n + c) cs).2) := by
  simp only [run]
  split
  · rename_i h; rw [tooLarge_fst] at h; simp [h]
  · rename_i h
    have h' := h; rw [tooLarge_fst] at h'
    simp only [Bool.not_eq_true] at h h'
    simp [h', tooLarge_snd limit cl n c h]

/-- Past the first chunk, the Content-Length plays no part. -/
theorem run_pos (limit : Nat) (cl : Option Nat) (cs : List Nat) :
    ∀ n, 0 < n → run limit cl n cs = run limit none n cs := by
  induction cs with
  | nil => intro n _; simp [run]
  | cons c cs ih =>
    intro n hn
    have hu : ∀ cl', upfront limit cl' n = false := fun _ => by
      simp [upfront]; omega
    rw [run_cons, run_cons, hu, hu, ih (n + c) (by omega)]

theorem fails_iff_none (limit : Nat) (cs : List Nat) :
    ∀ n, n ≤ limit → ((run limit none n cs).2 = true ↔ limit < n + total cs) := by
  induction cs with
  | nil => intro n hn; simp [run]; omega
  | cons c cs ih =>
    intro n hn
    rw [run_cons]
    by_cases h : limit < n + c
    · simp [upfront, h]; omega
    · simp only [upfront, Option.any_none, Bool.and_false, Bool.false_or, h,
        decide_false, Bool.false_eq_true, if_false]
      rw [ih (n + c) (by omega)]; simp; omega

theorem forwarded_within (limit : Nat) (cl : Option Nat) (cs : List Nat) :
    ∀ n, n ≤ limit → n + total (run limit cl n cs).1 ≤ limit := by
  induction cs with
  | nil => intro n hn; simp [run]; omega
  | cons c cs ih =>
    intro n hn
    rw [run_cons]
    split
    · simpa using hn
    · rename_i h
      simp only [Bool.or_eq_true, decide_eq_true_eq, not_or] at h
      have := ih (n + c) (by omega)
      simp; omega

theorem forwarded_prefix (limit : Nat) (cl : Option Nat) (cs : List Nat) :
    ∀ n, ∃ rest, cs = (run limit cl n cs).1 ++ rest := by
  induction cs with
  | nil => intro n; exact ⟨[], by simp [run]⟩
  | cons c cs ih =>
    intro n
    rw [run_cons]
    split
    · exact ⟨c :: cs, by simp⟩
    · obtain ⟨rest, h⟩ := ih (n + c)
      exact ⟨rest, by simp; exact h⟩

theorem all_unless_failed (limit : Nat) (cl : Option Nat) (cs : List Nat) :
    ∀ n, (run limit cl n cs).2 = false → (run limit cl n cs).1 = cs := by
  induction cs with
  | nil => intro n _; simp [run]
  | cons c cs ih =>
    intro n h
    rw [run_cons] at h ⊢
    split
    · rename_i hc; simp [hc] at h
    · rename_i hc; simp [hc] at h; simp [ih (n + c) h]

/-- The chunk after the forwarded ones would have taken the body past the
limit: nothing that fits is ever refused. -/
theorem refused_overflows (limit : Nat) (cs : List Nat) :
    ∀ n, (run limit none n cs).2 = true →
      ∃ c rest, cs = (run limit none n cs).1 ++ c :: rest ∧
        limit < n + total (run limit none n cs).1 + c := by
  induction cs with
  | nil => intro n h; simp [run] at h
  | cons c cs ih =>
    intro n h
    rw [run_cons] at h ⊢
    by_cases hc : limit < n + c
    · simp only [upfront, Option.any_none, Bool.and_false, Bool.false_or, hc, decide_true,
        if_true]
      exact ⟨c, cs, by simp, by simp; omega⟩
    · simp only [upfront, Option.any_none, Bool.and_false, Bool.false_or, hc, decide_false,
        Bool.false_eq_true, if_false] at h ⊢
      obtain ⟨c', rest, h1, h2⟩ := ih (n + c) h
      exact ⟨c', rest, by simp; exact h1, by simp; omega⟩

/-- An honest Content-Length (the body's own size) changes no verdict, and
when it fails the transfer it does so before any of the body is
forwarded. -/
theorem honest_upfront (limit : Nat) (cs : List Nat) (hpos : ∀ c ∈ cs, 0 < c) :
    (run limit (some (total cs)) 0 cs).2 = (run limit none 0 cs).2 ∧
      ((run limit (some (total cs)) 0 cs).2 = true →
        (run limit (some (total cs)) 0 cs).1 = []) := by
  cases cs with
  | nil => simp [run]
  | cons c cs =>
    have hc : 0 < c := hpos c (by simp)
    rw [run_cons, run_cons]
    by_cases hl : limit < c + total cs
    · have hfail : (run limit none 0 (c :: cs)).2 = true :=
        (fails_iff_none limit (c :: cs) 0 (by omega)).2 (by simpa using hl)
      rw [run_cons] at hfail
      simp [upfront, hl] at hfail ⊢
      exact hfail
    · simp only [upfront, total_cons, Option.any_some, decide_eq_true_eq, hl, decide_false,
        Bool.and_false, Bool.false_or, Nat.zero_add]
      rw [run_pos limit _ cs c hc]
      refine ⟨by simp, fun h => absurd h ?_⟩
      have hle : ¬ limit < c := by omega
      simp only [hle, if_false, Bool.not_eq_true]
      cases hr : (run limit none c cs).2
      · rfl
      · have := (fails_iff_none limit cs c (by omega)).1 hr; omega

end KatipoProofs.Limit
