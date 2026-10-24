import KatipoProofs.Timer.Proofs

/-!
# libcurl's timer: headline statements (frozen)

Proofs live in `Timer/Proofs.lean` under the `_proof` suffix; this file pins
what was agreed and only delegates.
-/

namespace KatipoProofs.Timer.Statements
open KatipoProofs.Timer

/-- With the re-arm, or libcurl's own reset, or the cache refresh with
libevent and libcurl on one clock, the port has a timer pending whenever
libcurl has a deadline (`TimerArmed`), for any clock, callback length, clock
lag and number of deadlines. -/
theorem timer_armed (P : Params) (hP : Safe P) (s : St) (h : Reach P s)
    (hd : s.ds ≠ []) : s.timer ≠ none := by
  apply timer_armed_proof <;> assumption

/-- Under the same condition, no deadline is overdue by more than one
callback's length (`Timely`). -/
theorem timely (P : Params) (hP : Safe P) (s : St) (h : Reach P s) (m : Nat)
    (hm : minD s.ds = some m) : s.now ≤ m + P.skew := by
  apply timely_proof <;> assumption

/-- With the cache refresh, the pending timer is never set before libcurl's
next deadline (`NotEarly`). It can still fire up to `P.lag` before it. -/
theorem not_early (P : Params) (hr : P.refresh = true) (s : St) (h : Reach P s)
    (m x : Nat) (hm : minD s.ds = some m) (hx : s.timer = some x) : m ≤ x := by
  apply not_early_proof <;> assumption

/-- The port before the fix, with libcurl 8.10.0-8.11.0: a deadline can be
left with no timer pending and be overdue by any amount
(`KatipoTimerOld811.cfg`). -/
theorem old_811_late (n : Nat) :
    ∃ s : St, Reach oldPort s ∧ s.timer = none ∧ minD s.ds = some 2 ∧ 2 + n ≤ s.now := by
  apply old_811_late_proof

/-- The cache refresh alone, with libcurl 8.10.0-8.11.0 and libevent's clock
coarser than libcurl's (Linux's default): a deadline can be left with no
timer pending and be overdue by any amount (`KatipoTimerRefreshOnly.cfg`).
The re-arm is what the fix rests on. -/
theorem refresh_only_late (n : Nat) :
    ∃ s : St, Reach refreshOnly s ∧ s.timer = none ∧ minD s.ds = some 1 ∧ 1 + n ≤ s.now := by
  apply refresh_only_late_proof

end KatipoProofs.Timer.Statements
