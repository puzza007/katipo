import KatipoProofs.Retry.Counterexamples

/-!
# Retries: headline statements (frozen)

Proofs live in `Retry/Proofs.lean` and `Retry/Counterexamples.lean`; this
file pins what was agreed and only delegates. Every statement holds for
any number of requests and any `max_retries` -- TLC checked two requests
with one retry, and one with three.

Frozen 2026-10-26.
-/

namespace KatipoProofs.Retry.Statements
open KatipoProofs.Retry

/-- Each request gets at most one outcome (`AtMostOnce`). -/
theorem at_most_once (P : Params) (s : St) (h : Reach P s) (r : Nat) :
    s.delivered r ≤ 1 := by
  rw [(gen_reach h).deliv r]; split <;> omega

/-- Nothing is delivered after a cancel takes effect (`CancelQuiet`). -/
theorem cancel_quiet (P : Params) (s : St) (h : Reach P s) (r : Nat)
    (hc : s.rs r = .cancelled) : s.delivered r = 0 := by
  rw [(gen_reach h).deliv r, hc]; rfl

/-- A request is sent at most `max_retries + 1` times (`RetriesBounded`). -/
theorem retries_bounded (P : Params) (s : St) (h : Reach P s) (r : Nat) :
    s.sent r ≤ P.maxRetries + 1 :=
  (gen_reach h).sentLe r

/-- With fresh port ids, the outcome a request gets, or the retry it makes,
is its current attempt's: never the late output of one it gave up on
(`NoStale`). -/
theorem no_stale (P : Params) (hf : P.fresh = true) (s : St) (h : Reach P s) :
    s.stale = false :=
  (fr_reach hf h).noStale

/-- Matching `Tref`, an attempt ends by timeout only on its own timer
(`NoSpurious`). -/
theorem no_spurious (P : Params) (hm : P.matchTref = true) (s : St) (h : Reach P s) :
    s.spurious = false :=
  spur_reach hm h

/-- With fresh port ids, every transfer the port runs is its request's
current attempt, or has an abort on its way (`NoOrphan`). -/
theorem no_orphan (P : Params) (hf : P.fresh = true) (s : St) (h : Reach P s) :
    NoOrphan s := by
  have hF := fr_reach hf h
  intro x hx
  rcases hF.runOk x hx with ⟨tr, h'⟩ | h'
  · exact Or.inl ⟨tr, by rw [← hF.runN x hx]; exact h'⟩
  · exact Or.inr h'

/-- Fresh ids are necessary: reusing the key, a late message from an
attempt given up on is taken for the retry's (`KatipoRetryReuse.cfg`). -/
theorem reuse_stale :
    ∃ (P : Params) (s : St), P.fresh = false ∧ P.matchTref = true ∧ Reach P s ∧
      s.stale = true := by
  obtain ⟨s, h1, h2⟩ := reuse_stale_proof
  exact ⟨pReuse, s, rfl, rfl, h1, h2⟩

/-- ... and the retry's transfer is left running for nobody
(`KatipoRetryReuseOrphan.cfg`). -/
theorem reuse_orphan :
    ∃ (P : Params) (s : St), P.fresh = false ∧ P.matchTref = true ∧ Reach P s ∧
      ¬ NoOrphan s := by
  obtain ⟨s, h1, h2⟩ := reuse_orphan_proof
  exact ⟨pReuse, s, rfl, rfl, h1, h2⟩

/-- Matching `Tref` is necessary: without it an earlier attempt's timer,
fired as that attempt ended, cuts the retry short (`KatipoRetryNoTref.cfg`). -/
theorem no_tref_spurious :
    ∃ (P : Params) (s : St), P.fresh = true ∧ P.matchTref = false ∧ Reach P s ∧
      s.spurious = true := by
  obtain ⟨s, h1, h2⟩ := no_tref_spurious_proof
  exact ⟨pNoTref, s, rfl, rfl, h1, h2⟩

end KatipoProofs.Retry.Statements
