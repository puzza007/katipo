import KatipoProofs.Defaults.Proofs
import KatipoProofs.Defaults.Counterexamples
import KatipoProofs.Defaults.MergeProofs

/-!
# Pool defaults: headline statements (frozen 2026-10-27, revised the same day)

Re-frozen for the defaults moving from a supervisor's ETS table into the
pool's wpool options: `table_with_sup` became `term_with_pool`;
`app_stays_up` and `no_await_takes_app_down` went with the wait they were
about; the window and stale counterexamples are the same claims; the merge
gained `credentials_stay_on_origin`, and the request's headers now come
first. Revised after review: origins became optional, as a url's may not be
told, and two unknown origins are never the same
(`unknown_origin_never_same`).

Revised 2026-10-30, after review found that wpool's rebuild is stored, and
may be stored over the options the pool has just stored: `term_with_pool`
allows the rebuild; `never_without_generation` is new, for the fallback
that asks a worker; `rebuild_replaces_options` and
`without_fallback_refused` show the race and that the fallback is needed.

For any number of callers, starts, stops, pool crashes and restarts. Proofs
live in `Defaults/Proofs.lean`, `Defaults/Counterexamples.lean` and
`Defaults/MergeProofs.lean`; this file pins what was agreed and only
delegates.
-/

namespace KatipoProofs.Defaults.Statements
open KatipoProofs.Defaults

/-- With requests tagged with their pool's generation, a request is only
ever served with the defaults of the pool serving it: never with none, and
never with another pool's of the same name. -/
theorem ran_with_its_defaults (P : Params) (hg : P.genCheck = true) (s : St)
    (h : Reach P s) : ∀ r ∈ s.ran, same r.2.1 r.2.2 = true :=
  (inv_reach h).ranSame hg

/-- With the fallback, no request is left with no generation, which every
worker would refuse: one that finds wpool's rebuild asks a worker. -/
theorem never_without_generation (P : Params) (hf : P.fallback = true) (s : St)
    (h : Reach P s) (c : Nat) : s.v c ≠ .nodef :=
  (inv_reach h).withGen hf c

/-- The options stored are the running pool's own, or wpool's rebuild, and
the workers are the running pool's own. -/
theorem term_with_pool (P : Params) (s : St) (h : Reach P s) :
    ((s.reg = .stored ∨ s.reg = .up) → s.term = termOf s.child ∨ s.term = .rebuilt) ∧
      (s.reg = .up → s.wgen = s.child) :=
  ⟨(inv_reach h).termPool, (inv_reach h).workersPool⟩

/-- The rebuild is no theory: in what ships, a caller racing the pool's
first start stores it over the pool's own options, and the pool runs
with it... -/
theorem rebuild_replaces_options :
    ∃ s, Reach pShipped s ∧ s.reg = .up ∧ s.term = .rebuilt :=
  rebuild_reach

/-- ...and without the fallback a request then has no generation while the
pool runs, which no worker serves. -/
theorem without_fallback_refused :
    ∃ s, Reach pNoAsk s ∧ s.reg = .up ∧ s.pc 0 = .read ∧ s.v 0 = .nodef ∧
      ∀ w, same (s.v 0) w = false := by
  obtain ⟨s, h, hr, hp, hv⟩ := noask_reach
  exact ⟨s, h, hr, hp, hv, fun w => by simp [hv, same]⟩

/-- Nothing outlives a stopped pool: a request then finds no pool. -/
theorem nothing_left (P : Params) (s : St) (h : Reach P s) (hc : s.child = none) :
    s.reg = .down :=
  (inv_reach h).nothingLeft hc

/-- The generation is necessary: without it, a request read as its pool
first starts is served with no defaults... -/
theorem unchecked_window :
    ∃ s, Reach pUnchecked s ∧ pUnchecked.genCheck = false ∧ (0, RV.nodef, some 0) ∈ s.ran := by
  obtain ⟨s, h, hm⟩ := window_reach
  exact ⟨s, h, rfl, hm⟩

/-- ...and one read from a pool being replaced is served by its successor
with the old defaults. -/
theorem unchecked_stale :
    ∃ s, Reach pUnchecked s ∧ pUnchecked.genCheck = false ∧ (0, RV.gen 0, some 1) ∈ s.ran := by
  obtain ⟨s, h, hm⟩ := stale_reach
  exact ⟨s, h, rfl, hm⟩

/-! ## The merge, for any options and headers -/

open KatipoProofs.Defaults.Merge in
/-- An option the request gives wins... -/
theorem request_option_wins {K V : Type} (d o : K → Option V) (k : K) (x : V)
    (h : o k = some x) : opts d o k = some x :=
  opts_given d o k x h

open KatipoProofs.Defaults.Merge in
/-- ...and otherwise the default applies... -/
theorem default_option_applies {K V : Type} (d o : K → Option V) (k : K)
    (h : o k = none) : opts d o k = d k :=
  opts_default d o k h

open KatipoProofs.Defaults.Merge in
/-- ...except that a request for another origin than `base_url`'s, or one
whose origin cannot be told, has none of the origin-only defaults, only
what it gives itself... -/
theorem credentials_stay_on_origin {K V O : Type} [DecidableEq O] (only : K → Bool)
    (base url : Option O) (d o : K → Option V) (k : K)
    (hu : sameOrigin url base = false) (hk : only k = true) :
    opts (scope only base url d) o k = o k :=
  scope_off only base url d o k hu hk

open KatipoProofs.Defaults.Merge in
/-- ...and an origin that cannot be told is never the same as another. -/
theorem unknown_origin_never_same {O : Type} [DecidableEq O] (x : Option O) :
    sameOrigin none x = false ∧ sameOrigin x none = false :=
  unknown_never_same x

open KatipoProofs.Defaults.Merge in
/-- The request's headers come first, all of them, in order... -/
theorem request_headers_kept {N A B : Type} [DecidableEq N] (name : A → N)
    (d g : List (A × B)) : ∃ suf, headers name d g = g ++ suf :=
  given_prefix name d g

open KatipoProofs.Defaults.Merge in
/-- ...a default header stays exactly when the request has none of its
name... -/
theorem default_header_kept_iff {N A B : Type} [DecidableEq N] (name : A → N)
    (d g : List (A × B)) (h : A × B) (hd : h ∈ d) (hg : h ∉ g) :
    h ∈ headers name d g ↔ name h.1 ∉ g.map (name ∘ Prod.fst) :=
  default_kept_iff name d g h hd hg

open KatipoProofs.Defaults.Merge in
/-- ...so every header with a name the request gives is the request's... -/
theorem request_name_wins {N A B : Type} [DecidableEq N] (name : A → N)
    (d g : List (A × B)) (h : A × B) (hm : h ∈ headers name d g)
    (hn : name h.1 ∈ g.map (name ∘ Prod.fst)) : h ∈ g :=
  named_given name d g h hm hn

open KatipoProofs.Defaults.Merge in
/-- ...and merging the defaults into headers that already have them
changes nothing. -/
theorem headers_idempotent {N A B : Type} [DecidableEq N] (name : A → N)
    (d g : List (A × B)) : headers name d (headers name d g) = headers name d g :=
  headers_idem name d g

end KatipoProofs.Defaults.Statements
