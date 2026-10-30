import KatipoProofs.Defaults.Merge

/-! # Pool defaults: the merge, proofs -/

namespace KatipoProofs.Defaults.Merge

variable {N A B : Type} [DecidableEq N] (name : A → N)

theorem opts_given {K V : Type} (d o : K → Option V) (k : K) (x : V) (h : o k = some x) :
    opts d o k = some x := by
  simp [opts, h]

theorem opts_default {K V : Type} (d o : K → Option V) (k : K) (h : o k = none) :
    opts d o k = d k := by
  simp [opts, h]

theorem scope_off {K V O : Type} [DecidableEq O] (only : K → Bool) (base url : Option O)
    (d o : K → Option V) (k : K) (hu : sameOrigin url base = false) (hk : only k = true) :
    opts (scope only base url d) o k = o k := by
  simp only [opts, scope, hu, hk]
  cases o k <;> rfl

theorem unknown_never_same {O : Type} [DecidableEq O] (x : Option O) :
    sameOrigin none x = false ∧ sameOrigin x none = false := by
  cases x <;> simp [sameOrigin]

theorem given_prefix (d g : List (A × B)) : ∃ suf, headers name d g = g ++ suf :=
  ⟨_, rfl⟩

theorem default_kept_iff (d g : List (A × B)) (h : A × B) (hd : h ∈ d)
    (hg : h ∉ g) :
    h ∈ headers name d g ↔ name h.1 ∉ g.map (name ∘ Prod.fst) := by
  simp [headers, List.mem_filter, hd, hg]

theorem named_given (d g : List (A × B)) (h : A × B) (hm : h ∈ headers name d g)
    (hn : name h.1 ∈ g.map (name ∘ Prod.fst)) : h ∈ g := by
  simp only [headers, List.mem_append, List.mem_filter] at hm
  rcases hm with hm | ⟨-, hf⟩
  · exact hm
  · simp_all

theorem headers_idem (d g : List (A × B)) :
    headers name d (headers name d g) = headers name d g := by
  conv => rhs; rw [← List.append_nil (headers name d g)]
  unfold headers
  congr 1
  rw [List.filter_eq_nil_iff]
  intro h hd
  simp only [Bool.not_eq_eq_eq_not, Bool.not_true, List.contains_eq_any_beq, List.any_eq_false,
    List.map_append, List.mem_append, List.mem_map, Function.comp]
  intro hall
  by_cases hn : ∃ a, a ∈ g ∧ name a.1 = name h.1
  · exact hall (name h.1) (Or.inl hn) (by simp)
  · refine hall (name h.1) (Or.inr ⟨h, ?_, rfl⟩) (by simp)
    simp only [List.mem_filter, hd, true_and, Bool.not_eq_eq_eq_not, Bool.not_true,
      List.any_eq_false, List.mem_map, Function.comp]
    rintro x ⟨a, ha, hax⟩ hb
    exact hn ⟨a, ha, by simp at hb; rw [hax, hb]⟩

end KatipoProofs.Defaults.Merge
