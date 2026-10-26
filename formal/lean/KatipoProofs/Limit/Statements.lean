import KatipoProofs.Limit.Proofs

/-!
# `max_body_size`: headline statements (frozen 2026-10-26)

For any limit and any chunk sizes curl hands `write_cb`. Proofs live in
`Limit/Proofs.lean`; this file pins what was agreed and only delegates.
-/

namespace KatipoProofs.Limit.Statements
open KatipoProofs.Limit

/-- Without a usable Content-Length (unknown, or the body is encoded), the
transfer fails exactly when the decoded body is larger than the limit. -/
theorem fails_iff (limit : Nat) (cs : List Nat) :
    (run limit none 0 cs).2 = true ↔ limit < total cs := by
  simpa using fails_iff_none limit cs 0 (Nat.zero_le _)

/-- Whatever the Content-Length says, no more than `limit` bytes are ever
forwarded... -/
theorem forwarded_le (limit : Nat) (cl : Option Nat) (cs : List Nat) :
    total (run limit cl 0 cs).1 ≤ limit := by
  simpa using forwarded_within limit cl cs 0 (Nat.zero_le _)

/-- ...and they are the body's first chunks, in order... -/
theorem forwarded_is_prefix (limit : Nat) (cl : Option Nat) (cs : List Nat) :
    ∃ rest, cs = (run limit cl 0 cs).1 ++ rest :=
  forwarded_prefix limit cl cs 0

/-- ...all of them, unless the transfer failed. -/
theorem forwarded_all (limit : Nat) (cl : Option Nat) (cs : List Nat)
    (h : (run limit cl 0 cs).2 = false) : (run limit cl 0 cs).1 = cs :=
  all_unless_failed limit cl cs 0 h

/-- A refused chunk is one that would have taken the body past the limit,
so nothing that fits is refused. -/
theorem refused_overflows (limit : Nat) (cs : List Nat)
    (h : (run limit none 0 cs).2 = true) :
    ∃ c rest, cs = (run limit none 0 cs).1 ++ c :: rest ∧
      limit < total (run limit none 0 cs).1 + c := by
  simpa using Limit.refused_overflows limit cs 0 h

/-- The up-front Content-Length check only fails sooner: with an honest
Content-Length the verdict is the same as without it, and a failure
forwards nothing. -/
theorem upfront_only_sooner (limit : Nat) (cs : List Nat) (hpos : ∀ c ∈ cs, 0 < c) :
    (run limit (some (total cs)) 0 cs).2 = (run limit none 0 cs).2 ∧
      ((run limit (some (total cs)) 0 cs).2 = true →
        (run limit (some (total cs)) 0 cs).1 = []) :=
  honest_upfront limit cs hpos

end KatipoProofs.Limit.Statements
