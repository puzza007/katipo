import KatipoProofs.Upload.Counterexamples

/-!
# Streaming request bodies: headline statements (frozen)

Proofs live in `Upload/Proofs.lean` and `Upload/Counterexamples.lean`;
this file pins what was agreed and only delegates. Every statement holds
for every `total`, `W` and `resp` -- TLC checked 2 or 3 of each -- chunked
or with the length declared.

Re-frozen 2026-10-26 for the shipped protocol's changes: the port holds
the body to its declared length and ignores anything after eof. The
honest-caller statements gained `P.liar = false`, the caller the new
`length_*` statements cover, and `complete_body` allows a declared length
in place of the caller's eof.
-/

namespace KatipoProofs.Upload.Statements
open KatipoProofs.Upload

/-- While the worker holds the request and the conn exists, every chunk the
caller sent has been read by curl or is on its way to it: none lost or
duplicated (`BodyConserved`). -/
theorem body_conserved (P : Params) (hlr : P.liar = false) (s : St) (h : Reach P s)
    (hr : s.inReqs = true) (hl : s.live = true) : s.readN + inFlight s = s.sentN :=
  (honest_reach hlr h).1 hr hl

/-- curl finishes the upload only after every chunk, and only after the
caller's eof unless the length was declared (`CompleteBody`). -/
theorem complete_body (P : Params) (hlr : P.liar = false) (s : St) (h : Reach P s)
    (hd : s.uploadDone = true) : s.readN = P.total ∧ (P.length = true ∨ s.sentEof = true) :=
  (honest_reach hlr h).2.1.done hd

/-- A caller that sends only on demand has at most one chunk between it and
curl (`OneChunkInFlight`). The guard and the masked resume are not needed
for this. -/
theorem one_chunk_in_flight (P : Params) (he : P.eager = false) (hlr : P.liar = false)
    (hg : P.guard = true ∨ P.masked = true) (s : St) (h : Reach P s) : inFlight s ≤ 1 := by
  have := (dem_reach he hlr hg h).one
  simp only [tokens, answerable, inFlight] at this ⊢; omega

/-- At most one demand is outstanding while the worker holds the request
(`OneDemand`), given either safeguard: the one-demand guard or the masked
resume. -/
theorem one_demand (P : Params) (he : P.eager = false) (hlr : P.liar = false)
    (hg : P.guard = true ∨ P.masked = true) (s : St) (h : Reach P s) (hr : s.inReqs = true) :
    demands s ≤ 1 := by
  have := (dem_reach he hlr hg h).one
  simp only [tokens, answerable, demands, hr, ite_true] at this ⊢; omega

/-- Whatever the caller sends, curl never gets more than the declared
length (`LengthHeld`). -/
theorem length_held (P : Params) (hlen : P.length = true) (s : St) (h : Reach P s) :
    s.readN ≤ P.total := by
  have := (len_reach h).gotLe hlen; omega

/-- Whatever the caller sends, curl finishes the upload only with exactly
the declared length (`BodyIsSent`, declared length). -/
theorem length_complete (P : Params) (hlen : P.length = true) (s : St) (h : Reach P s)
    (hd : s.uploadDone = true) : s.readN = P.total :=
  (len_reach h).done hlen hd

/-- With the masked resume, katipo's pause flags always agree with curl's,
inside `curl_easy_pause` too (`SendPausedAgrees`, `RecvPausedAgrees`). -/
theorem pause_flags_agree (P : Params) (hm : P.masked = true) (s : St) (h : Reach P s) :
    s.upPaused = s.curlSendPaused ∧ s.paused = s.curlRecvPaused :=
  agree_reach hm h

/-- Nothing reaches the caller after its terminal message: no demand behind
a timeout's error, say (`ProtocolOrder`). -/
theorem protocol_order (P : Params) (s : St) (h : Reach P s) : s.orderBad = false :=
  (ord_reach h).noBad

/-- One safeguard is necessary: with neither, a second demand goes out
before the first is answered (`KatipoUploadNoGuard.cfg`). -/
theorem no_safeguard_two_demands :
    ∃ (P : Params) (s : St), P.guard = false ∧ P.masked = false ∧ P.eager = false ∧
      P.liar = false ∧ Reach P s ∧ s.inReqs = true ∧ 2 ≤ demands s := by
  obtain ⟨s, h1, h2, h3⟩ := no_guard_two_demands_proof
  exact ⟨pNoGuard, s, rfl, rfl, rfl, rfl, h1, h2, h3⟩

/-- Waiting for demand is necessary: an eager caller buffers two chunks
(`KatipoUploadEager.cfg`). -/
theorem eager_two_chunks :
    ∃ (P : Params) (s : St), P.eager = true ∧ P.guard = true ∧ P.masked = true ∧
      Reach P s ∧ 2 ≤ inFlight s := by
  obtain ⟨s, h1, h2⟩ := eager_two_chunks_proof
  exact ⟨pEager, s, rfl, rfl, rfl, h1, h2⟩

/-- The mask is necessary for the flags to agree: plain `CURLPAUSE_CONT`
leaves `paused` set while curl is receiving (`KatipoUploadContAgrees.cfg`). -/
theorem cont_flags_drift :
    ∃ (P : Params) (s : St), P.masked = false ∧ P.guard = true ∧ Reach P s ∧
      s.unpausing = false ∧ s.paused ≠ s.curlRecvPaused := by
  obtain ⟨s, h1, h2, h3⟩ := cont_flags_drift_proof
  exact ⟨pCont, s, rfl, rfl, h1, h2, h3⟩

end KatipoProofs.Upload.Statements
