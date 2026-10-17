import KatipoProofs.Admission.Trace

/-!
`lake exe tracecheck FILE...`: replay the traces `test/katipo_trace.erl`
wrote (one `<slot> <event> <args>` line per event) against the admission
model, one worker slot at a time. Exits non-zero on any rejected slot.
-/

open KatipoProofs.Admission.Trace

def parseBit : String → Option Bool
  | "0" => some false
  | "1" => some true
  | _ => none

def parseRes : String → Option Res
  | "ok" => some .ok
  | "expired" => some .expired
  | "timeout" => some .timeout
  | "died" => some .died
  | _ => none

def parseEv : List String → Option Ev
  | ["start"] => some .start
  | ["send", a] => .send <$> a.toNat?
  | ["result", r, a] => .result <$> a.toNat? <*> parseRes r
  | ["cancel", a] => .cancel <$> a.toNat?
  | ["pre", a, l] => .pre <$> a.toNat? <*> parseBit l
  | ["recv", a, l] => .recv <$> a.toNat? <*> parseBit l
  | ["post", a, l] => .post <$> a.toNat? <*> parseBit l
  | ["admit", a, l] => .admit <$> a.toNat? <*> parseBit l
  | ["resp", a, b] => .resp <$> a.toNat? <*> parseBit b
  | ["chunk", a, b] => .chunk <$> a.toNat? <*> parseBit b
  | ["wcancel", a, b] => .wcancel <$> a.toNat? <*> parseBit b
  | "crash" :: as => .crash <$> as.mapM String.toNat?
  | _ => none

/-- Events grouped by slot, slots in order of first appearance. -/
def group (lines : List String) : Except String (List (String × List Ev)) := do
  let mut slots : Array (String × Array Ev) := #[]
  for (l, i) in lines.zipIdx do
    match l.splitOn " " |>.filter (· ≠ "") with
    | [] => pure ()
    | slot :: rest =>
      let some e := parseEv rest | throw s!"line {i + 1}: cannot parse {l}"
      match slots.findIdx? (·.1 == slot) with
      | some j => slots := slots.modify j fun (s, es) => (s, es.push e)
      | none => slots := slots.push (slot, #[e])
  return slots.toList.map fun (s, es) => (s, es.toList)

def main (args : List String) : IO UInt32 := do
  let mut bad := 0
  for file in args do
    let lines := (← IO.FS.readFile file).splitOn "\n"
    match group lines with
    | .error e => IO.eprintln s!"{file}: {e}"; bad := bad + 1
    | .ok slots =>
      let mut events := 0
      for (slot, evs) in slots do
        events := events + evs.length
        match check evs with
        | .ok c =>
          let open_ := c.1.ids.filter fun a => (c.1.owed a).isSome || c.1.st.pending a
          unless open_.isEmpty do
            IO.println s!"{file}: {slot}: note: attempts {open_} never reported a caller outcome"
        | .error (i, msg) =>
          bad := bad + 1
          IO.eprintln s!"{file}: {slot}: REJECTED at event {i} ({repr evs[i]?}): {msg}"
      IO.println s!"{file}: {slots.length} slots, {events} events checked"
  if bad == 0 then
    IO.println "OK: every trace is a run of the admission model"
    return 0
  return 1
