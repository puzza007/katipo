import KatipoProofs.Flow.Executable
import Std.Data.HashSet

/-! Enumerate the Lean flow model's reachable graph for the instance in
`formal/KatipoFlow.cfg` (or, with argument `crash` or `limit`,
`KatipoFlowCrash.cfg` or `KatipoFlowLimit.cfg`) and print it in TLC's value
syntax: one `I <state>` line for the initial state and one
`E <state> => <state>` line per non-stuttering edge.
Run: `lake env lean --run scripts/FlowGraph.lean [crash | limit]`. -/

open KatipoProofs.Flow

def P0 : Params := ⟨2, 4, 1, true, true, true, false, true, false, true, by decide, by decide⟩
def PCrash : Params := ⟨2, 4, 1, true, true, true, true, true, false, true, by decide, by decide⟩
def PLimit : Params := ⟨2, 4, 1, true, true, true, true, true, true, true, by decide, by decide⟩

def tb (b : Bool) : String := if b then "TRUE" else "FALSE"
def tm : Msg → String
  | .headers => "\"headers\"" | .chunk => "\"chunk\""
  | .done => "\"done\"" | .error => "\"error\""
def tseq (xs : List String) : String := "<<" ++ ", ".intercalate xs ++ ">>"

def render (s : St) : String :=
  ";".intercalate [
    s!"cancelQ={if s.cancelQ then tseq ["\"cancel\""] else tseq []}",
    s!"cancelled={tb s.cancelled}", s!"chunksSeen={s.chunksSeen}",
    s!"curlPaused={tb s.curlPaused}", s!"flowQ={tseq (s.flowQ.map toString)}",
    s!"headersSent={tb s.headersSent}", s!"inReqs={tb s.inReqs}",
    s!"live={tb s.live}", s!"orderBad={tb s.orderBad}", s!"owed={s.owed}",
    s!"pQ={tseq (s.pQ.map toString)}", s!"paused={tb s.paused}",
    s!"remaining={s.remaining}", s!"seenDone={tb s.seenDone}",
    s!"seenError={tb s.seenError}", s!"seenHeaders={tb s.seenHeaders}",
    s!"toC={tseq (s.toC.map tm)}", s!"toW={tseq (s.toW.map tm)}",
    s!"unpausing={tb s.unpausing}", s!"window={s.window}",
    s!"pAlive={tb s.pAlive}", s!"wAlive={tb s.wAlive}", s!"exitPending={tb s.exitQ}",
    s!"failed={tb s.failed}"]

partial def bfs (P0 : Params) (frontier : List St) (seen : Std.HashSet St) (out : Array String) :
    Array String :=
  match frontier with
  | [] => out
  | s :: rest =>
    let ts := succs P0 s
    let out := ts.foldl (fun o t => if t == s then o else o.push s!"E {render s} => {render t}") out
    let (seen, next) := ts.foldl (fun (sn, nx) t =>
      if sn.contains t then (sn, nx) else (sn.insert t, t :: nx)) (seen, [])
    bfs P0 (rest ++ next.reverse) seen out

def main (args : List String) : IO Unit := do
  let P0 := if args == ["crash"] then PCrash else if args == ["limit"] then PLimit else P0
  let s0 := init P0
  let edges := bfs P0 [s0] ((({} : Std.HashSet St).insert s0)) #[]
  IO.println s!"I {render s0}"
  for e in edges do IO.println e
