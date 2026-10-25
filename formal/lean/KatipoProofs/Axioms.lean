import KatipoProofs.Flow.Statements
import KatipoProofs.Flow.Executable
import KatipoProofs.Admission.Statements
import KatipoProofs.Admission.Trace
import KatipoProofs.Timer.Statements
import KatipoProofs.Upload.Statements

/-!
# Axiom pins

Every headline theorem may use only Lean's standard axioms. These
`#guard_msgs` checks make any drift -- a `sorry`, `native_decide`, or a new
`axiom` -- a build failure rather than something a reviewer must notice.
-/

open KatipoProofs

/-- info: 'KatipoProofs.Flow.Statements.credit_conservation' depends on axioms: [propext, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms Flow.Statements.credit_conservation

/-- info: 'KatipoProofs.Flow.Statements.bounded_buffering' depends on axioms: [propext, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms Flow.Statements.bounded_buffering

/-- info: 'KatipoProofs.Flow.Statements.no_lost_chunks' depends on axioms: [propext, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms Flow.Statements.no_lost_chunks

/-- info: 'KatipoProofs.Flow.Statements.paused_agrees' depends on axioms: [propext, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms Flow.Statements.paused_agrees

/-- info: 'KatipoProofs.Flow.Statements.steps_bounded' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms Flow.Statements.steps_bounded

/-- info: 'KatipoProofs.Flow.Statements.stuck_is_good' depends on axioms: [propext, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms Flow.Statements.stuck_is_good

/-- info: 'KatipoProofs.Flow.Statements.batch_gt_window_stalls' depends on axioms: [propext] -/
#guard_msgs (whitespace := lax) in #print axioms Flow.Statements.batch_gt_window_stalls

/-- info: 'KatipoProofs.Flow.Statements.clear_late_stalls' depends on axioms: [propext] -/
#guard_msgs (whitespace := lax) in #print axioms Flow.Statements.clear_late_stalls

/-- info: 'KatipoProofs.Flow.succs_iff' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms Flow.succs_iff

/-- info: 'KatipoProofs.Admission.Statements.at_most_once' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms Admission.Statements.at_most_once

/-- info: 'KatipoProofs.Admission.Statements.no_message_after_admission_error' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms Admission.Statements.no_message_after_admission_error

/-- info: 'KatipoProofs.Admission.Statements.no_delivery_after_effective_cancel' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms Admission.Statements.no_delivery_after_effective_cancel

/-- info: 'KatipoProofs.Admission.Statements.no_progress_after_stop' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms Admission.Statements.no_progress_after_stop

/-- info: 'KatipoProofs.Admission.Statements.telemetry_at_most_once' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms Admission.Statements.telemetry_at_most_once

/-- info: 'KatipoProofs.Admission.Statements.no_deadline_double_telemetry' depends on axioms: [propext] -/
#guard_msgs (whitespace := lax) in #print axioms Admission.Statements.no_deadline_double_telemetry

/-- info: 'KatipoProofs.Admission.Statements.no_deadline_double_delivery' depends on axioms: [propext] -/
#guard_msgs (whitespace := lax) in #print axioms Admission.Statements.no_deadline_double_delivery

/-- info: 'KatipoProofs.Admission.Statements.no_slack_double_delivery' depends on axioms: [propext] -/
#guard_msgs (whitespace := lax) in #print axioms Admission.Statements.no_slack_double_delivery

/-- info: 'KatipoProofs.Admission.Trace.accepted_safe' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms Admission.Trace.accepted_safe

/-- info: 'KatipoProofs.Admission.Statements.exact_refines' depends on axioms: [propext, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms Admission.Statements.exact_refines

/-- info: 'KatipoProofs.Admission.Statements.no_orphan_transfer' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms Admission.Statements.no_orphan_transfer

/-- info: 'KatipoProofs.Admission.Statements.eventual_outcome' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms Admission.Statements.eventual_outcome

/-- info: 'KatipoProofs.Admission.Statements.timer_fairness_needed' depends on axioms: [propext, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms Admission.Statements.timer_fairness_needed

/-- info: 'KatipoProofs.Flow.Statements.flow_guard_redundant' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms Flow.Statements.flow_guard_redundant

/-- info: 'KatipoProofs.Flow.Statements.flow_guard_redundant_rev' depends on axioms: [propext, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms Flow.Statements.flow_guard_redundant_rev

/-- info: 'KatipoProofs.Admission.Statements.pre_check_redundant' depends on axioms: [propext] -/
#guard_msgs (whitespace := lax) in #print axioms Admission.Statements.pre_check_redundant

/-- info: 'KatipoProofs.Admission.Statements.pre_check_redundant_rev' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms Admission.Statements.pre_check_redundant_rev

/-- info: 'KatipoProofs.Admission.Statements.no_post_check_double_delivery' depends on axioms: [propext, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms Admission.Statements.no_post_check_double_delivery

/-- info: 'KatipoProofs.Timer.Statements.timer_armed' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms Timer.Statements.timer_armed

/-- info: 'KatipoProofs.Timer.Statements.timely' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms Timer.Statements.timely

/-- info: 'KatipoProofs.Timer.Statements.not_early' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms Timer.Statements.not_early

/-- info: 'KatipoProofs.Timer.Statements.old_811_late' depends on axioms: [propext, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms Timer.Statements.old_811_late

/-- info: 'KatipoProofs.Timer.Statements.refresh_only_late' depends on axioms: [propext, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms Timer.Statements.refresh_only_late

/-- info: 'KatipoProofs.Upload.Statements.body_conserved' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms Upload.Statements.body_conserved

/-- info: 'KatipoProofs.Upload.Statements.complete_body' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms Upload.Statements.complete_body

/-- info: 'KatipoProofs.Upload.Statements.one_chunk_in_flight' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms Upload.Statements.one_chunk_in_flight

/-- info: 'KatipoProofs.Upload.Statements.one_demand' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms Upload.Statements.one_demand

/-- info: 'KatipoProofs.Upload.Statements.pause_flags_agree' depends on axioms: [propext] -/
#guard_msgs (whitespace := lax) in #print axioms Upload.Statements.pause_flags_agree

/-- info: 'KatipoProofs.Upload.Statements.protocol_order' depends on axioms: [propext, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms Upload.Statements.protocol_order

/-- info: 'KatipoProofs.Upload.Statements.no_safeguard_two_demands' does not depend on any axioms -/
#guard_msgs (whitespace := lax) in #print axioms Upload.Statements.no_safeguard_two_demands

/-- info: 'KatipoProofs.Upload.Statements.length_held' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms Upload.Statements.length_held

/-- info: 'KatipoProofs.Upload.Statements.length_complete' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (whitespace := lax) in #print axioms Upload.Statements.length_complete

/-- info: 'KatipoProofs.Upload.Statements.eager_two_chunks' does not depend on any axioms -/
#guard_msgs (whitespace := lax) in #print axioms Upload.Statements.eager_two_chunks

/-- info: 'KatipoProofs.Upload.Statements.cont_flags_drift' does not depend on any axioms -/
#guard_msgs (whitespace := lax) in #print axioms Upload.Statements.cont_flags_drift
