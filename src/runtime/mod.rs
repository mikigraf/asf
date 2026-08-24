//! PostgreSQL-backed durable reactor supervisors.
//!
//! The reactor owns only orchestration: durable claims, leases, fencing,
//! bounded polling, timer promotion, retry scheduling, and shutdown. Activity
//! handlers own their domain transaction and external idempotency contracts.

mod cancellation;
mod evidence_verification;
mod handlers;
mod intake;
mod reactor;
mod runmill_observation;
mod runmill_submission_recovery;
mod runmill_terminal_evidence;
mod source_closure;
mod timers;
mod work_order_dispatch;
mod worker_reconciliation;

pub use cancellation::*;
pub use evidence_verification::*;
pub use handlers::*;
pub use intake::*;
pub use reactor::*;
pub use runmill_observation::*;
pub use runmill_submission_recovery::*;
pub use runmill_terminal_evidence::*;
pub use source_closure::*;
pub use work_order_dispatch::*;
pub use worker_reconciliation::*;
