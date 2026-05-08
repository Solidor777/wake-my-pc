// daemon: M0 stub. Real listener + OS sleep integration lands in M2.
// Process exits cleanly with code 0 — never panics in production paths
// (Principle 2). Startup-time errors below print and return ExitCode::FAILURE
// rather than `.unwrap()`-ing.

use std::process::ExitCode;

fn main() -> ExitCode {
    println!("{}", wake_my_pc_core::hello());
    println!("daemon: M0 stub — listener arrives in M2");
    ExitCode::SUCCESS
}
