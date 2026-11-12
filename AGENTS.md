# Sandbox contributor instructions

Keep this repository minimal and public-safe.

- Implement the controller, scheduler, and node worker in Rust. Prefer existing runtime binaries and Linux facilities over custom replacements.
- Keep the scheduler in the controller; avoid extra services, generic plugin frameworks, and speculative distributed infrastructure.
- Use EROFS + OverlayFS for filesystem storage. Runtime candidates are runc + CRIU and runsc + native checkpointing. Never silently substitute one checkpoint format for the other.
- Separate implemented behavior, unimplemented contracts, and validated capabilities. An unavailable backend must fail closed, never return a fake running sandbox or advertise readiness.
- Require authentication for management operations. Do not expose credentials through command-line arguments, logs, committed configuration, or error bodies.
- Enforce bounded admission, restore concurrency, request sizes, subprocess output and deadlines. Keep blocking I/O off Tokio threads; never hold shared state locks across I/O.
- Network policy must be applied before untrusted processes run. Shared immutable seed/lower mounts are not writable sandbox state.
- Preserve matching filesystem and process checkpoints; retain artifacts while referenced; handle failure and restart cleanup explicitly.
- No unit tests unless the owner changes this preference. Use compilation/static checks and process-level smoke/integration validation. Do not claim a privileged runtime, isolation, or performance check passed without running it.
- Do not run privileged commands, load modules, modify host networking, or submit cluster jobs without explicit approval.
- No company names, internal endpoints, workload names, asset identifiers, credentials, private traces, or machine-specific paths in tracked content. Use generic examples. Public upstream references are fine.
- Do not copy third-party source without preserving its license and attribution. Prefer fresh small integrations.
- No subagent scratch reports, runtime state, private toolchain configuration, or downloaded binaries in the repository.
