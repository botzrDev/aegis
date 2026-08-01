//! Compile-time guard on the Aegis public API surface (AEG-45).
//!
//! This crate ships no code. It exists so `tests/ui/*.rs` can be compiled by
//! trybuild against the runtime stack with **default features only** — the
//! configuration a real consumer gets. The `compile_fail` cases are the
//! executable form of "this is not public API": if one of them starts
//! compiling, the surface regressed.
//!
//! It must stay a separate workspace member. `botzr-aegis-runtime`,
//! `-sandbox` and `-capability` each carry a self dev-dependency that turns on
//! `test-utils` for their own tests; trybuild derives each ui case's manifest
//! from its *host* package, so a suite living inside one of those crates would
//! inherit `test-utils` and the "fixture API is absent" cases would pass by
//! compiling instead of failing.
