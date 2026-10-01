# Validation

`ci.yml` resolves a fresh root lockfile once, then tests exactly that snapshot on
stable Rust natively and in a real headless browser. A separate nightly compiler
is needed for LLVM branch instrumentation. Both integer line and branch counts
must be fully covered. There are no production coverage exclusions.

The retired monolith and its evidence remain in immutable Git history, indexed
in RETIREMENT.md. The new door gate covers only current cmsg production sources.
It neither replaces leaf regression obligations nor proves current membership,
accounting, Tor networking or full-system acceptance.
Automatic validation is serialized. Expensive scale/churn belongs on owned CI.

Dependabot covers every tracked manifest. Auto-merge uses only trusted workflow
code and GitHub metadata; it requires protected main, administrator enforcement,
all substantive jobs and every exact-head check/status green. No PR checkout or
artifact is executed under the merge token.

References: [LLVM coverage](https://github.com/taiki-e/cargo-llvm-cov),
[workflow security](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflow_run).
