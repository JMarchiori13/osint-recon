# Contributing to osint-recon

Thanks for your interest in contributing. This project is a security research
tool; contributions must preserve its **passive-only** scope and its ethical
framing.

## Ground rules

- **Passive techniques only.** No port scanning, no directory/file brute
  forcing, no credential testing, no exploit code. Contributions adding
  active probing will be rejected.
- **Authorized-use framing.** New modules or docs must keep the
  "for authorized security assessments only" framing prominent.
- **Keyless sources preferred.** New data sources should work without API
  keys where possible; key-based integrations must degrade gracefully when
  the key is absent.

## Development workflow

1. Fork the repository and create a feature branch.
2. Write idiomatic Rust with doc comments on all public items.
3. Handle every external call with a timeout and graceful failure
   (warn & continue — never panic on network errors).
4. Verify before submitting:
   ```sh
   cargo fmt --check
   cargo clippy --all-targets
   cargo test --release
   cargo build --release
   ```
5. Open a pull request describing the module/change, its data sources, and
   its ATT&CK mapping.

## Adding a module

- Create `src/modules/<name>.rs` implementing `pub fn run(client: &HttpClient, domain: &str) -> ModuleOutput`.
- Register it in `src/modules/mod.rs` and wire a subcommand in `src/main.rs`.
- Respect the shared `HttpClient` rate limit — never bypass it.
- Document sources, output fields and limitations in `docs/modules.md`.

## Reporting issues

Use GitHub Issues. For security-sensitive reports about the tool itself,
please describe impact without including live target data.
