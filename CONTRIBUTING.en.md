<p align="center"><a href="CONTRIBUTING.md"><img src="https://raw.githubusercontent.com/Paulo-Marcos-Lucio/laboratorio-owasp/main/assets/btn-lang-pt.svg" alt="Ler este documento em Português" width="300"/></a></p>

# Contributing

New vulnerability demonstrations are welcome — especially the seven OWASP Top 10:2025 categories that don't have a pair yet (A02, A03, A06, A07, A08, A09, and A10).

## Running

```bash
./mvnw verify            # formatting (spotless) + all tests
./mvnw spotless:apply    # fixes the formatting (google-java-format, AOSP profile)
./mvnw spring-boot:run
```

`verify` is the same command the CI runs. If it passes here, it passes there.

## Adding a Vulnerability

Each module follows the same pattern:

1. One package per vulnerability, named after the **OWASP Top 10:2025 code** plus a short suffix (e.g., `a02config` for Security Misconfiguration).
2. `vulneravel` **and** `corrigido` endpoints (or service), with a comment explaining the mistake and the principle behind the fix.
3. A test that **fires the real exploit** and asserts the behavior of both sides, in the **mirrored** test package (`src/test/java/.../a02config/`).
4. A line in the `README.md` table and an entry in `CHANGELOG.md`.

## The Test Must Fail When the Fix Disappears

This is the criterion that decides whether a PR gets merged. Delete the security control you just wrote, run `./mvnw test`, and confirm the test goes **red**. If it stays green, it isn't testing the control — it's testing something else (a DNS lookup that fails to resolve, an earlier guard, a generic error). This happened in this very repository: two SSRF tests kept passing with the entire allowlist deleted.

Asserting the **reason** for the refusal (`content().string("host fora da allowlist")`), not just the status, kills most of this class of false-green.

## A Known Limitation Is Also Content

If the fix only solves part of the problem, write that down in the javadoc and, if possible, in a test that **documents the limit** — like `SsrfLimiteRebindingTest`. Promising a defense the code doesn't have is the worst possible flaw in teaching material.
