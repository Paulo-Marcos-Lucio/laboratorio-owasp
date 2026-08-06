<p align="center"><a href="SECURITY.md"><img src="https://raw.githubusercontent.com/Paulo-Marcos-Lucio/laboratorio-owasp/main/assets/btn-lang-pt.svg" alt="Ler este documento em Português" width="300"/></a></p>

# Security Policy

This repository is a **teaching lab** and contains vulnerabilities on purpose. It is not a product — do not expose it to the internet.

The application listens only on `127.0.0.1` (`server.address` in `src/main/resources/application.properties`, with a regression test in `ConfiguracaoDeRedeTest`). This is intentional and must not be changed: `/a05/cmd/vulneravel` executes arbitrary operating-system commands with no authentication at all.

## What to Report

**In scope:** any issue **outside the educational scope** — build, CI, or Maven-wrapper configuration; a `/corrigido` side that doesn't actually fix the flaw; text that promises a defense the code doesn't have; a vulnerability that escapes the lab and threatens the machine of whoever is studying it.

**Out of scope:** the vulnerabilities in the `/vulneravel` endpoints. They are the reason this repository exists, and they are documented in the README.

Report privately to **contatopml26@gmail.com** with the prefix `[security]`. This is an educational project maintained by one person; reports are read and answered as soon as possible.

## Legal Framework (Brazil)

The techniques demonstrated here may only be used in this lab or against a system for which you have **written authorization**, with a defined scope and time window.

- **Law 12.737/2012** (Lei Carolina Dieckmann) — criminalizes breaking into someone else's computing device.
- **Law 14.155/2021** — increases the penalties for crimes committed by electronic means.
- **Law 12.965/2014** (Marco Civil da Internet) — establishes retention and confidentiality duties for logs and communications.
- **Law 13.709/2018**, the LGPD (Brazil's data-protection law, GDPR-equivalent) — covers whatever you do with any personal data reached during a test.

Verbal authorization protects no one. Without a signed contract or work order, do not test.
