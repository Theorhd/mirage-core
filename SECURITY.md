# Security Policy

`mirage-core` is security- and privacy-critical software: vulnerabilities may expose users to identification, traffic interception, or censorship. Please report them **privately**.

## Supported Versions

The project is pre-release. Only the latest commit on `main` receives security fixes.

| Version | Supported |
| --- | --- |
| `main` (latest) | ✅ |
| Anything else | ❌ |

## Reporting a Vulnerability

**Do not open a public issue, discussion, or pull request for security problems.**

The only reporting channel is **GitHub Private Vulnerability Reporting** — *Security* tab → *Report a vulnerability*.

Please include:

* Affected component (`mirage-core` parser/crypto/state machine, `miraged` runtime, container/deployment, docs).
* Impact (e.g. remote DoS, active-probing distinguisher, credential/key leak, SSRF, PII in logs, retroactive de-anonymization).
* Reproduction steps or proof-of-concept (raw byte sequences are ideal for Sans-I/O components).
* Affected commit hash.

**Do not include real user credentials, share links, or captured traffic of third parties.**

## Response Process

| Step | Target |
| --- | --- |
| Acknowledgement | within 72 hours |
| Triage & severity assessment | within 7 days |
| Fix or mitigation | within 90 days (faster for critical issues) |
| Coordinated public disclosure | after a fix is released, by mutual agreement |

Reporters are credited in the advisory unless they prefer to remain anonymous.

## Scope

In scope:

* Anything that lets an unauthenticated party distinguish a `miraged` server from its `dest` (active-probing distinguishers are treated as **high severity**).
* Panics, crashes, or resource exhaustion reachable from unauthenticated input.
* Authentication bypass, replay acceptance, timing side-channels on credentials.
* Leakage of secrets or PII (memory, logs, errors, crash output, container metadata).
* SSRF / egress-policy bypass from authenticated clients.
* Supply-chain issues in the build, release, or container pipeline.

Out of scope:

* Attacks requiring live root/hypervisor access to the host.
* Global passive adversary end-to-end traffic correlation.
* Vulnerabilities in third-party clients (report upstream).

## Safe Harbor

Good-faith research that respects user privacy, avoids service degradation of infrastructure you do not own, and follows this policy will not be pursued legally by the maintainers. Only test against servers you own or are explicitly authorized to test.

## Project Privacy Commitment

`mirage-core` contains **no telemetry**, phones home to nothing, and by default logs no client IPs, SNIs, credentials, or destinations.
