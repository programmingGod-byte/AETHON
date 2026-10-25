# Security Policy

Aethon processes untrusted network traffic, so security bugs matter here more than in most projects. Thank you for reporting them responsibly.

## Supported versions

Aethon has no tagged releases yet. Only the latest commit on `main` is supported; fixes are not backported.

| Version | Supported |
|---|---|
| `main` (latest) | ✅ |
| older commits | ❌ |

## Reporting a vulnerability

**Do not open a public issue, discussion or pull request for a security problem.**

Report it privately through GitHub:

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability** (GitHub private vulnerability reporting).
3. Describe the issue (see below).

If that option is unavailable, contact the repository owner (programmingGod-byte) privately on GitHub and ask for a private channel. Do not include exploit details in the first message.

Please include:
- the affected component (XDP program, TCP stack, TLS handling, DPI, configuration parsing, ...) and commit hash;
- the impact you observed or expect (crash, memory corruption, inspection bypass, denial of service, data leak);
- steps or a minimal packet sequence to reproduce it, ideally runnable on the veth test network from `veth0.bash`;
- any suggested fix.

## What to expect

- Acknowledgement within **7 days**.
- An initial assessment within **14 days**, including whether we consider it a vulnerability.
- A fix as soon as practical, usually within 90 days. We will agree on a disclosure date with you and credit you in the fix commit and advisory unless you prefer to stay anonymous.

## Scope

In scope:
- memory-safety bugs reachable from network input (out-of-bounds reads or writes, use-after-free, overflows);
- ways to bypass inspection (DPI evasion, SNI policy bypass, TCP overlap or reassembly evasion);
- remotely triggerable denial of service (crashes, unbounded memory growth, frame or session leaks, livelocks);
- reaching a protected backend without passing through Aethon, when configured as documented.

Out of scope:
- the [known limitations](README.md#known-limitations) listed in the README (they are documented and tracked);
- attacks that require root on the host running Aethon;
- volumetric floods that exceed the link or host capacity;
- findings in third-party rule files in `rules/`.

## Safe harbor

We will not pursue legal action against researchers who act in good faith: test only against systems you own or are authorized to test, avoid privacy violations and service disruption to others, and give us reasonable time to fix the issue before public disclosure.
