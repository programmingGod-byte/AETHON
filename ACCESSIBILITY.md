# Accessibility

Aethon is a command-line network security tool and a set of documents. We want everyone who wants to build, run, test or contribute to it to be able to do so, including people who use screen readers, magnification, high-contrast settings, keyboard-only navigation or alternative input.

## Our commitment

- Documentation is written in plain Markdown with real headings, lists and tables, so it works with screen readers, browser zoom and text-only browsers.
- Instructions are given as copyable commands, never only as screenshots or videos.
- Diagrams in the documentation are ASCII text and are always explained in the surrounding prose.
- Information is never conveyed by color alone in new documentation.
- We treat accessibility barriers as bugs.

## Supported environments

| Area | Supported |
|---|---|
| Operating system | Linux with XDP and AF_XDP support (developed on kernel 6.x/7.x) |
| Architecture | x86_64 (other architectures are untested) |
| Interfaces | Any terminal; the tool has no graphical interface |
| Documentation | GitHub's Markdown rendering, any text editor, and the project website in `docs/` |

## Known limitations

- **Colored and decorated terminal output.** Some scripts (`veth0.bash`, `tests/run_tests.sh`, `tests/web_app_test/*.sh`) use ANSI colors and emoji. Results are always also written as text (`PASS`, `FAIL`, `INFO`, `[IPS BLOCK]`), so nothing depends on color alone, but emoji may be read out verbosely by screen readers.
- **Live statistics overwrite one terminal line.** The `[Stats]` line in `afxdp_control` uses carriage returns to redraw itself, which screen readers may announce repeatedly or not at all. A plain-log mode is planned.
- **Log output is unstructured.** Alerts are multi-line human-readable text, not a structured format that assistive or monitoring tools can filter easily.
- **The project website** (`docs/index.html`) has not yet been audited against WCAG 2.2.
- **Running Aethon requires root** and a Linux environment, which may be difficult on some managed or assistive-technology setups; the offline tests (`test_tcp_reassembly`, `test_tcp_fuzz`) need neither.

## Reporting a barrier

If something in Aethon or its documentation is hard or impossible for you to use, please tell us:

- open an issue using the **Bug report** form and add "accessibility" to the title, or
- if you prefer not to post publicly, contact the repository owner (programmingGod-byte) privately on GitHub.

Please describe what you were trying to do, what got in the way, and the assistive technology or setup you use, if you are comfortable sharing it. We aim to respond within 14 days.
