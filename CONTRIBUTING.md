# Contributing to Aethon

Thanks for your interest in Aethon. This guide explains how to set up a development environment, which tests to run, and what a good pull request looks like.

By participating you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md). Security problems must **not** be reported in public issues; see [SECURITY.md](SECURITY.md).

## Ways to contribute

- Report bugs with a reproducible test case (the [bug report form](.github/ISSUE_TEMPLATE/bug_report.yml) asks for the details we need).
- Fix a [known limitation](README.md#known-limitations) or an item from the [roadmap](README.md#roadmap).
- Add tests, especially failing ones that reproduce a bug.
- Improve documentation, including corrections where the docs claim more than the code does.

For larger changes (new protocol features, changes to the packet path, new dependencies), open an issue first so the design can be discussed before you invest time.

## Development setup

```bash
sudo apt install -y build-essential cmake clang llvm pkg-config \
    libxdp-dev libbpf-dev libhyperscan-dev libssl-dev liburing-dev
./build.sh                    # Debug build in build/
./build.sh --release          # Release build (-O3)
```

Running Aethon needs root (XDP attach, AF_XDP sockets). Always develop against the virtual network from `veth0.bash`, never against the interface you use for SSH.

## Tests

Run these before opening a pull request:

| Command | Root | Required for |
|---|---|---|
| `./build/src/test_tcp_reassembly` | no | every change |
| `./build/src/test_tcp_fuzz` | no | every change to `src/main/transport/` |
| `tests/web_app_test/test.sh` and `test.sh --netem` | yes | changes to TCP, TLS, the pipeline or the XDP program |
| `tests/web_app_test/torture.sh --quick` | yes | changes to TCP, TLS or memory management |

Setup for the root-level suites: [`tests/web_app_test/test.txt`](tests/web_app_test/test.txt).

When you fix a bug, add a test that fails without the fix. For reassembly bugs, a case in `tests/test_tcp_reassembly.cpp` (no root needed) is ideal.

## Coding guidelines

- **C++20**, matching the surrounding style: `AETHON_ALWAYS_INLINE`, `AETHON_LIKELY`/`AETHON_UNLIKELY`, `noexcept` on the hot path.
- **The packet path must not block.** No blocking syscalls, sleeps, locks or unbounded loops in code that runs per packet. Backend I/O goes through epoll.
- **No allocation per packet** where it can be avoided; use preallocated buffers and pools.
- **Every buffer that holds attacker-controlled data needs a hard limit** and a defined action when the limit is reached.
- **Validate lengths before every read** from a packet (`tot_len`, IHL, `doff`, TLS lengths) against the bytes actually received.
- **One owner per data structure.** Session tables are per worker thread; anything shared between workers must be explicitly synchronized.
- Keep comments short and explain *why*, not *what*.
- Compile without new warnings (`-Wall -Wextra`).

## Commits and pull requests

- Use [Conventional Commits](https://www.conventionalcommits.org/) prefixes, as in the existing history: `fix(tcp): ...`, `feat(tls): ...`, `test: ...`, `docs: ...`, `perf(af_xdp): ...`.
- Explain the problem and the reason for the change in the commit body, not only what changed.
- Keep pull requests focused: one logical change per PR.
- Fill in the [pull request template](.github/PULL_REQUEST_TEMPLATE.md), including which tests you ran.
- Do not commit build output. The exception is `src/main/ebpf/xdp_kern_prog.o`, which is tracked; if you change `xdp_kern_prog.c`, rebuild and commit the object too. If it conflicts in a merge, rebuild it from the merged source instead of picking a side.

## License

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE) (GPL-2.0 for `src/main/ebpf/xdp_kern_prog.c`).
