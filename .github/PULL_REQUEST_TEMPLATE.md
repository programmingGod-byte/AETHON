## What and why

<!-- What does this change, and what problem does it solve? Link the issue: "Fixes #123". -->

## How it works

<!-- Key design points, especially anything on the per-packet path (cost, allocations, locking). -->

## Tests

<!-- Tick what you ran and paste the summary lines. -->

- [ ] `./build/src/test_tcp_reassembly`
- [ ] `./build/src/test_tcp_fuzz`
- [ ] `tests/web_app_test/test.sh` and `test.sh --netem`
- [ ] `tests/web_app_test/torture.sh --quick`
- [ ] Added a test that fails without this change (for bug fixes)

```
paste results here
```

## Checklist

- [ ] No blocking calls, locks or unbounded loops added to the packet path
- [ ] Every new buffer holding network data has a size limit
- [ ] Packet lengths are validated before they are read
- [ ] Rebuilt and committed `src/main/ebpf/xdp_kern_prog.o` if `xdp_kern_prog.c` changed
- [ ] Updated README / docs (including Known limitations) if behavior changed
- [ ] No new compiler warnings
