# Static Security Analysis Summary

## Files Analyzed
- `tools/testing/selftests/timers/posix_timers.c`: 10 scenarios (0 confirmed vulnerabilities)
- `tools/testing/selftests/timers/nanosleep.c`: 10 scenarios (0 confirmed vulnerabilities)
- `tools/testing/selftests/timers/mqueue-lat.c`: 10 scenarios (0 confirmed vulnerabilities)
- `tools/testing/selftests/timers/set-timer-lat.c`: 10 scenarios (0 confirmed vulnerabilities)
- `ipc/msg.c`: 40 scenarios (1 confirmed vulnerability)
- `drivers/char/mem.c`: 40 scenarios (1 confirmed vulnerability)
- `net/ipv4/raw.c`: 40 scenarios (0 confirmed vulnerabilities)
- `net/ipv4/tcp_input.c`: 40 scenarios (0 confirmed vulnerabilities)
- `mm/mmap.c`: 40 scenarios (0 confirmed vulnerabilities)
- `net/core/sock.c`: 40 scenarios (0 confirmed vulnerabilities)
- `kernel/fork.c`: 40 scenarios (1 confirmed vulnerability)
- `kernel/exit.c`: 40 scenarios (0 confirmed vulnerabilities)

- `drivers/vhost/vhost.c`: 40 scenarios (2 confirmed vulnerabilities)
- `fs/eventpoll.c`: 40 scenarios (0 confirmed vulnerabilities)
## Top Findings
- Vhost ownership relies on mm equality; ptrace/CLONE_VM guests can hijack devices and stale worker lifetimes expose UAF and logging/iotlb races.
- Raw device nodes (/dev/mem and /dev/port) still expose broad physical and I/O access when STRICT_DEVMEM or capability gating is weak; mapping/write paths lack hotplug revocation and splice/mmap validation.
- SysV message queues combine RCU teardown with MSG_COPY semantics that can leak payloads without re-checking permissions and expose accounting overflows when limits are misconfigured.
- Raw IPv4 sockets clone and deliver traffic with minimal rate limiting and namespace isolation, leaving openings for VRF cross-delivery, spoofing via IP_HDRINCL, and stale error queues under close races.
- TCP input fast paths trust timestamp/prediction state, BPF callbacks, and driver-provided skb sizing, enabling memory inflation, RTT manipulation, and potential UAF/double-free conditions when routes or GRO buffers change concurrently.
- mmap flag handling and sysctl knobs expose weak ASLR/resource controls and races around MAP_FIXED, sealing, and MAP_DROPPABLE/execute-only semantics that can enable DoS or privilege escalation if combined with other bugs.
- Core socket code inherits opener credentials and offers memory bypass knobs (bypass_prot_mem, SOCK_MEMALLOC, high-order frags) that can enable privilege-confused operations or resource exhaustion, with RCU-delayed teardown leaving UAF windows.
- Fork/clone logic still has gaps around pidfd exposure, userfaultfd-writable parent_tid targets, and mixed namespace/cgroup initialization, leaving potential for pointer corruption and boundary bypass in early task setup.
- Exit path ordering mixes io_uring cancellation, task_work, and pid/signal teardown, creating UAF and notification races that warrant tighter synchronization and resource pinning.
- Epoll infrastructure depends on RCU snapshots and weak quotas for nested graphs, wakeup sources, and busy-poll metadata, creating avenues for recursion, UAF, and CPU/memory exhaustion when epoll_ctl races with teardown.
