### ipc/msg.c — ipc/msg.c-0031: msgrcv MSG_COPY skips repeated permission checks

**What is the attack?**  
- A caller performs an initial `msgrcv` with `MSG_COPY`, which runs `security_msg_queue_msgrcv()` once to approve access. The message remains on the queue. The attacker then issues repeated `MSG_COPY` requests on the same message after dropping privileges or changing LSM context; subsequent copies bypass any further permission checks and still return the payload.

**What can an attacker do?**  
- Continuously read sensitive message payloads without consuming them, even after losing privileges or moving namespaces. This can leak data meant for more privileged receivers and enable replay or side-channel observation of queue contents.

**What’s the impact?**  
- Unauthorized disclosure of SysV message contents (info leak) across credential changes or namespaces. The issue is reachable by local unprivileged users when `CONFIG_CHECKPOINT_RESTORE` is enabled and `MSG_COPY` is permitted.

**Which code files need manual audit to confirm this?**  
- `ipc/msg.c`: `find_msg()`, `do_msgrcv()` and `store_msg()` MSG_COPY handling.  
- `ipc/util.h`: helper definitions for message lifetime and `security_msg_queue_msgrcv()` hooks.  
- LSM modules implementing `security_msg_queue_msgrcv` to see whether they rely on per-copy invocation.

**Where is the vulnerable code snippet?**  
- `ipc/msg.c:1053-1098` – `find_msg()` performs the security hook once, stores the `msg` pointer, and returns it for MSG_COPY without taking an extra reference or rechecking permissions on subsequent copies.【F:ipc/msg.c†L1053-L1098】

**What’s the fix (high-level)?**  
- Re-run `security_msg_queue_msgrcv()` on every `MSG_COPY` request or mark the message as consumed on copy. Alternatively, disallow multiple MSG_COPY operations per message or take a refcounted snapshot that cannot be re-used without a new permission check.

---

### drivers/char/mem.c — drivers/char/mem.c-0001: /dev/mem arbitrary physical read without STRICT_DEVMEM

**What is the attack?**  
- With `CONFIG_STRICT_DEVMEM` disabled, `page_is_allowed()` unconditionally returns true. Any local user can open `/dev/mem` and read arbitrary PFNs. No capability gating or resource validation is performed, so the attacker directly reads kernel memory and MMIO regions.

**What can an attacker do?**  
- Extract kernel secrets, credentials, or modify attack gadgets by mapping sensitive physical ranges. This breaks kernel/user isolation entirely on affected configurations.

**What’s the impact?**  
- High-impact information disclosure and potential privilege escalation by reading or interacting with device memory, applicable to local users on systems built without STRICT_DEVMEM or with permissive arch overrides.

**Which code files need manual audit to confirm this?**  
- `drivers/char/mem.c`: `page_is_allowed()`, `read_mem()`, and `mmap_mem()` paths.  
- Architecture overrides of `phys_mem_access_prot_allowed` and `valid_phys_addr_range` to see whether any platforms narrow access.  
- Security policy modules or SELinux device node labeling that might mitigate access.

**Where is the vulnerable code snippet?**  
- `drivers/char/mem.c:59-92` – `read_mem()` consults `page_is_allowed()` which returns `1` when STRICT_DEVMEM is off, letting any PFN be read without capability checks.【F:drivers/char/mem.c†L59-L92】

**What’s the fix (high-level)?**  
- Enable `CONFIG_STRICT_DEVMEM` by default and require `CAP_SYS_RAWIO` for /dev/mem access. Consider default-deny architectures and perform resource-tree validation for PFNs before allowing reads or mappings.

### kernel/fork.c — kernel/fork.c-0021: CLONE_PARENT pointer reuse with userfaultfd leads to pid write to attacker page

**What is the attack?**  
- A privileged helper or setuid program calls `clone3()` with `CLONE_PARENT_SETTID`, writing the child PID into a user pointer. The attacker registers a userfaultfd handler on that pointer and remaps it during the fault window so that `put_user()` in `copy_process()` writes into an attacker-chosen mapping (or alias of kernel text when lacking write-protection enforcement).

**What can an attacker do?**  
- Corrupt arbitrary user-controlled mappings or writable aliases, potentially modifying privileged code/data pages if a writable alias exists, enabling local privilege escalation or crashing the system through malicious writes.

**What’s the impact?**  
- Integrity violation leading to LPE or targeted data corruption. The attack requires local access but can be mounted from a container with userfaultfd and a cooperating privileged helper using `CLONE_PARENT_SETTID`.

**Which code files need manual audit to confirm this?**  
- `kernel/fork.c`: `kernel_clone()` and the `put_user()` path around `args->parent_tid` handling.
- `mm/userfaultfd.c`: userfaultfd write-protect and remapping semantics.
- Architecture-specific `uaccess` implementations to verify whether `put_user()` can touch remapped aliases.

**Where is the vulnerable code snippet?**  
- `kernel/fork.c:2666-2670`: writes child PID to `args->parent_tid` via `put_user()` without pinning or prohibiting userfaultfd-remapped memory.

**What’s the fix (high-level)?**  
- Copy the parent_tid pointer into a pinned kernel buffer before writing, or fault in and pin the destination page. Alternatively, disallow `CLONE_PARENT_SETTID` for userfaultfd-managed regions or require a stable kernel-validated pointer for pid writes.


### drivers/vhost/vhost.c — drivers/vhost/vhost.c-0010: VHOST_SET_OWNER bypass with shared mm reuse

**What is the attack?**  
- Setup: a privileged process opens /dev/vhost-* and becomes owner. An unprivileged thread shares the same mm via CLONE_VM or ptrace.  
- Trigger: the unprivileged thread issues vhost configuration ioctls (e.g., worker attachment) while sharing the mm.  
- Mechanism: `vhost_dev_check_owner` only compares `dev->mm` with `current->mm` (lines 629-634), so any task sharing the mm passes ownership checks. Subsequent ioctls in `vhost_worker_ioctl` (1012-1092) rely on this check and allow full reconfiguration.

**What can an attacker do?**  
- Hijack the existing vhost instance to attach malicious workers, rewrite memory tables, and direct virtqueue buffers to controlled addresses, enabling kernel memory corruption or leakage.  
- Override device configuration without being the original opener, enabling cross-tenant interference.

**What’s the impact?**  
- Boundary bypass that can escalate privileges from an mm-sharing unprivileged task to full control over the vhost backend.  
- Applies when CONFIG_VHOST is enabled and ptrace or CLONE_VM is allowed between attacker and owner.

**Which code files need manual audit to confirm this?**  
- `drivers/vhost/vhost.c`: `vhost_dev_check_owner`, `vhost_worker_ioctl`, other ioctls relying on mm-only ownership.  
- `drivers/vhost/net.c` or other vhost frontends: call sites using `vhost_dev_check_owner`.  
- `drivers/vhost/vhost.h`: ownership fields and credential tracking.

**Where is the vulnerable code snippet?**  
- `drivers/vhost/vhost.c:629-634` – owner check compares only `dev->mm` with `current->mm`.  
- `drivers/vhost/vhost.c:1012-1092` – ioctls proceed after mm-only ownership validation.

**What’s the fix (high-level)?**  
- Tie ownership to credentials or pidfd rather than mm; store opener creds and validate on every ioctl.  
- Block ptrace/CLONE_VM sharing from granting implicit ownership and require CAP_SYS_ADMIN or equivalent for ownership transfer.

### drivers/vhost/vhost.c — drivers/vhost/vhost.c-0040: vhost_dev_check_owner permits ptrace hijack of device

**What is the attack?**  
- Setup: a privileged owner task controls the vhost device; an attacker ptraces the owner.  
- Trigger: the attacker injects ioctls while sharing the owner’s mm.  
- Mechanism: ownership validation in `vhost_dev_check_owner` (629-634) is satisfied by mm equality, so ptraced tasks inherit full vhost privileges; configuration ioctls (1012-1092) accept these calls.

**What can an attacker do?**  
- Reconfigure vring addresses to point at kernel memory or attacker-controlled pages, leak host data, or crash the kernel.  
- Perform cross-VM interference by altering queues of another tenant’s vhost device.

**What’s the impact?**  
- Local privilege escalation via ptrace or mm-sharing, applicable wherever CONFIG_VHOST is enabled and ptrace of the owner is possible.  
- Potential to abuse vhost data path for arbitrary kernel memory access.

**Which code files need manual audit to confirm this?**  
- `drivers/vhost/vhost.c`: `vhost_dev_check_owner`, `vhost_worker_ioctl`, vring setup ioctls.  
- `drivers/vhost/*`: frontends invoking the shared ownership helper.  
- Security modules interacting with ptrace restrictions to understand exposure.

**Where is the vulnerable code snippet?**  
- `drivers/vhost/vhost.c:629-634` – mm-only ownership check.  
- `drivers/vhost/vhost.c:1012-1092` – ioctls accepting ptraced caller after the check.

**What’s the fix (high-level)?**  
- Make ownership credential-based and refuse ioctls from ptrace-attached or mm-shared tasks unless they are the opener; consider pidfd-based ownership and LSM hooks.  
- Optionally require CAP_SYS_ADMIN or a dedicated capability to adopt ownership when mm is shared.

Selected target file: net/netfilter/nf_tables_api.c

### net/netfilter/nf_tables_api.c — net/netfilter/nf_tables_api.c-0001: Commit mutex leak on unbound set rejection

**What is the attack?**  
- Setup: CAP_NET_ADMIN attacker crafts a transaction that adds an unbound anonymous set or chain and drives it to commit.  
- Trigger: nf_tables_commit() rejects the unbound object and returns -EINVAL in the early binding-check path.  
- Mechanism: nf_tables_valid_genid() takes nft_net->commit_mutex, but the early return at the unbound-set/chain check exits before the mutex is released or abort cleanup runs, permanently leaving the commit_mutex locked for that netns and blocking all subsequent nftables operations.

**What can an attacker do?**  
- Permanently DoS nftables configuration in the affected netns (or host namespace) until reboot by locking commit_mutex.  
- Prevent firewall updates, enabling policy freeze or outage for other tenants sharing the namespace.

**What’s the impact?**  
- Persistent control-plane DoS reachable by CAP_NET_ADMIN (including privileged containers with that capability).  
- No packet-data corruption required; the lockout blocks all further netfilter updates.

**Which code files need manual audit to confirm this?**  
- `net/netfilter/nf_tables_api.c`: `nf_tables_commit()` binding checks and error paths; `nf_tables_valid_genid()` lock handling.  
- Netlink plumbing in `net/netfilter/nfnetlink.c` to confirm commit/abort expectations around commit_mutex.

**Where is the vulnerable code snippet?**  
- `net/netfilter/nf_tables_api.c:10890-10909` – early return on unbound set/chain skips cleanup.  
- `net/netfilter/nf_tables_api.c:11497-11505` – commit_mutex acquisition relies on commit to release it.

**What’s the fix (high-level)?**  
- Ensure all commit error exits release commit_mutex, e.g., by funneling to nf_tables_abort or explicitly unlocking on failure paths.  
- Consider rejecting unbound objects earlier during parsing or preventing their enqueue onto commit_list to avoid partial transactions.
### drivers/tty/pty.c — drivers/tty/pty.c-0025: ptm_open_peer use-after-free via late devpts_kill

**What is the attack?**  
- **Setup:** A master is opened via `/dev/ptmx`; an attacker retains the master file descriptor while fault-injection or namespace teardown causes `ptmx_open` to hit an error path that calls `tty_release` and `devpts_kill_index` (lines 789-840), freeing `driver_data` and the associated devpts entry.  
- **Trigger:** Before the close completes, a racing thread issues `TIOCGPTPEER` on the same master fd. `ptm_open_peer_file` constructs a `path` from `tty->link->driver_data` without validating liveness or holding `devpts_mutex` (lines 600-621).  
- **Mechanism:** Because the devpts entry was freed by the error path, `tty->link->driver_data` points to freed memory when dereferenced by `dentry_open`, producing a reliable use-after-free window controlled by the attacker.

**What can an attacker do?**  
- Crash the kernel via UAF in `dentry_open`, or leak heap contents through the freed dentry object.  
- Potentially steer the open toward attacker-controlled memory if slab reuse is predictable, enabling more targeted corruption.

**What’s the impact?**  
- Local privilege escalation opportunity via controlled UAF; at minimum, a reliable kernel crash/persistent DoS.  
- Requires `CONFIG_UNIX98_PTYS` and the ability to issue `TIOCGPTPEER` on a master fd during an induced `ptmx_open` failure.

**Which code files need manual audit to confirm this?**  
- `drivers/tty/pty.c`: `ptm_open_peer_file` (600-621), `ptmx_open` error paths and `tty_release`/`devpts_kill_index` handling (789-840).  
- `fs/devpts/*`: lifetime rules for devpts dentries and how `devpts_kill_index` frees them.  
- `drivers/tty/tty_io.c`: `tty_release` interactions with `driver_data` and file lists.

**Where is the vulnerable code snippet?**  
- `drivers/tty/pty.c:600-621`: `ptm_open_peer_file` builds `path` from `tty->link->driver_data` without any lifetime guard.  
- `drivers/tty/pty.c:789-840`: `ptmx_open` error cleanup calls `tty_release`/`devpts_kill_index`, dropping the very `driver_data` pointer later dereferenced.

**What’s the fix (high-level)?**  
- Reject `TIOCGPTPEER` once `TTY_IO_ERROR` is set or after the master enters the error cleanup path.  
- Take a `dget`/mount reference or hold `devpts_mutex` around `driver_data` use in `ptm_open_peer_file`.  
- Alternatively, clear `driver_data` and mark the master as dead before `tty_release` so peer opens cannot proceed on freed state.

