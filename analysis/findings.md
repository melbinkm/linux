### drivers/vhost/scsi.c — drivers/vhost/scsi.c-0002: Denial of Service via Stalled Worker in vhost_scsi_handle_vq

**What is the attack?**
- **Setup:** A standard vhost-scsi configuration with a malicious guest.
- **Trigger:** The guest issues a large number of SCSI commands that complete almost immediately or are aborted/failed rapidly.
- **Mechanism:**
  - `vhost_scsi_handle_vq` processes incoming commands. It has a weight check for incoming commands.
  - However, when commands complete, `vhost_scsi_complete_cmd_work` is scheduled.
  - This function iterates over `svq->completion_list` using `llist_del_all`.
  - If the completion list contains a massive number of commands (e.g., thousands or millions, if the guest managed to queue them), `vhost_scsi_complete_cmd_work` will loop processing all of them without yielding or checking limits.
  - This stalls the vhost worker thread, preventing other work (other VQs, other devices sharing the worker) from running.

**What can an attacker do?**
- **Impact:** Persistent Denial of Service (DoS) on the host's vhost worker thread.
- **Capability:** A single guest can monopolize the shared worker thread, affecting other guests or devices.

**What’s the impact?**
- **Severity:** Medium.
- **Prerequisites:** Malicious guest.

**Which code files need manual audit to confirm this?**
- `drivers/vhost/scsi.c`: `vhost_scsi_complete_cmd_work`.

**Where is the vulnerable code snippet?**
```c
drivers/vhost/scsi.c:717
	llnode = llist_del_all(&svq->completion_list);
    ...
	llist_for_each_entry_safe(cmd, t, llnode, tvc_completion_list) {
        ...
        // Heavy work: locking, signal, logging, release
    }
```
The loop is unbounded.

**What’s the fix (high-level)?**
- Implement a budget/weight mechanism in `vhost_scsi_complete_cmd_work`.
- If the budget is exceeded, stop processing, put the remaining list back (or queue a new work item), and yield.

---

### drivers/vhost/scsi.c — drivers/vhost/scsi.c-0004: Resource Leak in vhost_scsi_target_queue_cmd failure

**What is the attack?**
- **Setup:** vhost-scsi.
- **Trigger:** Guest sends a command that causes `target_submit_prep` to fail (e.g., invalid CDB, invalid SGL mapping that wasn't caught earlier).
- **Mechanism:**
  - `vhost_scsi_handle_vq` calls `vhost_scsi_target_queue_cmd`.
  - Inside, `target_submit_prep` is called. If it returns error (e.g. -ENOMEM or -EINVAL from TCM), `vhost_scsi_target_queue_cmd` returns immediately.
  - `vhost_scsi_handle_vq` sees the return, but `vhost_scsi_target_queue_cmd` is `void`. It assumes submission worked or was handled.
  - The `vhost_scsi_cmd` object (`cmd`) has taken a reference to `inflight`. It is occupying a slot in `svq->scsi_cmds`.
  - Since it wasn't submitted to TCM, TCM won't complete it.
  - The driver logic doesn't call `vhost_scsi_release_cmd_res`.
  - The command and its inflight reference are leaked.
  - Repeatedly triggering this leaks all available tags.

**What can an attacker do?**
- **Impact:** Persistent DoS (Device Hang).
- **Capability:** Exhaust all command tags, making the device unusable.

**What’s the impact?**
- **Severity:** High.
- **Prerequisites:** Triggerable error in `target_submit_prep`.

**Which code files need manual audit to confirm this?**
- `drivers/vhost/scsi.c`: `vhost_scsi_target_queue_cmd`, `vhost_scsi_handle_vq`.

**Where is the vulnerable code snippet?**
```c
drivers/vhost/scsi.c:1008
	if (target_submit_prep(se_cmd, cdb, sg_ptr,
			       cmd->tvc_sgl_count, NULL, 0, sg_prot_ptr,
			       cmd->tvc_prot_sgl_count, GFP_KERNEL))
		return;
```
It returns without cleaning up.

**What’s the fix (high-level)?**
- Change `vhost_scsi_target_queue_cmd` to return an `int` error code.
- Check the return value in `vhost_scsi_handle_vq`.
- If failed, call `vhost_scsi_release_cmd_res` and send a failure status to the guest.

---

### drivers/vhost/scsi.c — drivers/vhost/scsi.c-0005: Host Memory Exhaustion via Integer Underflow in exp_data_len

**What is the attack?**
- **Setup:** T10 PI enabled vhost-scsi.
- **Trigger:** Guest sends a PI request where `pi_bytesout` or `pi_bytesin` (prot_bytes) is larger than the total data length (`exp_data_len`).
- **Mechanism:**
  - `exp_data_len` is calculated from descriptor sizes (e.g. 1024 bytes).
  - `prot_bytes` is read from the guest-provided header (e.g. 2048 bytes).
  - The code calculates: `if (prot_bytes) { exp_data_len -= prot_bytes; ... }`.
  - `exp_data_len` is `u32`. 1024 - 2048 underflows to `4294966272`.
  - This huge value is passed to `vhost_scsi_mapal` as `data_bytes`.
  - `vhost_scsi_mapal` calls `vhost_scsi_calc_sgls`.
  - `iov_iter_npages` on `4GB` might return ~1 million pages.
  - If `max_sgls` check passes (or if the overflow in calc_sgls logic described in Scenario 0001 also happens), the driver attempts to allocate huge scatterlists or iterate huge ranges.
  - `vhost_scsi_calc_sgls` returns `sgl_count`. `sg_alloc_table_chained` is called.
  - This allocates memory. Even if it fails later, it stresses the allocator.

**What can an attacker do?**
- **Impact:** Host Memory Exhaustion (DoS).
- **Capability:** Force large allocations or expensive iterations.

**What’s the impact?**
- **Severity:** Medium.
- **Prerequisites:** T10 PI feature bit enabled.

**Which code files need manual audit to confirm this?**
- `drivers/vhost/scsi.c`: `vhost_scsi_handle_vq`.

**Where is the vulnerable code snippet?**
```c
drivers/vhost/scsi.c:1270
			if (prot_bytes) {
				exp_data_len -= prot_bytes;
```
Missing check `if (prot_bytes > exp_data_len)`.

**What’s the fix (high-level)?**
- Add a check ensuring `prot_bytes <= exp_data_len` before subtraction.
