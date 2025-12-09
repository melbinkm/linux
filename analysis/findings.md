### drivers/vhost/scsi.c — drivers/vhost/scsi.c-0001: Guest I/O Stall via Weight Limit in vhost_scsi_handle_vq

**What is the attack?**
- **Concept**: A malicious or heavy-workload guest can induce a Denial of Service (stall) on the virtual SCSI device by filling the virtqueue with more requests than the configured batch weight (256).
- **Vulnerability Path**:
    - **Setup**: Guest configures `vhost-scsi` device.
    - **Trigger**: Guest submits > 256 requests to the virtqueue and kicks the host.
    - **Mechanism**: `vhost_scsi_handle_vq` runs in the vhost worker thread. It processes requests in a loop. The loop condition checks `vhost_exceeds_weight(vq, ++c, 0)`. When `c` reaches 256, this function returns `true`, causing the loop to terminate. The function then releases `vq->mutex` and returns. Crucially, it does **not** check if the ring still has pending descriptors, nor does it call `vhost_poll_queue` to reschedule the work item.
    - **Result**: The vhost worker thread goes to sleep because it thinks work is done. The guest sees requests as pending and waits for completion. If the ring is full, the guest cannot submit new requests (and thus cannot kick again). The system deadlocks/stalls.

**What can an attacker do?**
- Trigger a persistent stall of the SCSI device, effectively causing a Denial of Service for the guest's storage subsystem.

**What’s the impact?**
- **Classification**: Denial of Service (DoS).
- **Likelihood**: Medium. Requires guest to fill the ring, which is common behavior under load.
- **Context**: Virtualization driver.

**Which code files need manual audit to confirm this?**
- `drivers/vhost/scsi.c`: `vhost_scsi_handle_vq` function.
- `drivers/vhost/vhost.c`: `vhost_exceeds_weight` and `vhost_poll_queue` usage patterns.

**Where is the vulnerable code snippet?**
```c
// drivers/vhost/scsi.c:1342
    } while (likely(!vhost_exceeds_weight(vq, ++c, 0)));
out:
    mutex_unlock(&vq->mutex);
}
// Missing: check for more work and reschedule if needed.
```

**What’s the fix (high-level)?**
- Modify `vhost_scsi_handle_vq` to check if there are more available descriptors in the vring after the loop terminates due to weight limits.
- If pending work exists, call `vhost_poll_queue(&vq->poll)` to ensure the worker thread is rescheduled to continue processing.

---

### drivers/vhost/scsi.c — drivers/vhost/scsi.c-0002: Host Memory Exhaustion via Integer Underflow in exp_data_len

**What is the attack?**
- **Concept**: An integer underflow in the calculation of `exp_data_len` allows an attacker to bypass size checks and pass a huge `data_length` to the target core, leading to massive memory allocation attempts.
- **Vulnerability Path**:
    - **Setup**: `VIRTIO_SCSI_F_T10_PI` feature negotiated.
    - **Trigger**: Guest sends a request where `pi_bytesout` (protection info size) is slightly larger than the calculated `exp_data_len` (total data size derived from iov).
    - **Mechanism**:
        - `exp_data_len` is `u32`. `prot_bytes` is `int`.
        - The code performs `exp_data_len -= prot_bytes;`.
        - If `prot_bytes > exp_data_len`, `exp_data_len` wraps around to a large positive integer (underflow).
        - `vhost_scsi_mapal` is called with this huge length. It processes `prot_iter` (valid) and `data_iter` (which gets exhausted because `iov_iter_advance` moves it past the end).
        - `vhost_scsi_target_queue_cmd` calls `target_submit_prep`.
        - `target_submit` calls `transport_generic_new_cmd`.
        - `transport_generic_new_cmd` sees `cmd->data_length` is huge and `SCF_PASSTHROUGH_SG_TO_MEM_NOALLOC` is NOT set (because `data_sgl_count` was 0).
        - It calls `target_alloc_sgl` with the huge length, attempting to allocate gigabytes of memory.
    - **Result**: Immediate memory pressure on the host, potentially triggering OOM killer or denial of service.

**What can an attacker do?**
- Exhaust host kernel memory (DoS) or trigger OOM kills of other processes.

**What’s the impact?**
- **Classification**: Resource Exhaustion / DoS.
- **Likelihood**: Medium. Specific feature (T10_PI) must be enabled.
- **Context**: Virtualization driver.

**Which code files need manual audit to confirm this?**
- `drivers/vhost/scsi.c`: `vhost_scsi_handle_vq` logic for `exp_data_len` and `prot_bytes`.
- `drivers/target/target_core_transport.c`: `transport_generic_new_cmd` allocation logic.

**Where is the vulnerable code snippet?**
```c
// drivers/vhost/scsi.c:1229
if (prot_bytes) {
    exp_data_len -= prot_bytes; // UNDERFLOW
    prot_iter = data_iter;
    iov_iter_truncate(&prot_iter, prot_bytes);
    iov_iter_advance(&data_iter, prot_bytes);
}
```

**What’s the fix (high-level)?**
- Add a sanity check before subtraction: `if (prot_bytes > exp_data_len) goto err;`.

---

### drivers/vhost/scsi.c — drivers/vhost/scsi.c-0003: Resource Leak in vhost_scsi_target_queue_cmd on Initialization Failure

**What is the attack?**
- **Concept**: Failure to release resources when `target_init_cmd` fails leads to a leak of `vhost_scsi_cmd` structures, tags, and inflight references.
- **Vulnerability Path**:
    - **Setup**: Standard operation.
    - **Trigger**: A condition causing `target_init_cmd` to fail (e.g., `target_get_sess_cmd` fails due to session shutdown or refcount issues).
    - **Mechanism**:
        - `vhost_scsi_get_cmd` allocates a tag and increments `inflight` refcount.
        - `vhost_scsi_target_queue_cmd` calls `target_init_cmd`.
        - If `target_init_cmd` fails, it returns error code.
        - `vhost_scsi_target_queue_cmd` checks the error: `if (rc) return;`.
        - It returns `void`, so the caller (`vhost_scsi_handle_vq`) assumes success (as previous steps were successful).
        - The `cmd` is orphaned. The tag remains "busy" in the bitmap. The `inflight` refcount is never decremented.
    - **Result**: Repeated triggering leads to exhaustion of command tags (DoS) or inability to flush/close the device (due to stuck inflight refcount).

**What can an attacker do?**
- Permanently deplete the available command tags, preventing any further I/O (DoS).

**What’s the impact?**
- **Classification**: Resource Leak / DoS.
- **Likelihood**: Low (requires specific failure mode in target core).
- **Context**: Driver.

**Which code files need manual audit to confirm this?**
- `drivers/vhost/scsi.c`: `vhost_scsi_target_queue_cmd`.

**Where is the vulnerable code snippet?**
```c
// drivers/vhost/scsi.c:1049
    rc = target_init_cmd(se_cmd, nexus->tvn_se_sess, &cmd->tvc_sense_buf[0],
            lun, exp_data_len, vhost_scsi_to_tcm_attr(task_attr),
            data_dir, TARGET_SCF_ACK_KREF);
    if (rc)
        return; // LEAK: cmd resources not freed
```

**What’s the fix (high-level)?**
- In `vhost_scsi_target_queue_cmd`, if `target_init_cmd` fails, call `vhost_scsi_release_cmd_res(se_cmd)` before returning.
