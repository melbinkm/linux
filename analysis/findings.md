### drivers/vhost/net.c — drivers/vhost/net.c-0001: TX Queue Stall via Descriptor Leak in get_tx_bufs Error Path

**What is the attack?**
- **Concept**: A malicious guest can trigger a persistent Denial of Service (DoS) of the virtio-net transmit queue by sending a specific malformed descriptor (writable descriptor in the TX queue).
- **Vulnerability Path**:
    - **Setup**: Standard vhost-net device.
    - **Trigger**: The guest places a descriptor with the `VRING_DESC_F_WRITE` flag set into the TX virtqueue and kicks the host.
    - **Mechanism**:
        - The vhost worker thread executes `handle_tx_copy`.
        - It calls `get_tx_bufs` to fetch the next descriptor.
        - `get_tx_bufs` calls `vhost_net_tx_get_vq_desc` -> `vhost_get_vq_desc_n`.
        - `vhost_get_vq_desc_n` successfully validates the descriptor structure, increments `vq->last_avail_idx` (marking the descriptor as consumed from the available ring), and returns the head index.
        - `get_tx_bufs` checks the `*in` parameter (number of input/writable descriptors). Since the guest set `VRING_DESC_F_WRITE`, `*in` is non-zero.
        - The code considers this an error for a TX queue. It logs an error via `vq_err` and returns `-EFAULT`.
        - `handle_tx_copy` receives `-EFAULT`, breaks its processing loop, and returns.
        - **Crucial Logic Error**: The code **fails to call** `vhost_discard_vq_desc` to roll back the `last_avail_idx`. It also **fails to call** `vhost_add_used` to return the descriptor to the guest with an error status.
    - **Result**: The descriptor is logically "consumed" by the host but never "completed" to the guest. The guest sees the descriptor as still pending. If the guest waits for this descriptor (or if the ring fills up with such descriptors), the queue effectively stalls permanently.

**What can an attacker do?**
- Permanently stall the transmit queue of the vhost-net device from within the guest (Guest-to-Guest DoS or Guest-to-Host resource waste if polling).

**What’s the impact?**
- **Classification**: Persistent Denial of Service (DoS).
- **Likelihood**: High. Trivial for a modified driver/guest to trigger.
- **Context**: Driver (vhost-net).

**Which code files need manual audit to confirm this?**
- `drivers/vhost/net.c`: `get_tx_bufs` and `handle_tx_copy`.
- `drivers/vhost/vhost.c`: `vhost_get_vq_desc_n` (to confirm side effects on `last_avail_idx`).

**Where is the vulnerable code snippet?**
```c
// drivers/vhost/net.c:1083
    if (*in) {
        vq_err(vq, "Unexpected descriptor format for TX: out %d, int %d\n",
            *out, *in);
        return -EFAULT; // Returns error WITHOUT calling vhost_discard_vq_desc()
    }
```

**What’s the fix (high-level)?**
- In `get_tx_bufs`, if the `*in` check fails (or the subsequent `init_iov_iter` check fails), call `vhost_discard_vq_desc(vq, 1, *ndesc)` before returning `-EFAULT`. This effectively "puts back" the descriptor so it can be retried or handled correctly, or at least ensures internal state consistency (though ideally we should probably consume it and mark it used with error to prevent infinite loops, but discarding is the standard rollback mechanism in vhost). Alternatively, consume it and add to used ring with 0 length to signal completion.

---

### drivers/vhost/net.c — drivers/vhost/net.c-0002: Zerocopy Descriptor Stall via Protocol Switch

**What is the attack?**
- **Concept**: A state machine violation allows an attacker (local user owning the device) to switch the transmission mode from zerocopy to copy mode while buffers are in flight, causing the completion signals for those buffers to be lost.
- **Vulnerability Path**:
    - **Setup**: `experimental_zcopytx=1` is enabled. User owns the vhost-net file descriptor and the backend socket.
    - **Trigger**:
        1. User enables `SOCK_ZEROCOPY` on the socket.
        2. User sends traffic, causing `vhost-net` to enter `handle_tx_zerocopy` and submit buffers with `ubuf_info`. `nvq->upend_idx` advances.
        3. While buffers are in flight (DMA pending), user disables `SOCK_ZEROCOPY` on the socket.
        4. User kicks the device.
    - **Mechanism**:
        - `handle_tx` runs. It checks `vhost_sock_zcopy(sock)`, which now returns false.
        - It calls `handle_tx_copy` instead of `handle_tx_zerocopy`.
        - `handle_tx_copy` processes new packets using data copying.
        - **Crucial Omission**: `handle_tx_zerocopy` is the only function that calls `vhost_zerocopy_signal_used` to check for completed zerocopy buffers (`ubufs`) and signal them to the guest. `handle_tx_copy` does NOT call this.
        - The backend kernel network stack completes the DMA and calls the `vhost_zerocopy_complete` callback, decrementing the `ubuf` refcount.
        - However, the vhost-net driver logic that moves descriptors from "pending" (`upend_idx`) to "used" (`done_idx`) never runs.
    - **Result**: The guest never receives completion interrupts for the in-flight zerocopy descriptors. They remain pending forever.

**What can an attacker do?**
- Stall the virtqueue by creating a "black hole" for a set of descriptors.

**What’s the impact?**
- **Classification**: Denial of Service (DoS) / Logic Bypass.
- **Likelihood**: Medium. Requires `experimental_zcopytx` and specific socket manipulation.
- **Context**: Driver.

**Which code files need manual audit to confirm this?**
- `drivers/vhost/net.c`: `handle_tx`, `handle_tx_copy`, `handle_tx_zerocopy`.

**Where is the vulnerable code snippet?**
```c
// drivers/vhost/net.c:1278
    if (vhost_sock_zcopy(sock))
        handle_tx_zerocopy(net, sock); // Handles signaling
    else
        handle_tx_copy(net, sock);     // Does NOT handle signaling
```

**What’s the fix (high-level)?**
- Modify `handle_tx` or `handle_tx_copy` to ensure that `vhost_zerocopy_signal_used` is called if there are pending zerocopy buffers (`nvq->upend_idx != nvq->done_idx`), even if the current mode is copy-based.

---

### drivers/vhost/net.c — drivers/vhost/net.c-0003: Host Process Hang via Zerocopy Reference Pinning

**What is the attack?**
- **Concept**: Resource exhaustion and process hang caused by the unprivileged user's ability to pin kernel memory indefinitely via the zerocopy mechanism.
- **Vulnerability Path**:
    - **Setup**: `experimental_zcopytx=1`.
    - **Trigger**:
        1. User creates a vhost-net instance attached to a TAP device.
        2. User sends zerocopy packets. These become SKBs in the TAP receive queue, holding a reference to `ubufs`.
        3. User does *not* read from the TAP device.
        4. User calls `close()` on the vhost-net file descriptor.
    - **Mechanism**:
        - `vhost_net_release` calls `vhost_net_flush`.
        - `vhost_net_flush` calls `vhost_net_ubuf_put_and_wait`.
        - This function waits specifically for `atomic_read(&ubufs->refcount) == 0`.
        - Since the SKBs are still alive in the TAP queue, the refcount remains > 0.
        - The `close()` call (and the userspace process) enters an uninterruptible sleep (D-state) waiting for the refcount.
    - **Result**: The process cannot be killed. Kernel memory associated with the process and the vhost device remains allocated.

**What can an attacker do?**
- Cause processes to hang indefinitely in D-state, potentially exhausting system resources (PID limit, memory) if repeated.

**What’s the impact?**
- **Classification**: Resource Exhaustion / DoS.
- **Likelihood**: Medium. Known issue type for zerocopy, but impactful.
- **Context**: Driver.

**Which code files need manual audit to confirm this?**
- `drivers/vhost/net.c`: `vhost_net_release`, `vhost_net_flush`.

**Where is the vulnerable code snippet?**
```c
// drivers/vhost/net.c:1347
    vhost_net_ubuf_put_and_wait(n->vqs[VHOST_NET_VQ_TX].ubufs);
```

**What’s the fix (high-level)?**
- This is an inherent risk of zerocopy. Hardening could involve a timeout in `vhost_net_flush` (followed by a leak warning instead of a hang), or mechanisms to force-purge the backend queues (though difficult across subsystems). Documenting the risk or restricting `experimental_zcopytx` to privileged users is the mitigation.
