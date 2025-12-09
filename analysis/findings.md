### drivers/vhost/net.c — drivers/vhost/net.c-0002: Use-After-Free in vhost_net_set_backend failure path

**What is the attack?**
- **Setup:** A privileged user (or a process with access to `/dev/vhost-net`) configures a vhost-net backend.
- **Trigger:** Call `VHOST_NET_SET_BACKEND` with a valid file descriptor, but induce a failure in `vhost_net_enable_vq` (e.g. via fault injection or racing with another operation that affects the VQ state).
- **Mechanism:**
  - `vhost_net_set_backend` calls `vhost_net_ubuf_alloc` to allocate `ubufs`.
  - It sets `nvq->ubufs = ubufs`.
  - It calls `vhost_net_enable_vq`.
  - If `vhost_net_enable_vq` fails (returns error), execution jumps to `err_used`.
  - At `err_used`, the code attempts to cleanup: `vhost_vq_set_backend(vq, oldsock)` and `vhost_net_enable_vq(n, vq)`.
  - Then: `if (ubufs) vhost_net_ubuf_put_wait_and_free(ubufs);`.
  - This frees `ubufs`.
  - **CRITICAL FLAW:** `nvq->ubufs` is NOT restored to `oldubufs` (or NULL). It remains pointing to the now-freed `ubufs`.
  - Subsequent operations (e.g. `vhost_net_flush` or another `set_backend` call) will access `nvq->ubufs`, causing a Use-After-Free.

**What can an attacker do?**
- **Impact:** Host Kernel Crash (GPF or paging request) or potentially Privilege Escalation if the freed memory is reallocated and corrupted appropriately (e.g. `ubufs->refcount` or `ubufs->wait` manipulation).

**What’s the impact?**
- **Severity:** High.
- **Prerequisites:** Ability to open `/dev/vhost-net` and set backend.

**Which code files need manual audit to confirm this?**
- `drivers/vhost/net.c`: `vhost_net_set_backend` function.

**Where is the vulnerable code snippet?**
```c
drivers/vhost/net.c:1666
		nvq->ubufs = ubufs;
...
	r = vhost_net_enable_vq(n, vq);
	if (r)
		goto err_used;
...
err_used:
	vhost_vq_set_backend(vq, oldsock);
	vhost_net_enable_vq(n, vq);
	if (ubufs)
		vhost_net_ubuf_put_wait_and_free(ubufs); // Frees ubufs
    // nvq->ubufs is still pointing to freed ubufs!
```

**What’s the fix (high-level)?**
- In the `err_used` label, explicitly restore `nvq->ubufs` to `oldubufs` before freeing `ubufs`.

---

### drivers/vhost/net.c — drivers/vhost/net.c-0005: Integer Overflow in vhost_net_build_xdp

**What is the attack?**
- **Setup:** A guest with `virtio-net` and XDP enabled on the host TAP device.
- **Trigger:** Guest sends a packet via `virtio-net` with a carefully crafted descriptor chain length.
- **Mechanism:**
  - `vhost_net_build_xdp` calculates `buflen` and `pad`.
  - `size_t len = iov_iter_count(from)`.
  - `int pad = SKB_DATA_ALIGN(VHOST_NET_RX_PAD + headroom + nvq->sock_hlen)`.
  - `if (SKB_DATA_ALIGN(len + pad) + SKB_DATA_ALIGN(sizeof(struct skb_shared_info)) > PAGE_SIZE) return -ENOSPC;`.
  - If `len` is extremely large (close to `SIZE_MAX`), `len + pad` can overflow.
  - On 64-bit systems, `size_t` is 64-bit. `iov_iter_count` is sum of iov lengths. Guest controls iov lengths (up to 4GB per desc? Total length is limited by implementation but potentially large).
  - If `len` is large enough to cause `len + pad` to wrap around to a small value (e.g. `SIZE_MAX - pad + 100`), the `> PAGE_SIZE` check passes.
  - `buflen` calculation wraps similarly.
  - `buf = page_frag_alloc_align(..., buflen, ...)` allocates a small buffer.
  - `copy_from_iter(buf + pad - sock_hlen, len, from)` attempts to copy `len` (huge) bytes into the small buffer.
  - This results in a massive heap overflow.

**What can an attacker do?**
- **Impact:** Host Kernel Crash (DoS) or RCE/LPE via heap corruption.

**What’s the impact?**
- **Severity:** High.
- **Prerequisites:** XDP enabled on host socket, guest capability to send huge descriptor chains.

**Which code files need manual audit to confirm this?**
- `drivers/vhost/net.c`: `vhost_net_build_xdp`.

**Where is the vulnerable code snippet?**
```c
drivers/vhost/net.c:755
	if (SKB_DATA_ALIGN(len + pad) +
	    SKB_DATA_ALIGN(sizeof(struct skb_shared_info)) > PAGE_SIZE)
		return -ENOSPC;
```
Implicit integer promotion rules and overflow behavior need checking. `len` is `size_t`. `pad` is `int`.

**What’s the fix (high-level)?**
- Use `check_add_overflow` for `len + pad` or validate `len` against a sanity limit (e.g. `ETH_MAX_MTU` or `PAGE_SIZE`) *before* arithmetic.

---

### drivers/vhost/net.c — drivers/vhost/net.c-0007: Zerocopy Descriptor Completion Signal Loss

**What is the attack?**
- **Setup:** Vhost-net with `experimental_zcopytx=1`.
- **Trigger:** Guest sends zerocopy packets. Underlying network device or driver fails to signal DMA completion for a specific buffer in a sequence.
- **Mechanism:**
  - `vhost_zerocopy_signal_used` reaps completed descriptors in order.
  - It iterates from `done_idx` to `upend_idx`.
  - If the buffer at `done_idx` is NOT marked done (still `VHOST_DMA_IN_PROGRESS`), it stops processing.
  - If subsequent buffers are done, they remain in the ring, not signaled to the guest.
  - If the first buffer is permanently stuck (e.g. lost interrupt or driver bug), the guest never gets completion for *any* subsequent packets.
  - The guest eventually runs out of TX descriptors and stalls.
  - Furthermore, `vhost_net_flush` waits for `ubufs->refcount`. If completion is lost, refcount never drops. Host process hangs on close/exit.

**What can an attacker do?**
- **Impact:** Persistent DoS (Guest Network Stall) and Host Process Hang.

**What’s the impact?**
- **Severity:** Medium.
- **Prerequisites:** `experimental_zcopytx=1`.

**Which code files need manual audit to confirm this?**
- `drivers/vhost/net.c`: `vhost_zerocopy_signal_used`, `vhost_net_flush`.

**Where is the vulnerable code snippet?**
```c
drivers/vhost/net.c:303
	for (i = nvq->done_idx; i != nvq->upend_idx; i = (i + 1) % UIO_MAXIOV) {
		if (VHOST_DMA_IS_DONE(vq->heads[i].len)) {
            ...
		} else
			break; // Stops at first incomplete buffer
	}
```

**What’s the fix (high-level)?**
- Improve zerocopy reliability mechanism (e.g. timeout for completion).
- In `vhost_net_flush`, use a timeout loop instead of indefinite wait, or force-complete old buffers.

---

### drivers/vhost/net.c — drivers/vhost/net.c-0008: Host Process Hang via Zerocopy Reference Pinning

**What is the attack?**
- **Setup:** Vhost-net with `experimental_zcopytx=1`.
- **Trigger:** Guest sends zerocopy packets.
- **Mechanism:**
  - `vhost_net_flush` (called on release/stop) calls `vhost_net_ubuf_put_and_wait`.
  - This function waits: `wait_event(ubufs->wait, !atomic_read(&ubufs->refcount));`.
  - The refcount is decremented in the `vhost_zerocopy_complete` callback.
  - This callback is executed by the networking stack's SKB destructor.
  - If the SKB is leaked, held indefinitely by a qdisc, or stuck in a driver queue, the callback never fires.
  - The `vhost_net_release` function (and thus the closing `close()` syscall) blocks forever.
  - The QEMU/VMM process enters 'D' (uninterruptible sleep) state and cannot be killed `kill -9`.

**What can an attacker do?**
- **Impact:** Host DoS (Unkillable process).

**What’s the impact?**
- **Severity:** Medium.
- **Prerequisites:** `experimental_zcopytx=1`.

**Which code files need manual audit to confirm this?**
- `drivers/vhost/net.c`: `vhost_net_ubuf_put_and_wait`.

**Where is the vulnerable code snippet?**
```c
drivers/vhost/net.c:215
	wait_event(ubufs->wait, !atomic_read(&ubufs->refcount));
```

**What’s the fix (high-level)?**
- Use `wait_event_timeout` and implement a fallback cleanup strategy (though reclaiming memory from live SKBs is difficult/impossible, logging and allowing exit is preferred over hanging).
