### drivers/vhost/vsock.c — drivers/vhost/vsock.c-0001: Integer Overflow in vhost_vsock_alloc_skb on 32-bit

**What is the attack?**
- **Setup:** A 32-bit Linux kernel running `vhost_vsock`.
- **Trigger:** A malicious guest sends a virtio descriptor with a crafted header where `hdr->len` (payload length) is close to `U32_MAX` (e.g., `0xFFFFFFE0`).
- **Mechanism:**
  - In `vhost_vsock_alloc_skb`, `payload_len` is read as a 32-bit integer.
  - The check `if (payload_len + sizeof(*hdr) > len)` is performed.
  - On 32-bit systems, `size_t` is 32-bit. `payload_len + sizeof(*hdr)` wraps around (e.g., `0xFFFFFFE0 + 44 = 24`).
  - If `len` (the buffer size provided by the guest) is larger than the wrapped sum (e.g., 64), the check passes.
  - `virtio_vsock_skb_put(skb, payload_len)` is called with the huge length.
  - `skb_put` adds the huge length to the tail pointer. `tail + huge` wraps around the address space.
  - The `skb_put` assertion (`tail <= end`) might be bypassed due to the pointer wrap.
  - `skb_copy_datagram_from_iter` copies data to the `skb`. It writes to the wrapped memory address, corrupting kernel memory or causing a crash.

**What can an attacker do?**
- **Impact:** Host Kernel Crash (DoS). In some scenarios, it might lead to memory corruption, but a crash is the most likely outcome due to unmapped memory access or assertions.

**What’s the impact?**
- **Severity:** High (for 32-bit systems). Low (for 64-bit systems, where it is not feasible).
- **Context:** Requires a malicious guest.

**Which code files need manual audit to confirm this?**
- `drivers/vhost/vsock.c`: `vhost_vsock_alloc_skb` function.
- `include/linux/virtio_vsock.h`: `virtio_vsock_skb_put` and `virtio_vsock_alloc_skb`.

**Where is the vulnerable code snippet?**
```c
drivers/vhost/vsock.c:453
	/* The pkt is too big or the length in the header is invalid */
	if (payload_len + sizeof(*hdr) > len) {
		kfree_skb(skb);
		return NULL;
	}
```
On 32-bit, the addition `payload_len + sizeof(*hdr)` wraps.

**What’s the fix (high-level)?**
- Use `check_add_overflow` to detect the overflow.
- Or cast to `u64` before addition: `if ((u64)payload_len + sizeof(*hdr) > len)`.

---

### drivers/vhost/vsock.c — drivers/vhost/vsock.c-0002: Host Memory Exhaustion via Unbounded send_pkt_queue

**What is the attack?**
- **Setup:** A standard `vhost_vsock` environment.
- **Trigger:** A malicious guest opens a connection and advertises a very large credit window (e.g., 2GB or more) but refuses to process incoming packets (Rx).
- **Mechanism:**
  - The Host application sends data to the Guest.
  - The `virtio_transport` layer checks the peer's credit. Since credit is available, it queues packets.
  - `vhost_transport_send_pkt` queues these packets into `vsock->send_pkt_queue`.
  - There is no limit on the number of packets or bytes in `send_pkt_queue` other than the flow control credit.
  - The Host kernel allocates memory for each packet (`sk_buff` + data).
  - The queue grows until the credit limit is reached.
  - A single guest can consume gigabytes of Host kernel memory.

**What can an attacker do?**
- **Impact:** Persistent DoS (OOM Killer triggered on Host).
- **Capability:** A container or VM guest can crash other containers or the host itself by exhausting memory.

**What’s the impact?**
- **Severity:** Medium.
- **Prerequisites:** Malicious guest.

**Which code files need manual audit to confirm this?**
- `drivers/vhost/vsock.c`: `vhost_transport_send_pkt`.
- `net/vmw_vsock/virtio_transport_common.c` (logic for credit updates).

**Where is the vulnerable code snippet?**
```c
drivers/vhost/vsock.c:380
	virtio_vsock_skb_queue_tail(&vsock->send_pkt_queue, skb);
```
It queues without checking any local resource limit.

**What’s the fix (high-level)?**
- Implement a limit on `send_pkt_queue` size (e.g., max 1000 packets or max 16MB).
- If the limit is reached, return `-EAGAIN` or drop the packet (forcing TCP-like backpressure or packet loss).
- Do not rely solely on the guest-controlled credit window for resource management.
