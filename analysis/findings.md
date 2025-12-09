### io_uring/io_uring.c — io_uring/io_uring.c-0002: Atomic Memory Exhaustion via CQ Overflow

**What is the attack?**
- **Concept:** The `io_uring` subsystem uses the `GFP_ATOMIC` flag when allocating overflow completion queue events (CQEs) because the allocation happens under a spinlock (`completion_lock`). There is no effective limit on the number of these overflow entries that can be queued.
- **Vulnerability Path:**
  - **Setup:** An attacker creates an `io_uring` instance.
  - **Trigger:** The attacker fills the Completion Queue (CQ) with events (e.g., by submitting many NOP requests and not reaping the completions). Then, the attacker continues to submit requests that complete immediately (e.g., small reads, NOPs).
  - **Mechanism:**
    1. `io_req_complete_post` is called to complete a request.
    2. It acquires `ctx->completion_lock`.
    3. `io_fill_cqe_req` attempts to write to the CQ ring but fails because it is full.
    4. `io_cqe_overflow_locked` is called.
    5. `io_alloc_ocqe` is called with `GFP_ATOMIC | __GFP_ACCOUNT`.
    6. `kzalloc` consumes memory from the system-wide atomic reserve (due to `GFP_ATOMIC` implying `__GFP_HIGH`).
    7. The allocated `ocqe` is added to `ctx->cq_overflow_list`.
    8. The list grows indefinitely as long as memory permits.

**What can an attacker do?**
- **DoS:** The attacker can deplete the system's atomic memory reserves. These reserves are critical for interrupt handlers, network drivers (sk_buff allocation), and other kernel subsystems that cannot sleep. Exhausting them can cause network packet drops, storage failures, or general system instability (soft lockups if drivers spin waiting for memory).
- While `__GFP_ACCOUNT` charges the allocation to the user's cgroup, users with large memory limits (or root users in containers) can still consume the *global* atomic reserve, which is a scarcer resource than general RAM.

**What’s the impact?**
- **Impact:** Persistent Denial of Service (System Instability).
- **Context:** Reachable by any local user with access to `io_uring` (default enabled in most distros).

**Which code files need manual audit to confirm this?**
- `io_uring/io_uring.c`: `io_cqe_overflow_locked`, `io_alloc_ocqe`, `io_cqring_add_overflow`.

**Where is the vulnerable code snippet?**
```c
// io_uring/io_uring.c
static __cold bool io_cqe_overflow_locked(struct io_ring_ctx *ctx,
					  struct io_cqe *cqe,
					  struct io_big_cqe *big_cqe)
{
	struct io_overflow_cqe *ocqe;

    // GFP_ATOMIC used here allows dipping into atomic reserves
	ocqe = io_alloc_ocqe(ctx, cqe, big_cqe, GFP_ATOMIC);
	return io_cqring_add_overflow(ctx, ocqe);
}

static __cold bool io_cqring_add_overflow(struct io_ring_ctx *ctx,
					  struct io_overflow_cqe *ocqe)
{
    // ...
    // No limit check on the list size
	list_add_tail(&ocqe->list, &ctx->cq_overflow_list);
	return true;
}
```

**What’s the fix (high-level)?**
- **Impose a Limit:** Add a counter for `cq_overflow_list` size. If it exceeds a reasonable threshold (e.g., `cq_entries` or a fixed hard limit), drop the new overflow event and set `IO_CHECK_CQ_DROPPED_BIT` instead of allocating more memory.
- **Alternative:** Avoid `GFP_ATOMIC` if possible, though this is hard due to the spinlock.
- **Mitigation:** Rely on strict memcg limits, but this doesn't fully protect the atomic reserve. A hard limit on the list size is the correct fix.

---

### io_uring/io_uring.c — io_uring/io_uring.c-0063: Resource Exhaustion via io_msg_ring Overflow

**What is the attack?**
- **Concept:** The `io_msg_ring` opcode allows one ring to write entries into another ring's CQ. If the target ring is full, this triggers the same overflow mechanism as above, but allows cross-ring flooding.
- **Vulnerability Path:**
  - **Setup:** Attacker creates Ring A and Ring B. Ring B's CQ is filled.
  - **Trigger:** Ring A sends `IORING_OP_MSG_RING` requests targeting Ring B.
  - **Mechanism:** `io_msg_ring` calls `io_post_aux_cqe` on Ring B. Since Ring B is full, it calls `io_cqe_overflow_locked` using `GFP_ATOMIC`.
  - **Impact:** Similar to the self-inflicted overflow, but allows a process to exhaust resources using a separate "attack" ring against a "victim" ring (even if both owned by same user, it facilitates the attack structure).

**What can an attacker do?**
- Efficiently trigger the Atomic Exhaustion vulnerability described in 0002.

**What’s the impact?**
- **Impact:** Persistent Denial of Service.
- **Context:** Local unprivileged.

**Which code files need manual audit to confirm this?**
- `io_uring/msg_ring.c`: `io_msg_ring`.
- `io_uring/io_uring.c`: `io_post_aux_cqe`.

**Where is the vulnerable code snippet?**
```c
// io_uring/msg_ring.c
// calls io_post_aux_cqe(target_ctx, ...)

// io_uring/io_uring.c
bool io_post_aux_cqe(struct io_ring_ctx *ctx, u64 user_data, s32 res, u32 cflags)
{
    // ...
    // If fill fails (ring full), it calls io_cqe_overflow_locked
    filled = io_cqe_overflow_locked(ctx, &cqe, NULL);
    // ...
}
```

**What’s the fix (high-level)?**
- Same as 0002: limit the overflow list size.
